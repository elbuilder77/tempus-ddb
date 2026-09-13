import json
import os
import sys
import tempfile
import time

from tempus_ddb import TempusDDB, TempusExecutor, gen_keys


class DownstreamAPI:
    """A simulated protected downstream API that only trusts Tempus permits."""
    def __init__(self, secret_token: str):
        self.secret_token = secret_token
        self.credits = 0

    def process_purchase_request(self, token: str, amount: int):
        # The API explicitly demands a secret token that only the mediated executor knows.
        if token != self.secret_token:
            return {"error": "Acceso denegado: Credenciales invalidas."}
        self.credits += amount
        return {"credits_added": amount, "total_credits": self.credits}

class ExecutorProxy:
    """The mediated executor proxy that sits in front of the API."""
    def __init__(self, db_path: str, keyfile: str, trusted_gate_id: str, trusted_tenant_id: str, api: DownstreamAPI, api_secret: str):
        self.executor = TempusExecutor(db_path, keyfile, trusted_gate_id, trusted_tenant_id)
        self.api = api
        self.api_secret = api_secret
        self.purchase_count = 0

    def process_purchase_request(self, permit_json: str):
        try:
            # 1. Enforced mediation: Consume permit atomically, verify signatures, gate id, tenant, hash.
            auth_str = self.executor.verify_and_consume_permit(permit_json)
            auth = json.loads(auth_str)

            permit_obj = json.loads(permit_json)
            authorized_amount = permit_obj["intent"]["input"]["amount"]

            # 2. Effect: Call the real API with the secret token
            result = self.api.process_purchase_request(self.api_secret, authorized_amount)
            if "error" in result:
                return result

            self.purchase_count += 1

            # 3. Complete execution: Sign outcome
            outcome = self.executor.complete_execution(
                auth["authorization_id"],
                auth["action_id"],
                "SUCCEEDED",
                json.dumps(result)
            )
            return json.loads(outcome)

        except Exception as e:
            return {"error": str(e)}

def color_print(text, color_code):
    print(f"\033[{color_code}m{text}\033[0m")

def print_step(step_num, title):
    print(f"\n\033[1;36m[{step_num}] {title}\033[0m")

def main():
    print("================================================================")
    print(" Tempus DDB - Demostracion Comercial (Epic 5)")
    print("================================================================\n")
    print("Esta demo prueba que: Un agente puede decidir lo que quiera, pero")
    print("no puede producir un efecto irreversible sin pasar por Tempus.\n")

    with tempfile.TemporaryDirectory() as tmpdir:
        gate_db = os.path.join(tmpdir, "gate.db")
        exec_db = os.path.join(tmpdir, "exec.db")

        gate_keyfile = os.path.join(tmpdir, "gate.keys.json")
        agent_keyfile = os.path.join(tmpdir, "agent.keys.json")
        exec_keyfile = os.path.join(tmpdir, "executor.keys.json")

        gen_keys(gate_keyfile)
        gen_keys(agent_keyfile)
        gen_keys(exec_keyfile)

        gate = TempusDDB(gate_db, gate_keyfile)

        with open(gate_keyfile) as f:
            gate_id = json.load(f)["public_key"]
        with open(agent_keyfile) as f:
            agent_id = json.load(f)["public_key"]
        with open(exec_keyfile) as f:
            executor_id = json.load(f)["public_key"]

        gate.register_agent(gate_id, "tempus-gate", '{"can_delegate":true}')
        gate.register_agent(agent_id, "test-agent", "{}")
        gate.register_agent(executor_id, "test-executor", "{}")

        tenant_id = "demo-tenant"
        api_secret = "demo-only-executor-credential"
        api = DownstreamAPI(api_secret)
        proxy = ExecutorProxy(exec_db, exec_keyfile, gate_id, tenant_id, api, api_secret)

        time_ms = time.time_ns() // 1_000_000

        print_step("1", "Un agente intenta comprar sin Tempus (Falla)")
        # Agent tries to bypass executor but does not know the secret
        result_no_tempus = api.process_purchase_request("wrong_token_or_no_token", 100)
        assert "error" in result_no_tempus
        assert proxy.purchase_count == 0
        color_print(f"PASS direct bypass rejected: {result_no_tempus['error']}", "32")

        print_step("2", "Un agente intenta comprar con Tempus (Funciona)")
        intent = json.dumps({
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "idempotency_key": f"purchase-demo-{time_ms}",
            "action_type": "purchase",
            "resource": "api/credits",
            "requested_at": time.time_ns() // 1_000,
            "input": {"amount": 100},
        })

        auth_result = json.loads(gate.request_action(intent, agent_keyfile, 60))
        permit = json.dumps(auth_result)

        outcome_success = proxy.process_purchase_request(permit)
        assert "error" not in outcome_success
        assert outcome_success["status"] == "SUCCEEDED"
        assert outcome_success["output"]["credits_added"] == 100
        assert proxy.purchase_count == 1
        color_print(f"PASS valid permit executed. Resultado: {outcome_success['output']}", "32")

        print_step("3", "Un replay (reintento del mismo permiso) es rechazado")
        outcome_replay = proxy.process_purchase_request(permit)
        assert "error" in outcome_replay
        assert proxy.purchase_count == 1
        color_print(f"PASS replay rejected: {outcome_replay['error']}", "32")

        print_step("4", "Un permiso expirado es rechazado")
        intent_exp = json.dumps({
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "idempotency_key": f"purchase-exp-{time_ms}",
            "action_type": "purchase",
            "resource": "api/credits",
            "requested_at": time.time_ns() // 1_000,
            "input": {"amount": 100},
        })
        auth_result_exp = json.loads(gate.request_action(intent_exp, agent_keyfile, 1))
        permit_exp = json.dumps(auth_result_exp)
        time.sleep(1.1)
        outcome_exp = proxy.process_purchase_request(permit_exp)
        assert "error" in outcome_exp
        assert proxy.purchase_count == 1
        color_print(f"PASS expired permit rejected: {outcome_exp['error']}", "32")

        print_step("5", "Un permiso alterado es rechazado")
        intent_alt = json.dumps({
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "idempotency_key": f"purchase-alt-{time_ms}",
            "action_type": "purchase",
            "resource": "api/credits",
            "requested_at": time.time_ns() // 1_000,
            "input": {"amount": 100},
        })
        auth_result_alt = json.loads(gate.request_action(intent_alt, agent_keyfile, 60))
        auth_result_alt["authorization"]["action_id"] = "fake-action-id-123"
        permit_alt = json.dumps(auth_result_alt)
        outcome_alt = proxy.process_purchase_request(permit_alt)
        assert "error" in outcome_alt
        assert proxy.purchase_count == 1
        color_print(f"PASS tampered permit rejected: {outcome_alt['error']}", "32")

        print_step("6", "Un permiso cross-tenant es rechazado")
        intent_cross = json.dumps({
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": "other-tenant",
            "agent_id": agent_id,
            "idempotency_key": f"purchase-cross-{time_ms}",
            "action_type": "purchase",
            "resource": "api/credits",
            "requested_at": time.time_ns() // 1_000,
            "input": {"amount": 100},
        })
        auth_result_cross = json.loads(gate.request_action(intent_cross, agent_keyfile, 60))
        permit_cross = json.dumps(auth_result_cross)
        outcome_cross = proxy.process_purchase_request(permit_cross)
        assert "error" in outcome_cross
        assert proxy.purchase_count == 1
        color_print(f"PASS cross-tenant permit rejected: {outcome_cross['error']}", "32")

        print_step("7", "Se genera un receipt verificable")
        receipt_str = gate.commit_outcome_signed(
            auth_result['authorization']['authorization_id'],
            json.dumps(outcome_success),
        )
        receipt = json.loads(receipt_str)
        assert receipt["schema_version"] == "tempus.execution-result.v1"

        verification_str = gate.verify_trace(auth_result['authorization']['action_id'])
        verification = json.loads(verification_str)
        assert verification.get('status') == 'VERIFIED'
        color_print(f"PASS receipt verified: {verification['status']} (Fase: {verification['phase']})", "32")

        print_step("8", "Resumen de downstream")
        assert api.credits == 100
        assert proxy.purchase_count == 1
        color_print(f"PASS downstream effects = {proxy.purchase_count}", "32")

        print("\n================================================================")
        color_print(" Demo Finalizada Exitosamente (Todas las aserciones pasaron)", "32")
        print("================================================================\n")

        del gate, proxy, api
        import gc
        gc.collect()

if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    try:
        main()
    except AssertionError:
        color_print("\n[ERROR] Assertion Error: Demo fallida en una asercion.", "31")
        sys.exit(1)
    except Exception as e:
        color_print(f"\n[ERROR] Error inesperado: {e}", "31")
        sys.exit(1)
