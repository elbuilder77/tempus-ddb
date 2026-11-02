//! Rules in a policy: a strict, typed subset of JsonLogic, evaluated by `jsonlogic-fast`.
//!
//! JsonLogic coerces like JavaScript (`"10" > 9`, `1 == "1"`) and its arithmetic is floating
//! point, which a policy cannot have: a permit must mean the same to every reader. So the
//! grammar is checked when a policy is read, and what `var` returns is checked as the rule
//! runs. Anything outside the types blocks the action.
//!
//! The runtime check computes nothing itself. Every value it looks at comes from the
//! evaluator, so there remains one policy evaluator, and it follows the same short-circuits,
//! so a branch not taken cannot fail.

use serde_json::{Map, Number, Value};

pub(crate) const RULES_DENIED: &str = "POLICY_RULES_DENIED";
pub(crate) const RULES_ERROR: &str = "POLICY_RULES_ERROR";

const MAX_RULES: usize = 32;
const MAX_NODES: usize = 256;
const MAX_DEPTH: usize = 16;
const MAX_ID_BYTES: usize = 64;
/// Above this an IEEE double cannot tell neighbouring integers apart.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
/// All a rule sees, so that every reader can rebuild it from the permit.
const CONTEXT_ROOTS: &[&str] = &["intent", "ttl_seconds", "money"];

fn invalid(detail: impl std::fmt::Display) -> String {
    format!("TEMPUS_POLICY_RULES_INVALID: {detail}")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bool,
    Test,
    Num,
    Str,
    Term,
}

fn is_safe_integer(number: &Number) -> bool {
    number
        .as_u64()
        .map(|value| value <= MAX_SAFE_INTEGER)
        .or_else(|| {
            number
                .as_i64()
                .map(|value| value.unsigned_abs() <= MAX_SAFE_INTEGER)
        })
        .unwrap_or(false)
}

/// The one key of an operator object, and its arguments. A bare argument (`{"!": x}`) reads
/// as a list of one, as in JsonLogic.
fn operator(map: &Map<String, Value>) -> Option<(&str, &[Value])> {
    if map.len() != 1 {
        return None;
    }
    let (name, arguments) = map.iter().next()?;
    Some((
        name.as_str(),
        match arguments {
            Value::Array(list) => list.as_slice(),
            single => std::slice::from_ref(single),
        },
    ))
}

fn is_valid_path(path: &str) -> bool {
    let mut segments = path.split('.');
    segments
        .next()
        .is_some_and(|root| CONTEXT_ROOTS.contains(&root))
        && path.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        })
}

struct Grammar {
    nodes: usize,
}

impl Grammar {
    fn check(&mut self, node: &Value, kind: Kind, depth: usize) -> Result<(), String> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(format!("more than {MAX_NODES} nodes"));
        }
        if depth > MAX_DEPTH {
            return Err(format!("deeper than {MAX_DEPTH} levels"));
        }
        let fits = match node {
            Value::Bool(_) => matches!(kind, Kind::Bool | Kind::Test | Kind::Term),
            Value::String(_) => matches!(kind, Kind::Str | Kind::Term),
            Value::Null => kind == Kind::Term,
            Value::Number(number) => {
                if !is_safe_integer(number) {
                    return Err(format!("{number} is not an exact integer"));
                }
                matches!(kind, Kind::Num | Kind::Term)
            }
            Value::Array(_) => false,
            Value::Object(map) => return self.operator(map, kind, depth),
        };
        if fits {
            Ok(())
        } else {
            Err(format!("{node} is not allowed here"))
        }
    }

    fn operator(
        &mut self,
        map: &Map<String, Value>,
        kind: Kind,
        depth: usize,
    ) -> Result<(), String> {
        let (name, arguments) =
            operator(map).ok_or_else(|| "an operator object has exactly one key".to_string())?;
        let is_bool = matches!(kind, Kind::Bool | Kind::Test);
        let is_number = matches!(kind, Kind::Num | Kind::Term);
        let refused = || format!("operator '{name}' is not allowed here");
        let count = |wanted: usize| {
            if arguments.len() == wanted {
                Ok(())
            } else {
                Err(format!("'{name}' takes {wanted} arguments"))
            }
        };
        let next = depth + 1;
        match name {
            "var" => self.var(arguments),
            "missing" if kind == Kind::Test => {
                if !arguments.is_empty()
                    && arguments
                        .iter()
                        .all(|path| path.as_str().is_some_and(is_valid_path))
                {
                    Ok(())
                } else {
                    Err("'missing' takes readable paths".to_string())
                }
            }
            "and" | "or" if is_bool => {
                if arguments.is_empty() {
                    return Err(format!("'{name}' takes at least one argument"));
                }
                self.each(arguments, Kind::Bool, next)
            }
            "if" if is_bool => {
                count(3)?;
                self.each(arguments, Kind::Bool, next)
            }
            "!" | "!!" if is_bool => {
                count(1)?;
                self.each(arguments, Kind::Test, next)
            }
            "===" | "!==" if is_bool => {
                count(2)?;
                self.each(arguments, Kind::Term, next)
            }
            "<" | "<=" | ">" | ">=" if is_bool => {
                count(2)?;
                self.each(arguments, Kind::Num, next)
            }
            "in" if is_bool => {
                count(2)?;
                self.check(&arguments[0], Kind::Str, next)?;
                match &arguments[1] {
                    // The evaluator does not look inside a literal list: a `var` there would be
                    // compared as an object, and never match.
                    Value::Array(list) if !list.iter().all(Value::is_string) => {
                        Err("a list in 'in' holds only literal strings".to_string())
                    }
                    Value::Array(list) => self.each(list, Kind::Str, next),
                    haystack => self.check(haystack, Kind::Str, next),
                }
            }
            "+" | "-" | "*" if is_number => {
                count(2)?;
                self.each(arguments, Kind::Num, next)
            }
            "min" | "max" if is_number => {
                if arguments.is_empty() {
                    return Err(format!("'{name}' takes at least one argument"));
                }
                self.each(arguments, Kind::Num, next)
            }
            _ => Err(refused()),
        }
    }

    fn each(&mut self, nodes: &[Value], kind: Kind, depth: usize) -> Result<(), String> {
        nodes
            .iter()
            .try_for_each(|node| self.check(node, kind, depth))
    }

    fn var(&mut self, arguments: &[Value]) -> Result<(), String> {
        let (path, default) = match arguments {
            [path] => (path, None),
            [path, default] => (path, Some(default)),
            _ => return Err("'var' takes a path and an optional default".to_string()),
        };
        if !path.as_str().is_some_and(is_valid_path) {
            return Err(format!(
                "'var' reads a path under {}, not {path}",
                CONTEXT_ROOTS.join(", ")
            ));
        }
        match default {
            None | Some(Value::Bool(_) | Value::Null | Value::String(_)) => Ok(()),
            Some(Value::Number(number)) if is_safe_integer(number) => Ok(()),
            Some(other) => Err(format!("'var' cannot default to {other}")),
        }
    }
}

/// Check a policy's `rules`: the list, the ids, and each rule's grammar and limits.
pub(crate) fn validate(rules: &Value) -> Result<(), String> {
    let list = rules
        .as_array()
        .ok_or_else(|| invalid("rules must be a list"))?;
    if list.len() > MAX_RULES {
        return Err(invalid(format!("more than {MAX_RULES} rules")));
    }
    let mut seen: Vec<&str> = Vec::with_capacity(list.len());
    for rule in list {
        let fields = rule
            .as_object()
            .ok_or_else(|| invalid("a rule must be an object"))?;
        if let Some(extra) = fields.keys().find(|key| *key != "id" && *key != "logic") {
            return Err(invalid(format!("unknown rule field '{extra}'")));
        }
        let id = rule
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| {
                (1..=MAX_ID_BYTES).contains(&id.len())
                    && id.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'.' | b'_' | b'-')
                    })
            })
            .ok_or_else(|| invalid("a rule id is 1 to 64 characters of a-z 0-9 . _ -"))?;
        if seen.contains(&id) {
            return Err(invalid(format!("rule id '{id}' is repeated")));
        }
        seen.push(id);
        let logic = rule
            .get("logic")
            .ok_or_else(|| invalid(format!("rule '{id}' has no logic")))?;
        Grammar { nodes: 0 }
            .check(logic, Kind::Bool, 1)
            .map_err(|detail| invalid(format!("rule '{id}': {detail}")))?;
    }
    Ok(())
}

/// A rule went outside its types, or the evaluator refused it.
struct Fault;

/// One rule's run. `context` holds only the paths the rule can read: the evaluator parses it
/// for every node it is asked about, and an intent's input can be megabytes it never looks at.
struct Run {
    context: String,
}

impl Run {
    fn value(&self, node: &Value) -> Result<Value, Fault> {
        jsonlogic_fast::evaluate(&node.to_string(), &self.context).map_err(|_| Fault)
    }

    fn boolean(&self, node: &Value) -> Result<bool, Fault> {
        if let Some((name, arguments)) = node.as_object().and_then(operator) {
            match (name, arguments) {
                ("and", list) => {
                    for child in list {
                        if !self.boolean(child)? {
                            break;
                        }
                    }
                }
                ("or", list) => {
                    for child in list {
                        if self.boolean(child)? {
                            break;
                        }
                    }
                }
                ("if", [condition, then, otherwise]) => {
                    let chosen = if self.boolean(condition)? {
                        then
                    } else {
                        otherwise
                    };
                    self.boolean(chosen)?;
                }
                ("!" | "!!", [test]) => self.test(test)?,
                ("===" | "!==", [left, right]) => {
                    self.term(left)?;
                    self.term(right)?;
                }
                ("<" | "<=" | ">" | ">=", [left, right]) => {
                    self.number(left)?;
                    self.number(right)?;
                }
                ("in", [needle, haystack]) => {
                    self.text(needle)?;
                    self.haystack(haystack)?;
                }
                _ => {}
            }
        }
        match self.value(node)? {
            Value::Bool(result) => Ok(result),
            _ => Err(Fault),
        }
    }

    fn test(&self, node: &Value) -> Result<(), Fault> {
        match node.as_object().and_then(operator) {
            // Asking whether a value is there or truthy is what these are for: any type will do.
            Some(("var" | "missing", _)) => Ok(()),
            _ => self.boolean(node).map(|_| ()),
        }
    }

    fn number(&self, node: &Value) -> Result<(), Fault> {
        let Some((name, arguments)) = node.as_object().and_then(operator) else {
            return Ok(()); // a literal, checked by the grammar
        };
        if name == "var" {
            return match self.value(node)? {
                Value::Number(number) if is_safe_integer(&number) => Ok(()),
                _ => Err(Fault),
            };
        }
        arguments.iter().try_for_each(|child| self.number(child))?;
        // The operands are exact, and IEEE arithmetic rounds correctly, so a result inside
        // the safe range is exact, and one outside it cannot be trusted.
        match self.value(node)?.as_f64() {
            Some(result)
                if result.is_finite()
                    && result.fract() == 0.0
                    && result.abs() <= MAX_SAFE_INTEGER as f64 =>
            {
                Ok(())
            }
            _ => Err(Fault),
        }
    }

    fn text(&self, node: &Value) -> Result<(), Fault> {
        match node {
            Value::Object(_) => match self.value(node)? {
                Value::String(_) => Ok(()),
                _ => Err(Fault),
            },
            _ => Ok(()),
        }
    }

    fn haystack(&self, node: &Value) -> Result<(), Fault> {
        match node {
            Value::Object(_) => match self.value(node)? {
                Value::String(_) => Ok(()),
                Value::Array(list) if list.iter().all(Value::is_string) => Ok(()),
                _ => Err(Fault),
            },
            _ => Ok(()),
        }
    }

    fn term(&self, node: &Value) -> Result<(), Fault> {
        match node.as_object().and_then(operator) {
            None => Ok(()),
            Some(("var", _)) => match self.value(node)? {
                Value::Bool(_) | Value::Null | Value::String(_) => Ok(()),
                Value::Number(number) if is_safe_integer(&number) => Ok(()),
                _ => Err(Fault),
            },
            Some(_) => self.number(node),
        }
    }
}

fn collect_paths<'a>(node: &'a Value, paths: &mut Vec<&'a str>) {
    match node {
        Value::Array(list) => list.iter().for_each(|item| collect_paths(item, paths)),
        Value::Object(map) => {
            for (name, arguments) in map {
                match (name.as_str(), arguments) {
                    ("var", Value::String(path)) => paths.push(path),
                    ("var", Value::Array(list)) => {
                        paths.extend(list.first().and_then(Value::as_str))
                    }
                    ("missing", Value::String(path)) => paths.push(path),
                    ("missing", Value::Array(list)) => {
                        paths.extend(list.iter().filter_map(Value::as_str));
                    }
                    (_, other) => collect_paths(other, paths),
                }
            }
        }
        _ => {}
    }
}

/// Copy `path` from `from` into `to`, walking objects. Where the path runs out or reaches
/// something else (an array, say) the whole value comes along, so a read means the same.
fn copy_path<'a>(from: &Value, to: &mut Value, mut segments: impl Iterator<Item = &'a str>) {
    let Some(segment) = segments.next() else {
        *to = from.clone();
        return;
    };
    let Some(fields) = from.as_object() else {
        *to = from.clone();
        return;
    };
    let Some(inner) = fields.get(segment) else {
        return; // missing stays missing
    };
    if !to.is_object() {
        *to = Value::Object(Map::new());
    }
    if let Some(target) = to.as_object_mut() {
        let slot = target
            .entry(segment.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        copy_path(inner, slot, segments);
    }
}

/// Run every rule; the reason codes it adds, if any. All rules run, so the same codes come
/// out however the list is ordered.
pub(crate) fn evaluate(rules: &Value, context: &Value) -> Vec<&'static str> {
    // A reader also gets here with a policy it has already refused: nothing outside the grammar
    // reaches the evaluator, whoever signed it.
    if validate(rules).is_err() {
        return vec![RULES_ERROR];
    }
    let (mut denied, mut failed) = (false, false);
    for rule in rules.as_array().map(Vec::as_slice).unwrap_or_default() {
        let logic = rule.get("logic").unwrap_or(&Value::Null);
        let mut paths = Vec::new();
        collect_paths(logic, &mut paths);
        let mut visible = Value::Object(Map::new());
        for path in paths {
            copy_path(context, &mut visible, path.split('.'));
        }
        let run = Run {
            context: visible.to_string(),
        };
        match run.boolean(logic) {
            Ok(true) => {}
            Ok(false) => denied = true,
            Err(Fault) => failed = true,
        }
    }
    let mut reasons = Vec::new();
    if denied {
        reasons.push(RULES_DENIED);
    }
    if failed {
        reasons.push(RULES_ERROR);
    }
    reasons
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn context() -> Value {
        json!({
            "intent": {
                "action_type": "report.read",
                "resource": "reports/q3",
                "tenant_id": "acme",
                "input": {"pages": 12, "tags": ["a", "b"], "ratio": 1.5, "text": "10", "yes": true,
                          "huge": 9_007_199_254_740_993u64, "nothing": null, "list": [1, 2]},
            },
            "ttl_seconds": 300,
            "money": {"amount_minor": 2500, "currency": "USD"},
        })
    }

    fn rules(logic: Value) -> Value {
        json!([{"id": "r", "logic": logic}])
    }

    fn outcome(logic: Value) -> Vec<&'static str> {
        let rules = rules(logic);
        validate(&rules).unwrap();
        evaluate(&rules, &context())
    }

    fn passes(logic: Value) {
        assert_eq!(outcome(logic.clone()), Vec::<&str>::new(), "{logic}");
    }

    fn denied(logic: Value) {
        assert_eq!(outcome(logic.clone()), vec![RULES_DENIED], "{logic}");
    }

    fn errors(logic: Value) {
        assert_eq!(outcome(logic.clone()), vec![RULES_ERROR], "{logic}");
    }

    fn refused(logic: Value) {
        let error = validate(&rules(logic.clone())).expect_err(&logic.to_string());
        assert!(error.starts_with("TEMPUS_POLICY_RULES_INVALID"), "{error}");
    }

    #[test]
    fn the_grammar_accepts_what_it_says() {
        passes(json!(true));
        denied(json!(false));
        passes(json!({"and": [true, true]}));
        denied(json!({"and": [true, false]}));
        passes(json!({"or": [false, true]}));
        denied(json!({"or": [false, false]}));
        passes(json!({"if": [true, true, false]}));
        denied(json!({"if": [false, true, false]}));
        passes(json!({"!": false}));
        passes(json!({"!": [false]}));
        passes(json!({"!!": true}));
        passes(json!({"===": [{"var": "intent.action_type"}, "report.read"]}));
        denied(json!({"===": [{"var": "intent.action_type"}, "other"]}));
        passes(json!({"!==": [{"var": "intent.action_type"}, "other"]}));
        passes(json!({"<": [1, 2]}));
        passes(json!({"<=": [2, 2]}));
        passes(json!({">": [{"var": "ttl_seconds"}, 299]}));
        denied(json!({">=": [{"var": "ttl_seconds"}, 301]}));
        passes(json!({"===": [{"var": "intent.input.yes"}, true]}));
        passes(json!({"===": [{"var": "intent.input.nothing"}, null]}));
        passes(json!({"===": [{"var": "intent.absent"}, null]}));
        passes(json!({"===": [{"var": ["intent.absent", "fallback"]}, "fallback"]}));
        passes(json!({"===": [{"var": ["intent.absent", 7]}, 7]}));
    }

    #[test]
    fn arithmetic_is_exact_or_an_error() {
        passes(json!({"===": [{"+": [2, 3]}, 5]}));
        passes(json!({"===": [{"-": [2, 3]}, -1]}));
        passes(json!({"===": [{"*": [{"var": "money.amount_minor"}, 2]}, 5000]}));
        passes(json!({"<=": [{"+": [{"var": "money.amount_minor"}, 1]}, 2501]}));
        passes(json!({"===": [{"min": [3, 1, 2]}, 1]}));
        passes(json!({"===": [{"max": [{"var": "ttl_seconds"}, 1]}, 300]}));

        // The largest exact integer, then one step past it.
        let top = MAX_SAFE_INTEGER as i64;
        passes(json!({"===": [{"+": [top - 1, 1]}, top]}));
        errors(json!({"<": [{"+": [top, 1]}, 0]}));
        errors(json!({"<": [{"*": [top, top]}, 0]}));
        errors(json!({"<": [{"-": [-top, 1]}, 0]}));
    }

    #[test]
    fn coercion_is_refused_or_an_error_never_an_answer() {
        // Refused when the policy is read.
        refused(json!({"==": [1, 1]}));
        refused(json!({"!=": [1, 2]}));
        refused(json!({"<": ["10", 9]}));
        refused(json!({"<": [1.5, 2]}));
        refused(json!({"===": [1.5, 1.5]}));
        refused(json!({"===": [[1], [1]]}));
        refused(json!({"===": [9_007_199_254_740_992u64, 0]}));
        refused(json!({"in": [1, "abc"]}));
        refused(json!({"<": [true, 2]}));
        refused(json!({"and": [1, 2]}));
        refused(json!(1));
        refused(json!("true"));
        refused(json!(null));
        refused(json!([true]));
        // Errors when the value turns out to be the wrong type: a string read as a number,
        // a float, an integer past the exact range, a missing value, a list.
        errors(json!({"<": [{"var": "intent.input.text"}, 100]}));
        errors(json!({"<": [{"var": "intent.input.ratio"}, 100]}));
        errors(json!({"<": [{"var": "intent.input.huge"}, 100]}));
        errors(json!({"<": [{"var": "intent.absent"}, 100]}));
        errors(json!({"<": [{"var": "intent.input.list"}, 100]}));
        errors(json!({"===": [{"var": "intent.input.ratio"}, 1]}));
        errors(json!({"===": [{"var": "intent.input.list"}, null]}));
        errors(json!({"===": [{"var": "intent.input"}, null]}));
        errors(json!({"and": [{"var": "intent.input.text"}]}));
        errors(json!({"and": [{"var": "intent.absent"}]}));
        errors(json!({"if": [{"var": "intent.input.pages"}, true, true]}));
        errors(json!({"in": [{"var": "intent.input.pages"}, "abc"]}));
        errors(json!({"in": ["a", {"var": "intent.input.pages"}]}));
        errors(json!({"in": ["1", {"var": "intent.input.list"}]}));
        errors(json!({"var": "intent.input.pages"}));
    }

    #[test]
    fn operators_outside_the_subset_are_refused() {
        for name in [
            "==",
            "!=",
            "/",
            "%",
            "substr",
            "cat",
            "map",
            "filter",
            "reduce",
            "all",
            "some",
            "none",
            "merge",
            "missing_some",
            "log",
            "unknown",
        ] {
            refused(json!({name: [1, 2]}));
            refused(json!({"===": [{name: [1, 2]}, 1]}));
        }
        refused(json!({"and": [true], "or": [true]}));
        refused(json!({}));
        // The right operator with the wrong shape.
        refused(json!({"and": []}));
        refused(json!({"or": []}));
        refused(json!({"if": [true, true]}));
        refused(json!({"if": [true, true, false, false, true]}));
        refused(json!({"!": [true, false]}));
        refused(json!({"<": [1, 2, 3]}));
        refused(json!({"<": [1]}));
        refused(json!({"===": [1]}));
        refused(json!({"===": [{"+": [1]}, 1]}));
        refused(json!({"===": [{"+": [1, 2, 3]}, 6]}));
        refused(json!({"===": [{"-": [1]}, -1]}));
        refused(json!({"===": [{"min": []}, 1]}));
        refused(json!({"in": ["a"]}));
        refused(json!({"in": ["a", 1]}));
        refused(json!({"in": ["a", [1]]}));
        refused(json!({"in": ["a", [{"var": "intent.tenant_id"}]]}));
        // `missing` only makes sense as a test.
        refused(json!({"missing": ["money"]}));
        refused(json!({"and": [{"missing": ["money"]}]}));
        refused(json!({"===": [{"missing": ["money"]}, null]}));
        refused(json!({"!": {"missing": []}}));
        refused(json!({"!": {"missing": [1]}}));
    }

    #[test]
    fn var_reads_only_what_a_rule_may_see() {
        for path in [
            "",
            "x",
            "intent.",
            ".intent",
            "intent..x",
            "secrets",
            "intent.a b",
            "Intent",
        ] {
            refused(json!({"var": path}));
            refused(json!({"!": {"missing": [path]}}));
        }
        refused(json!({"var": 1}));
        refused(json!({"var": []}));
        refused(json!({"var": ["intent.x", 1.5]}));
        refused(json!({"var": ["intent.x", [1]]}));
        refused(json!({"var": ["intent.x", 1, 2]}));
        refused(json!({"var": ["intent.x", {"var": "money"}]}));
    }

    #[test]
    fn a_branch_not_taken_cannot_fail() {
        let guarded = |path: &str| {
            json!({"if": [{"!": {"missing": ["intent.absent"]}},
                          {"<=": [{"var": path}, 100]},
                          true]})
        };
        passes(guarded("intent.absent"));
        passes(guarded("intent.input.text"));
        // The same read, reached, is an error.
        errors(json!({"if": [true, {"<=": [{"var": "intent.input.text"}, 100]}, true]}));
        // `and` stops at the first false, `or` at the first true.
        denied(json!({"and": [false, {"<": [{"var": "intent.input.text"}, 1]}]}));
        passes(json!({"or": [true, {"<": [{"var": "intent.input.text"}, 1]}]}));
        errors(json!({"and": [true, {"<": [{"var": "intent.input.text"}, 1]}]}));
        errors(json!({"or": [false, {"<": [{"var": "intent.input.text"}, 1]}]}));
    }

    #[test]
    fn money_can_be_absent_and_the_example_in_the_design_holds() {
        let rule = rules(json!({"if": [{"!": {"missing": ["money"]}},
                                       {"<=": [{"var": "money.amount_minor"}, 100]},
                                       true]}));
        validate(&rule).unwrap();
        let mut without = context();
        without.as_object_mut().unwrap().remove("money");
        assert_eq!(evaluate(&rule, &without), Vec::<&str>::new());
        assert_eq!(evaluate(&rule, &context()), vec![RULES_DENIED]);
    }

    #[test]
    fn in_works_on_text_and_lists() {
        passes(json!({"in": ["q3", {"var": "intent.resource"}]}));
        denied(json!({"in": ["q4", {"var": "intent.resource"}]}));
        passes(json!({"in": [{"var": "money.currency"}, ["USD", "EUR"]]}));
        denied(json!({"in": [{"var": "money.currency"}, ["JPY", "EUR"]]}));
        passes(json!({"in": ["a", {"var": "intent.input.tags"}]}));
        passes(json!({"in": ["reports", "reports/q3"]}));
    }

    #[test]
    fn tests_ask_about_any_type() {
        passes(json!({"!!": {"var": "intent.input.text"}}));
        passes(json!({"!": {"var": "intent.absent"}}));
        passes(json!({"!!": {"var": "intent.input.ratio"}}));
        passes(json!({"!": {"missing": ["money.currency", "intent.tenant_id"]}}));
        passes(json!({"!!": {"missing": ["intent.absent"]}}));
        // `missing` asks whether the key is there. A null is there.
        passes(json!({"!": {"missing": ["intent.input.nothing"]}}));
    }

    #[test]
    fn limits_are_enforced() {
        let many: Vec<Value> = (0..33)
            .map(|i| json!({"id": format!("r{i}"), "logic": true}))
            .collect();
        assert!(validate(&json!(many)).unwrap_err().contains("more than 32"));
        let thirty_two = &many[..32];
        assert!(validate(&json!(thirty_two)).is_ok());

        let wide = json!({"and": vec![json!(true); 255]});
        assert!(validate(&rules(wide)).is_ok());
        let too_wide = json!({"and": vec![json!(true); 256]});
        assert!(validate(&rules(too_wide)).unwrap_err().contains("256"));

        let mut deep = json!(true);
        for _ in 0..15 {
            deep = json!({"!": deep});
        }
        assert!(validate(&rules(deep.clone())).is_ok());
        let too_deep = json!({"!": deep});
        assert!(validate(&rules(too_deep)).unwrap_err().contains("16"));
    }

    #[test]
    fn the_list_and_the_ids_are_closed() {
        for bad in [
            json!({"id": "r", "logic": true}),
            json!("rules"),
            json!([1]),
            json!([{"logic": true}]),
            json!([{"id": "r"}]),
            json!([{"id": "", "logic": true}]),
            json!([{"id": "UP", "logic": true}]),
            json!([{"id": "a b", "logic": true}]),
            json!([{"id": "x".repeat(65), "logic": true}]),
            json!([{"id": 1, "logic": true}]),
            json!([{"id": "r", "logic": true, "note": "x"}]),
            json!([{"id": "r", "logic": true}, {"id": "r", "logic": true}]),
        ] {
            assert!(validate(&bad).is_err(), "{bad}");
        }
        assert!(validate(&json!([])).is_ok());
        assert!(validate(&json!([{"id": "a.b_c-1", "logic": true}])).is_ok());
    }

    #[test]
    fn every_rule_runs_and_the_codes_do_not_depend_on_the_order() {
        let list = |first: Value, second: Value| json!([{"id": "a", "logic": first}, {"id": "b", "logic": second}]);
        let (no, broken) = (
            json!(false),
            json!({"<": [{"var": "intent.input.text"}, 1]}),
        );
        assert_eq!(
            evaluate(&list(no.clone(), broken.clone()), &context()),
            vec![RULES_DENIED, RULES_ERROR]
        );
        assert_eq!(
            evaluate(&list(broken, no), &context()),
            vec![RULES_DENIED, RULES_ERROR]
        );
        assert_eq!(evaluate(&json!([]), &context()), Vec::<&str>::new());
    }

    #[test]
    fn a_rule_sees_the_same_with_a_narrowed_context() {
        let mut visible = Value::Object(Map::new());
        let full = context();
        for path in [
            "intent.input.tags",
            "intent.input",
            "money.currency",
            "money.absent",
            "ttl_seconds.x",
        ] {
            copy_path(&full, &mut visible, path.split('.'));
        }
        assert_eq!(visible["intent"]["input"], full["intent"]["input"]);
        assert_eq!(visible["money"]["currency"], "USD");
        assert_eq!(visible["ttl_seconds"], 300);
        assert!(visible["intent"].get("resource").is_none());
        assert!(visible["money"].get("amount_minor").is_none());

        // A long input a rule does not read does not reach the evaluator.
        let mut large = context();
        large["intent"]["input"]["blob"] = json!("x".repeat(1_000_000));
        let rule = rules(json!({"===": [{"var": "ttl_seconds"}, 300]}));
        assert_eq!(evaluate(&rule, &large), Vec::<&str>::new());
    }
}
