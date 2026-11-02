"""Reference HTTP, Slack and payment executors for Tempus permits.

These adapters live outside the ``tempus-ddb`` wheel. They run on the core
``ExecutorRuntime`` and pass the same ``AdapterConformanceHarness`` as the GitHub
executor that stays in ``tempus_ddb``, but they are reference integrations, not part of
the protocol surface: this distribution (``tempus-executors-contrib``) is not published
to PyPI and is installed from the repository with ``pip install -e contrib/executors``.

- HttpExecutorAdapter / HttpActionAdapter: credential-isolated HTTPS webhook executor.
- SlackExecutorAdapter / SlackActionAdapter: credential-isolated Slack message executor.
- PaymentExecutorAdapter / PaymentActionAdapter: disburse/transfer executor with the
  universal ``money`` envelope and a pluggable ``PaymentTransport``.
"""

__version__ = "0.7.0"

from .http import (
    HttpActionAdapter,
    HttpAPIError,
    HttpExecutorAdapter,
    HttpExecutorError,
    HttpTransport,
    UrllibHttpTransport,
)
from .payment import (
    MockPaymentTransport,
    PaymentActionAdapter,
    PaymentExecutorAdapter,
    PaymentExecutorError,
    PaymentTransport,
    canonical_money,
    component_pattern_matches,
)
from .slack import (
    SlackActionAdapter,
    SlackExecutorAdapter,
    SlackExecutorError,
    SlackTransport,
    UrllibSlackTransport,
)

__all__ = [
    "HttpAPIError",
    "HttpActionAdapter",
    "HttpExecutorAdapter",
    "HttpExecutorError",
    "HttpTransport",
    "MockPaymentTransport",
    "PaymentActionAdapter",
    "PaymentExecutorAdapter",
    "PaymentExecutorError",
    "PaymentTransport",
    "SlackActionAdapter",
    "SlackExecutorAdapter",
    "SlackExecutorError",
    "SlackTransport",
    "UrllibHttpTransport",
    "UrllibSlackTransport",
    "__version__",
    "canonical_money",
    "component_pattern_matches",
]
