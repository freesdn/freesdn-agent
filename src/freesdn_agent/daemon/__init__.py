"""FreeSDN Agent - Daemon mode for headless operation."""

from typing import TYPE_CHECKING, Any

__all__ = ["run_daemon"]

if TYPE_CHECKING:  # pragma: no cover
    from freesdn_agent.daemon.main import run_daemon


def __getattr__(name: str) -> Any:
    """
    Lazily re-export ``run_daemon`` (PEP 562).

    ``__all__`` has always advertised ``run_daemon``, but the name was never
    bound here, so ``from freesdn_agent.daemon import run_daemon`` raised
    ImportError and ``import *`` raised AttributeError. The only in-tree caller
    (``daemon/cli.py``) sidesteps it by importing from ``daemon.main`` inside a
    function, which is why nothing broke.

    Resolving it lazily rather than importing at module scope preserves that
    deferral: ``daemon.main`` pulls in the full daemon stack, and importing the
    package should not pay for that.
    """
    if name == "run_daemon":
        from freesdn_agent.daemon.main import run_daemon

        return run_daemon
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
