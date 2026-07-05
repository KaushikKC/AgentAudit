"""Local web dashboard for browsing and verifying audit evidence.

``agentaudit serve`` starts a self-contained single-page app (no external deps)
backed by the real verification engine -- every status shown is a live
``verify_bundle`` result, never a cached claim.
"""

from agentaudit.dashboard.data import DashboardData

__all__ = ["DashboardData", "serve"]


def serve(*args, **kwargs):  # lazy import so the package has no import-time cost
    from agentaudit.dashboard.server import serve as _serve

    return _serve(*args, **kwargs)
