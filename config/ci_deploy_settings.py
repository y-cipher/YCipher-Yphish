"""Deployment checks with only the trial's two documented HSTS exceptions."""

from .settings import *  # noqa: F403

# The trial does not promise HTTPS for all subdomains or a browser preload entry.
# All other deployment warnings remain fatal in CI.
SILENCED_SYSTEM_CHECKS = ["security.W005", "security.W021"]
