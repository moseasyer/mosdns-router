"""Read-only NetworkManager DHCP DNS bridge for the MOSDNS router.

The package collects what DNS a DHCP lease pointed the router at and publishes
it for the ``dhcp_forward`` plugin. It never changes NetworkManager
configuration, never restarts a resolver, and never rewrites the host's
resolver state.
"""

from .collect import collect_dns

__all__ = ["collect_dns"]
