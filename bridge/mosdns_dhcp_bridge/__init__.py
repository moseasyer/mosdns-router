"""Read-only NetworkManager DHCP DNS bridge for the MOSDNS router.

The package answers one question for the router's ``dhcp_forward`` plugin: which
resolvers does the current DHCP lease point at, and which source said so.
``collect_dns_with_source`` reads them from NetworkManager and reports the source
that answered, ``publish_if_changed`` commits them as a versioned state file a
fail-closed reader can validate, compare, and reload without restarting the
resolver, and the ``cli`` module is the program one NetworkManager dispatcher
event runs. Nothing here changes NetworkManager configuration, restarts a
resolver, or rewrites the host's resolver state.

``cli`` is deliberately not re-exported here: a package that imports its own
entry point makes ``python3 -m mosdns_dhcp_bridge.cli`` load the module twice and
warn about it on every dispatcher event.
"""

from .collect import collect_dns, collect_dns_with_source
from .publish import publish_if_changed

__all__ = ["collect_dns", "collect_dns_with_source", "publish_if_changed"]
