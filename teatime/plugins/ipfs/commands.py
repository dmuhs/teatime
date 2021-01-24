"""This module contains plugins regarding commands surfaced by the node."""

from typing import Optional, Sequence

from teatime import Context, Issue, NodeType, PluginException, Severity
from teatime.plugins import IPFSRPCPlugin

ALL_COMMANDS = [
    ("refs",),
    (
        "refs",
        "local",
    ),
    ("cid",),
    (
        "cid",
        "codecs",
    ),
    (
        "cid",
        "hashes",
    ),
    (
        "cid",
        "format",
    ),
    (
        "cid",
        "base32",
    ),
    (
        "cid",
        "bases",
    ),
    ("dht",),
    (
        "dht",
        "put",
    ),
    (
        "dht",
        "provide",
    ),
    (
        "dht",
        "query",
    ),
    (
        "dht",
        "findprovs",
    ),
    (
        "dht",
        "findpeer",
    ),
    (
        "dht",
        "get",
    ),
    ("key",),
    (
        "key",
        "rm",
    ),
    (
        "key",
        "rotate",
    ),
    (
        "key",
        "gen",
    ),
    (
        "key",
        "export",
    ),
    (
        "key",
        "import",
    ),
    (
        "key",
        "list",
    ),
    (
        "key",
        "rename",
    ),
    ("log",),
    (
        "log",
        "level",
    ),
    (
        "log",
        "ls",
    ),
    (
        "log",
        "tail",
    ),
    ("p2p",),
    (
        "p2p",
        "close",
    ),
    (
        "p2p",
        "ls",
    ),
    (
        "p2p",
        "stream",
    ),
    (
        "p2p",
        "stream",
        "ls",
    ),
    (
        "p2p",
        "stream",
        "close",
    ),
    (
        "p2p",
        "forward",
    ),
    (
        "p2p",
        "listen",
    ),
    ("ping",),
    ("cat",),
    ("dag",),
    (
        "dag",
        "stat",
    ),
    (
        "dag",
        "put",
    ),
    (
        "dag",
        "get",
    ),
    (
        "dag",
        "resolve",
    ),
    (
        "dag",
        "import",
    ),
    (
        "dag",
        "export",
    ),
    ("dns",),
    ("ls",),
    ("bitswap",),
    (
        "bitswap",
        "wantlist",
    ),
    (
        "bitswap",
        "ledger",
    ),
    (
        "bitswap",
        "reprovide",
    ),
    (
        "bitswap",
        "stat",
    ),
    ("resolve",),
    ("update",),
    ("shutdown",),
    ("block",),
    (
        "block",
        "stat",
    ),
    (
        "block",
        "get",
    ),
    (
        "block",
        "put",
    ),
    (
        "block",
        "rm",
    ),
    ("filestore",),
    (
        "filestore",
        "ls",
    ),
    (
        "filestore",
        "verify",
    ),
    (
        "filestore",
        "dups",
    ),
    ("pubsub",),
    (
        "pubsub",
        "pub",
    ),
    (
        "pubsub",
        "sub",
    ),
    (
        "pubsub",
        "ls",
    ),
    (
        "pubsub",
        "peers",
    ),
    ("name",),
    (
        "name",
        "publish",
    ),
    (
        "name",
        "resolve",
    ),
    (
        "name",
        "pubsub",
    ),
    (
        "name",
        "pubsub",
        "state",
    ),
    (
        "name",
        "pubsub",
        "subs",
    ),
    (
        "name",
        "pubsub",
        "cancel",
    ),
    ("id",),
    ("mount",),
    ("files",),
    (
        "files",
        "ls",
    ),
    (
        "files",
        "stat",
    ),
    (
        "files",
        "rm",
    ),
    (
        "files",
        "flush",
    ),
    (
        "files",
        "read",
    ),
    (
        "files",
        "write",
    ),
    (
        "files",
        "mv",
    ),
    (
        "files",
        "cp",
    ),
    (
        "files",
        "mkdir",
    ),
    (
        "files",
        "chcid",
    ),
    ("repo",),
    (
        "repo",
        "verify",
    ),
    (
        "repo",
        "stat",
    ),
    (
        "repo",
        "gc",
    ),
    (
        "repo",
        "fsck",
    ),
    (
        "repo",
        "version",
    ),
    ("config",),
    (
        "config",
        "show",
    ),
    (
        "config",
        "edit",
    ),
    (
        "config",
        "replace",
    ),
    (
        "config",
        "profile",
    ),
    (
        "config",
        "profile",
        "apply",
    ),
    ("diag",),
    (
        "diag",
        "sys",
    ),
    (
        "diag",
        "cmds",
    ),
    (
        "diag",
        "cmds",
        "clear",
    ),
    (
        "diag",
        "cmds",
        "set-time",
    ),
    ("swarm",),
    (
        "swarm",
        "disconnect",
    ),
    (
        "swarm",
        "filters",
    ),
    (
        "swarm",
        "filters",
        "add",
    ),
    (
        "swarm",
        "filters",
        "rm",
    ),
    (
        "swarm",
        "peers",
    ),
    (
        "swarm",
        "addrs",
    ),
    (
        "swarm",
        "addrs",
        "local",
    ),
    (
        "swarm",
        "addrs",
        "listen",
    ),
    (
        "swarm",
        "connect",
    ),
    ("urlstore",),
    (
        "urlstore",
        "add",
    ),
    ("version",),
    (
        "version",
        "deps",
    ),
    ("commands",),
    ("get",),
    ("bootstrap",),
    (
        "bootstrap",
        "list",
    ),
    (
        "bootstrap",
        "add",
    ),
    (
        "bootstrap",
        "add",
        "default",
    ),
    (
        "bootstrap",
        "rm",
    ),
    (
        "bootstrap",
        "rm",
        "all",
    ),
    ("pin",),
    (
        "pin",
        "add",
    ),
    (
        "pin",
        "rm",
    ),
    (
        "pin",
        "ls",
    ),
    (
        "pin",
        "verify",
    ),
    (
        "pin",
        "update",
    ),
    ("file",),
    (
        "file",
        "ls",
    ),
    ("add",),
    ("stats",),
    (
        "stats",
        "bitswap",
    ),
    (
        "stats",
        "dht",
    ),
    (
        "stats",
        "bw",
    ),
    (
        "stats",
        "repo",
    ),
    ("object",),
    (
        "object",
        "diff",
    ),
    (
        "object",
        "get",
    ),
    (
        "object",
        "links",
    ),
    (
        "object",
        "new",
    ),
    (
        "object",
        "patch",
    ),
    (
        "object",
        "patch",
        "append-data",
    ),
    (
        "object",
        "patch",
        "add-link",
    ),
    (
        "object",
        "patch",
        "rm-link",
    ),
    (
        "object",
        "patch",
        "set-data",
    ),
    (
        "object",
        "put",
    ),
    (
        "object",
        "stat",
    ),
    (
        "object",
        "data",
    ),
    ("tar",),
    (
        "tar",
        "cat",
    ),
    (
        "tar",
        "add",
    ),
]


def _get_by_path(data: dict, path: Sequence[str]):
    if not path:
        return data
    if not data:
        return None

    for item in data.get("Subcommands"):
        if item.get("Name", "") == path[0]:
            return _get_by_path(data=item, path=path[1:])

    return None


class CommandCheck(IPFSRPCPlugin):
    """Detect whether disallowed commands are enabled.

    Severity: High

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-commands

    The IPFS API offers a lot of endpoints, some of which might be accidentally
    enabled. This plugin attempts to fetch the list of enabled API commands and
    will log an issue of user-specified commands are enabled, or not enabled.
    """

    INTRUSIVE = False

    def __init__(
        self,
        allowlist: Optional[Sequence[Sequence[str]]] = None,
        denylist: Optional[Sequence[Sequence[str]]] = None,
    ):
        if allowlist is None and denylist is None:
            # deny the presence of all endpoints by default
            self.allowlist = []
            self.denylist = ALL_COMMANDS
        else:
            self.allowlist = allowlist or []
            self.denylist = denylist or []
        if set(self.allowlist).intersection(set(self.denylist)):
            raise PluginException("Must not have overlap between allow- and denylist")

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        payload = self.get_rpc_json(
            target=context.target,
            route="/api/v0/commands",
        )

        for command in ALL_COMMANDS:
            item = _get_by_path(payload, command)
            if item is not None and (
                command in self.denylist or command not in self.allowlist
            ):
                context.report.add_issue(
                    Issue(
                        title="Forbidden Method is Exposed",
                        description=(
                            "A forbidden API method is open to the Internet. Attackers "
                            "may be able to use the exposed functionality to cause undesired "
                            "effects to the system."
                        ),
                        severity=Severity.HIGH,
                        raw_data=item,
                    )
                )
