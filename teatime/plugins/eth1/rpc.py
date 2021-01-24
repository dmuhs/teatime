"""This module contains plugins for controlling the HTTP RPC server status."""
from teatime.plugins import Context, JSONRPCPlugin, NodeType
from teatime.reporting import Issue, Severity


class GethStartRPC(JSONRPCPlugin):
    """Try to start the RPC service.

    Severity: Critical

    This plugin attempts to start the HTTP RPC interface using the
    :code:`admin_startRPC` method.
    """

    INTRUSIVE = True

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.GETH:
            return

        payload = self.get_rpc_json(context.target, method="admin_startRPC")
        if payload:
            context.report.add_issue(
                Issue(
                    title="Admin RPC Start Rights",
                    description=(
                        "The HTTP RPC service can be started "
                        "using the admin_startRPC RPC call."
                    ),
                    raw_data=payload,
                    severity=Severity.CRITICAL,
                )
            )


class GethStopRPC(JSONRPCPlugin):
    """Try to stop the RPC service.

    Severity: Critical

    Talking about shooting yourself in the foot. This plugin attempts to stop
    the HTTP RPC interface using the :code:`admin_stopRPC` method. In case you
    didn't notice, this might affect the outcome of other plugins due to
    connection failures.
    """

    INTRUSIVE = True

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.GETH:
            return

        payload = self.get_rpc_json(context.target, method="admin_stopRPC")
        if payload:
            context.report.add_issue(
                Issue(
                    title="Admin RPC Stop Rights",
                    description=(
                        "The HTTP RPC service can be stopped "
                        "using the admin_stopRPC RPC call."
                    ),
                    raw_data=payload,
                    severity=Severity.CRITICAL,
                )
            )
