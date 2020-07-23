from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Issue, Severity


class GethStartRPC(Plugin):
    def _check(self, context: Context) -> None:
        """Try to start the RPC service.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(context.target, method="admin_startRPC", params=[])
        context.report.add_issue(
            Issue(
                title="Admin RPC Start Rights",
                description="The HTTP RPC service can be started using the admin_startRPC RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )


class GethStopRPC(Plugin):
    def _check(self, context: Context) -> None:
        """Try to stop the RPC service.

        Talking about shooting yourself in the foot.
        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(context.target, method="admin_stopRPC", params=[])
        context.report.add_issue(
            Issue(
                title="Admin RPC Stop Rights",
                description="The HTTP RPC service can be stopped using the admin_stopRPC RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )
