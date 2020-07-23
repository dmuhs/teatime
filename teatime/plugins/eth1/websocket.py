from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Issue, Severity


class GethStartWebsocket(Plugin):
    def _check(self, context: Context) -> None:
        """Try to start the websocket service.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(context.target, method="admin_startWS", params=[])
        context.report.add_issue(
            Issue(
                title="Admin Websocket Start Rights",
                description="The RPC Websocket service can be started using the admin_startWS RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )


class GethStopWebsocket(Plugin):
    def _check(self, context: Context) -> None:
        """Try to stop the websocket service.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(context.target, method="admin_stopWS", params=[])
        context.report.add_issue(
            Issue(
                title="Admin Websocket Stop Rights",
                description="The RPC Websocket service can be stopped using the admin_stopWS RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )
