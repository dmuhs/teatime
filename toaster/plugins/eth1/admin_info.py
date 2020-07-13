"""This module contains plugins with admin interface checks."""

from toaster.plugins import Context, NodeType, Plugin
from toaster.reporting import Issue, Severity

TEST_ENODE = (
    "enode://6f8a80d14311c39f35f516fa664deaaaa13"
    "e85b2f7493f37f6144d86991ec012937307647bd3b9"
    "a82abe2974e1407241d54947bbb39763a4cac9f7716"
    "6ad92a0@10.3.58.6:30303?discport=30301"
)


class GethAdminCheck(Plugin):
    """Check for weaknesses on the Geth admin interface."""

    name = "Geth Admin Information Leaks"
    version = "0.5.0"
    node_type = (NodeType.GETH,)

    def __repr__(self):
        return f"<GethAdminCheck v{self.version}>"

    def check_datadir_access(self, context):
        """Try to fetch Geth's data directory.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(context.target, method="admin_datadir", params=[])
        context.report.add_issue(
            Issue(
                title="Admin datadir access",
                description="The datadir directory path can be fetched using the admin_datadir RPC call.",
                raw_data=payload,
                severity=Severity.LOW,
            )
        )

    def check_add_peer(self, context):
        """Try to add a peer to the node's peer list.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(
            context.target, method="admin_addPeer", params=TEST_ENODE
        )
        context.report.add_issue(
            Issue(
                title="Admin peer manipulation",
                description="Arbitrary peers can be added using the admin_addPeer RPC call.",
                raw_data=payload,
                severity=Severity.HIGH,
            )
        )

    def check_node_info(self, context):
        """Try to fetch admin info about the node.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(context.target, method="admin_nodeInfo", params=[])
        context.report.add_issue(
            Issue(
                title="Admin Node Info Leaks",
                description="Admin-only information can be fetched using the admin_nodeInfo RPC call.",
                raw_data=payload,
                severity=Severity.LOW,
            )
        )

    def check_peerlist_info(self, context):
        """Try to fetch information about the node's peer list.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(context.target, method="admin_peers", params=[])
        context.report.add_issue(
            Issue(
                title="Admin Peerlist Access",
                description="Admin-only information about the peer list can be fetched using the admin_peers RPC call.",
                raw_data=payload,
                severity=Severity.MEDIUM,
            )
        )

    def check_rpc_start(self, context):
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

    def check_rpc_stop(self, context):
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

    def check_websocket_start(self, context):
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

    def check_websocket_stop(self, context):
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

    def run(self, context: Context):
        """Run the Geth-related admin interface checks.

        .. todo:: Add details!

        :param context:
        :return:
        """
        if context.node_type != NodeType.GETH:
            return

        # SCAN[LOW]: GETH datadir information leak
        self.run_catch("Geth datadir access", self.check_datadir_access, context)
        # SCAN[HIGH]: GETH peerlist manipulation
        self.run_catch("Geth add peer", self.check_add_peer, context)
        # SCAN[LOW]: GETH node information leaks
        self.run_catch("Geth node info", self.check_node_info, context)
        # SCAN[MEDIUM]: GETH peer list information leaks
        self.run_catch("Geth peerlist info", self.check_peerlist_info, context)
        # SCAN[CRITICAL]: GETH RPC start rights
        self.run_catch("Geth RPC start", self.check_rpc_start, context)
        # SCAN[CRITICAL]: GETH RPC stop rights
        self.run_catch("Geth RPC stop", self.check_rpc_stop, context)
        # SCAN[CRITICAL]: GETH Websocket start rights
        self.run_catch("Geth websocket start", self.check_websocket_start, context)
        # SCAN[CRITICAL]: GETH Websocket stop rights
        self.run_catch("Geth websocket stop", self.check_websocket_stop, context)

        context.report.add_meta(self.name, self.version)


class ParityAdminCheck(Plugin):
    """Check for weaknesses on the Parity/OpenEthereum admin interface."""

    name = "Parity Admin Information Leaks"
    version = "0.5.0"
    node_type = (NodeType.PARITY,)

    def __repr__(self):
        return f"<ParityAdminCheck v{self.version}>"

    def check_dev_log(self, context):
        """Try to fetch the node's developer logs.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(context.target, method="parity_devLogs", params=[])
        context.report.add_issue(
            Issue(
                title="Developer log information leak",
                description="The node's developer logs can be fetched using the parity_devLogs RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )

    def check_peerlist(self, context):
        """Try to fetch peer list information.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(context.target, method="parity_netPeers", params=[])
        context.report.add_issue(
            Issue(
                title="Peer list information leak",
                description="Admin-only peer list information can be fetched with the parity_netPeers RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )

    def check_peerlist_manipulation(self, context):
        """Try to add a reserved peer.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(
            context.target, method="parity_addReservedPeer", params=[TEST_ENODE]
        )
        context.report.add_issue(
            Issue(
                title="Peer list manipulation",
                description="Reserved peers can be added to the node's peer list using the parity_addReservedPeer RPC "
                            "call",
                raw_data=payload,
                severity=Severity.HIGH,
            )
        )

    def check_drop_peers(self, context):
        """Try to remove non-reserved peers from the peer list.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(
            context.target, method="parity_dropNonReservedPeers"
        )
        if payload:
            context.report.add_issue(
                Issue(
                    title="Peer list manipulation",
                    description="Anyone can drop the non-reserved peerlist on the node using the "
                                "parity_dropNonReservedPeers RPC call.",
                    raw_data=payload,
                    severity=Severity.CRITICAL,
                )
            )

    def check_change_coinbase(self, context):
        """Try to change the coinbase address.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(
            context.target,
            method="parity_setAuthor",
            params=["0x25862BB810eEC365C4562FEAA8B2739B59B70A6a"],
        )
        context.report.add_issue(
            Issue(
                title="Coinbase address change possible",
                description="Anyone can change the coinbase address and redirect miner payouts using the "
                            "parity_setAuthor RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )

    def check_change_target_chain(self, context):
        """Try to change the target chain.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(
            context.target, method="parity_setChain", params=["mainnet"]
        )
        context.report.add_issue(
            Issue(
                title="Chain preset change possible",
                description="Anyone can change the node's target chain value using the parity_setChain RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )

    def change_extra_data(self, context):
        """Try to set the extra data field.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(
            context.target, method="parity_setExtraData", params=["toasted"]
        )
        context.report.add_issue(
            Issue(
                title="Extra data change possible",
                description="Anyone can change the extra data attached to newly mined blocks using the "
                            "parity_setExtraData RPC call.",
                raw_data=payload,
                severity=Severity.LOW,
            )
        )

    def check_set_gas_ceiling(self, context):
        """Try to set the gas ceiling.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(
            context.target, method="parity_setGasCeilTarget", params=["0x2540be400"]
        )
        context.report.add_issue(
            Issue(
                title="Gas ceiling target can be changed",
                description="Anyone can change the gas ceiling value using the parity_setGasCeilTarget RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )

    def check_set_gas_floor(self, context):
        """Try to set the gas floor.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(
            context.target, method="parity_setGasFloorTarget", params=["0x0"]
        )
        context.report.add_issue(
            Issue(
                title="Gas floor target can be changed",
                description="Anyone can change the gas floor value using the parity_setGasFloorTarget RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )

    def check_set_max_tx_gas(self, context):
        """Try to set the maximum transaction gas.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(
            context.target, method="parity_setMaxTransactionGas", params=["0x186a0"]
        )
        context.report.add_issue(
            Issue(
                title="Transaction maximum gas can be changed",
                description="Anyone can change the maximum transaction gas limit using the "
                            "parity_setMaxTransactionGas RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )

    def check_set_min_tx_gas(self, context):
        """Try to set the minimum transaction gas limit.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(
            context.target, method="parity_setMinGasPrice", params=["0x0"]
        )
        context.report.add_issue(
            Issue(
                title="Transaction minimum gas can be changed",
                description="Anyone can change the minimum transaction gas limit using the parity_setMinGasPrice RPC "
                            "call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )

    def check_set_sync_mode(self, context):
        """Try to set the node's sync mode.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(
            context.target, method="parity_setMode", params=["active"]
        )
        context.report.add_issue(
            Issue(
                title="The sync mode can be changed",
                description="Anyone can change the node's sync mode using the parity_setMode RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )

    def check_parity_upgrade(self, context):
        """Try to check for an available upgrade.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(context.target, method="parity_upgradeReady")
        context.report.add_issue(
            Issue(
                title="The node can be upgraded",
                description="Anyone can upgrade the node using the parity_upgradeReady RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )

    def run(self, context: Context):
        """Run the Parity/OpenEthereum-related admin interface checks.

        .. todo:: Add details!

        :param context:
        :return:
        """
        if context.node_type != NodeType.PARITY:
            return

        # SCAN[CRITICAL]: PARITY dev log leak
        self.run_catch("Parity dev log info leak", self.check_dev_log, context)
        # SCAN[MEDIUM]: PARITY peer list information leaks
        self.run_catch("Parity peerlist info leak", self.check_peerlist, context)
        # SCAN[HIGH]: PARITY peerlist manipulation
        self.run_catch(
            "Parity peerlist manipulation", self.check_peerlist_manipulation, context
        )
        # SCAN[CRITICAL]: PARITY drop non-reserved peers
        self.run_catch("Parity reserved peer drop", self.check_drop_peers, context)
        # SCAN[CRITICAL]: PARITY change coinbase address
        self.run_catch("Parity change coinbase", self.check_change_coinbase, context)
        # SCAN[CRITICAL]: PARITY change target chain
        self.run_catch("Parity change chain", self.check_change_target_chain, context)
        # SCAN[LOW]: PARITY change extra data
        self.run_catch("Parity change extra data", self.change_extra_data, context)
        # SCAN[CRITICAL]: PARITY set gas ceiling target
        self.run_catch("Parity set gas ceiling", self.check_set_gas_ceiling, context)
        # SCAN[CRITICAL]: PARITY set gas floor target
        self.run_catch("Parity set gas floor", self.check_set_gas_floor, context)
        # SCAN[CRITICAL]: PARITY set maximum tx gas limit
        self.run_catch("Parity set max gas limit", self.check_set_max_tx_gas, context)
        # SCAN[CRITICAL]: PARITY set minimum tx gas limit
        self.run_catch("Parity set min gas limit", self.check_set_min_tx_gas, context)
        # SCAN[CRITICAL]: PARITY sync mode can be set
        self.run_catch("Parity set sync mode", self.check_set_sync_mode, context)
        # SCAN[CRITICAL]: PARITY upgrade check
        self.run_catch("Parity upgrade", self.check_parity_upgrade, context)

        context.report.add_meta(self.name, self.version)


class AdminInformationLeakCheck(Plugin):
    """Detect admin-interface-related weaknesses."""

    name = "Admin Information Leaks"
    version = "0.0.2"

    def run(self, context):
        """Run admin-interface checks.

        .. todo:: Add details!

        :param context:
        :return:
        """
        if context.node_type == NodeType.GETH:
            plugin = GethAdminCheck()
        elif context.node_type == NodeType.PARITY:
            plugin = ParityAdminCheck()
        else:
            return
        plugin.run(context)
