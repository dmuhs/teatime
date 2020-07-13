"""This module contains the logic to build new scanner objects."""

from dataclasses import dataclass, field

from toaster.plugins import NodeType
from toaster.plugins.eth1 import (
    AdminInformationLeakCheck,
    MiningNodeDetector,
    NetworkMethodCheck,
    NewAccountCheck,
    NodeSyncedCheck,
    NodeVersionCheck,
    OpenAccountsCheck,
    SHA3Check,
    TxPoolCheck,
)
from toaster.scanner.scanner import Scanner


@dataclass
class ETH1ScannerConfig:
    """The configuration to build an Ethereum 1.0 scanner.

    .. todo:: Add details!
    .. todo::
        This can be defined by the user
        configs could be split up per check to pass parameters as well
        -> can map directly to user config interface
    """

    uri: str
    node_type: NodeType
    account_creation: dict = field(default_factory=dict)
    admin_info: dict = field(default_factory=dict)
    mining: dict = field(default_factory=dict)
    network: dict = field(default_factory=dict)
    accounts: dict = field(default_factory=dict)
    sha3: dict = field(default_factory=dict)
    syncing: dict = field(default_factory=dict)
    txpool: dict = field(default_factory=dict)
    version: dict = field(default_factory=dict)


class ScannerFactory:
    """Factory to build new scanners."""

    @staticmethod
    def build_eth1(scanner_config: ETH1ScannerConfig):
        """Build a new Ethereum 1.0 scanner.

        .. todo:: Add details!

        :param scanner_config:
        :return:
        """
        pipeline = (
            (scanner_config.account_creation, NewAccountCheck),
            (scanner_config.admin_info, AdminInformationLeakCheck),
            (scanner_config.mining, MiningNodeDetector),
            (scanner_config.network, NetworkMethodCheck),
            (scanner_config.accounts, OpenAccountsCheck),
            (scanner_config.sha3, SHA3Check),
            (scanner_config.syncing, NodeSyncedCheck),
            (scanner_config.txpool, TxPoolCheck),
            (scanner_config.version, NodeVersionCheck),
        )
        plugin_list = [
            plugin_cls.setup(config["settings"])
            for config, plugin_cls in pipeline
            if config["enabled"]
        ]

        return Scanner(
            target=scanner_config.uri,
            plugins=plugin_list,
            node_type=scanner_config.node_type,
        )
