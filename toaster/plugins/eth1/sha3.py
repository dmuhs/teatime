"""This module contains a plugin to check for SHA3 consistency."""

from toaster.plugins import Context, NodeType, Plugin
from toaster.reporting import Issue, Severity


class SHA3Check(Plugin):
    """A plugin checking for consistency of SHA3 hashes."""
    name = "RPC SHA3 Consistency Test"
    version = "0.1.0"
    node_type = (NodeType.GETH, NodeType.PARITY)

    def __repr__(self):
        return f"<SHA3Check v{self.version}>"

    def check_sha3_consistency(self, context):
        """Check for SHA3 consistency.

        .. todo:: Add details!

        :param context:
        """
        expected = "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
        sha_hash = self.get_rpc_json(
            target=context.target,
            method="web3_sha3",
            params=["0x68656c6c6f20776f726c64"],
        )
        if sha_hash != expected:
            context.report.add_issue(
                Issue(
                    title="SHA3 test failed",
                    description=f"Expected {expected} but received {sha_hash}",
                    raw_data=sha_hash,
                    severity=Severity.CRITICAL,
                )
            )

    def run(self, context: Context):
        """Run the SHA3 consistency check.

        :param context:
        """
        # SCAN[CRITICAL]: Malformed SHA3 hash calculation
        self.run_catch("SHA3 consistency", self.check_sha3_consistency, context)

        context.report.add_meta(self.name, self.version)
