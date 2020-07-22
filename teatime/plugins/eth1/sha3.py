"""This module contains a plugin to check for SHA3 consistency."""

from teatime.plugins import Context, Plugin
from teatime.reporting import Issue, Severity


class SHA3Check(Plugin):
    """A plugin checking for consistency of SHA3 hashes."""

    name = "RPC SHA3 Consistency Test"
    version = "0.1.1"

    def __init__(self, test_input: str, test_output: str):
        self.test_input = test_input
        self.test_output = test_output

    def __repr__(self):
        return f"<SHA3Check v{self.version}>"

    def check_sha3_consistency(self, context: Context) -> None:
        """Check for SHA3 consistency.

        .. todo:: Add details!

        :param context:
        """
        sha_hash = self.get_rpc_json(
            target=context.target, method="web3_sha3", params=[self.test_input],
        )
        if sha_hash != self.test_output:
            context.report.add_issue(
                Issue(
                    title="SHA3 test failed",
                    description=f"Expected {self.test_output} but received {sha_hash}",
                    raw_data=sha_hash,
                    severity=Severity.CRITICAL,
                )
            )

    def run(self, context: Context) -> None:
        """Run the SHA3 consistency check.

        :param context:
        """
        # SCAN[CRITICAL]: Malformed SHA3 hash calculation
        self.run_catch("SHA3 consistency", self.check_sha3_consistency, context)

        context.report.add_meta(self.name, self.version)
