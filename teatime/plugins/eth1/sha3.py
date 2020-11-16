"""This module contains a plugin to check for SHA3 consistency."""

from teatime.plugins import Context, JSONRPCPlugin
from teatime.reporting import Issue, Severity


class SHA3Consistency(JSONRPCPlugin):
    """Check for SHA3 consistency.

    Severity: Critical

    This plugin submits a user-specified value and lets the node
    convert it into a SHA3 hash using the :code:`web3_sha3` method. If
    the result value is different from the user-specified output value,
    an issue is logged.
    """

    INTRUSIVE = False

    def __init__(self, test_input: str, test_output: str):
        self.test_input = test_input
        self.test_output = test_output

    def _check(self, context: Context) -> None:
        sha_hash = self.get_rpc_json(
            target=context.target, method="web3_sha3", params=[self.test_input]
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
