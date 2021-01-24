"""This module contains plugins regarding file uploads to the node."""

import io
import tarfile

from teatime import Context, Issue, NodeType, Severity
from teatime.plugins.base import IPFSRPCPlugin


class OpenUploadAdd(IPFSRPCPlugin):
    """Detect where it's possible to upload a file using the /add endpoint.

    Severity: High

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-add

    An open upload functionality can enable an attacker to upload a lot
    of random data until storage space is exhausted, thus performing a
    denial of service attack against future uploads.
    """

    INTRUSIVE = True

    def __init__(
        self, file_name: str = ".teatime", file_content: str = "teatime test file"
    ):
        self.file_name = file_name
        self.file_content = file_content

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        payload = self.get_rpc_json(
            target=context.target,
            route="/api/v0/add",
            files={self.file_name: self.file_content.encode("utf-8")},
        )

        context.report.add_issue(
            Issue(
                title="Anyone can upload data to the node",
                description=(
                    "Anyone is able to upload files to the node. An attacker can use this to "
                    "upload large amounts of data and thus prevent the node from accepting "
                    "further uploads, performing a Denial of Service (DoS) attack."
                ),
                raw_data=payload,
                severity=Severity.HIGH,
            )
        )


class OpenUploadTarAdd(IPFSRPCPlugin):
    """Detect where it's possible to upload a file using the /tar/add endpoint.

    Severity: High

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-tar-add

    An open upload functionality can enable an attacker to upload a lot
    of random data until storage space is exhausted, thus performing a
    denial of service attack against future uploads.
    """

    INTRUSIVE = True

    def __init__(
        self, file_name: str = ".teatime", file_content: str = "teatime test file"
    ):
        self.file_name = file_name
        self.file_content = file_content

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        fh = io.BytesIO()
        content = io.BytesIO(self.file_content.encode("utf-8"))
        with tarfile.open(fileobj=fh, mode="w:gz") as tar:
            info = tarfile.TarInfo(self.file_name)
            info.size = len(self.file_content)
            tar.addfile(info, content)

        payload = self.get_rpc_json(
            target=context.target,
            route="/api/v0/tar/add",
            files={self.file_name: fh},
        )

        context.report.add_issue(
            Issue(
                title="Anyone can upload compressed data to the node",
                description=(
                    "Anyone is able to upload files to the node. An attacker can use this to "
                    "upload large amounts of data and thus prevent the node from accepting "
                    "further uploads, performing a Denial of Service (DoS) attack."
                ),
                raw_data=payload,
                severity=Severity.HIGH,
            )
        )
