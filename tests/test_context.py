from teatime import Context, NodeType, Report


def test_valid_context():
    target = "127.0.0.1:8545"
    node_type = NodeType.GETH
    context = Context(
        target=target,
        report=Report(target=target),
        node_type=node_type,
    )

    assert context.target == target
    assert context.node_type == node_type
    assert context.report.target == target
    assert context.report.issues == []
