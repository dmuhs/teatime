===========================================
Teatime - A Blockchain RPC Attack Framework
===========================================

.. image:: https://img.shields.io/pypi/v/teatime.svg
    :target: https://pypi.python.org/pypi/teatime

.. image:: https://img.shields.io/travis/dmuhs/teatime.svg
    :target: https://travis-ci.com/dmuhs/teatime

.. image:: https://codecov.io/gh/dmuhs/teatime/branch/master/graph/badge.svg?token=RP0WZ6NXUP
    :target: https://codecov.io/gh/dmuhs/teatime

.. image:: https://readthedocs.org/projects/teatime/badge/?version=latest
    :target: https://teatime.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://pyup.io/repos/github/dmuhs/teatime/shield.svg
    :target: https://pyup.io/repos/github/dmuhs/teatime/
    :alt: Updates


Deployed a node? Have a cup.
----------------------------

Teatime is an RPC attack framework aimed at making it easy to spot
misconfigurations in blockchain nodes. It detects a large variety of issues,
ranging from information leaks to open accounts, and configuration
manipulation.

The goal is to enable tools scanning for vulnerable nodes and minimizing
the risk of node-based attacks due to common vulnerabilities. Teatime uses
a plugin-based architecture, so extending the library with your own checks
is straightforward.

Please note that this library is still a PoC and lacks documentation. If there
are plugins you would like to see, feel free to contact me on Twitter!


Installation
------------
Teatime runs on Python 3.6+.

To get started, simply run

.. code-block:: console

    $ pip3 install teatime

Alternatively, clone the repository and run

.. code-block:: console

    $ pip3 install .

Or directly through Python's :code:`setuptools`:

.. code-block:: console

    $ python3 setup.py install


Example
-------

To get started, simply instantiate a :code:`Scanner` class and pass in the
target IP, port, node type, and a list of instantiated plugins. Consider the
following sample to check whether a node is synced and mining:

.. code-block:: python

    from teatime.scanner import Scanner
    from teatime.plugins.context import NodeType
    from teatime.plugins.eth1 import NodeSync, MiningStatus

    TARGET_IP = "127.0.0.1"
    TARGET_PORT = 8545
    INFURA_URL = "Infura API Endpoint"

    def get_scanner():
        return Scanner(
            ip=TARGET_IP,
            port=TARGET_PORT,
            node_type=NodeType.GETH,
            plugins=[
                NodeSync(infura_url=INFURA_URL, block_threshold=10),
                MiningStatus(should_mine=False)
            ]
        )

    if __name__ == '__main__':
        scanner = get_scanner()
        report = scanner.run()
        print(report.to_dict())


Check out the examples directory for more small samples! Teatime is fully
typed, so also feel free to explore options in your IDE if reading the
documentation is not your preferred choice. :)


Future Development
------------------

The future of Teatime is uncertain, even though I would love to add broader
checks that go beyond RPC interfaces, specifically for technologies such as:

- Ethereum 2.0
- Filecoin
- IPFS

If you want to integrate plugins for smaller, less meaningful chains such
as Bitcoin or Ethereum knock-offs, feel free to fork the project and integrate
them separately.
