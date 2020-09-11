===========================================
Teatime - A Blockchain RPC Attack Framework
===========================================

.. image:: https://img.shields.io/pypi/v/teatime.svg
        :target: https://pypi.python.org/pypi/teatime

.. image:: https://img.shields.io/travis/dmuhs/teatime.svg
        :target: https://travis-ci.com/dmuhs/teatime

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
Teatime runs on Python 3.6+ and PyPy3.

To get started, simply run

.. code-block:: console

    $ pip3 install teatime

Alternatively, clone the repository and run

.. code-block:: console

    $ pip3 install .

Or directly through Python's :code:`setuptools`:

.. code-block:: console

    $ python3 setup.py install


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
