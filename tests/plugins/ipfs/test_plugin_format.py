import inspect
import sys

import pytest

import teatime.plugins.ipfs
from teatime import IPFSRPCPlugin

PLUGINS = [
    obj
    for name, obj in inspect.getmembers(sys.modules["teatime.plugins.ipfs"])
    if inspect.isclass(obj)
]


@pytest.mark.parametrize("plugin", PLUGINS)
def test_plugin_interface(plugin):
    assert issubclass(plugin, IPFSRPCPlugin)
    assert isinstance(plugin.INTRUSIVE, bool)
    assert getattr(plugin, "_check", None)
