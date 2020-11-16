import inspect
import sys

import pytest

import teatime.plugins.eth1
from teatime import JSONRPCPlugin

PLUGINS = [
    obj
    for name, obj in inspect.getmembers(sys.modules["teatime.plugins.eth1"])
    if inspect.isclass(obj)
]


@pytest.mark.parametrize("plugin", PLUGINS)
def test_plugin_interface(plugin):
    assert issubclass(plugin, JSONRPCPlugin)
    assert isinstance(plugin.INTRUSIVE, bool)
    assert getattr(plugin, "_check", None)
