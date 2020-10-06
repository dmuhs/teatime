import sys
import teatime.plugins.eth1
import inspect
from teatime import Plugin
import pytest


PLUGINS = [
    obj
    for name, obj
    in inspect.getmembers(
        sys.modules['teatime.plugins.eth1']
    ) if inspect.isclass(obj)
]


@pytest.mark.parametrize("plugin", PLUGINS)
def test_plugin_interface(plugin):
    assert issubclass(plugin, Plugin)
    assert isinstance(plugin.INTRUSIVE, bool)
    assert getattr(plugin, "_check", None)
