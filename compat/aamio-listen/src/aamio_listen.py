"""aamio_listen, kept working after the package was renamed to aamio.

Every name that used to be importable from here is re-exported from aamio, so
code written before the rename keeps running. Nothing is implemented twice:
this is one line of indirection and a module that says where it went.

    import aamio_listen          ->  aamio
    from aamio_listen import X   ->  from aamio import X

The command line is unaffected either way: installing aamio gives you both the
aamio and the aamio-listen commands.
"""

import sys as _sys

import aamio as _aamio

__all__ = getattr(_aamio, "__all__", [name for name in dir(_aamio) if not name.startswith("_")])
__version__ = _aamio.__version__
__doc_of_aamio__ = _aamio.__doc__

# Submodules too, so `from aamio_listen.runtime import Runtime` resolves to the
# one object rather than to a second copy of it.
for _name in ("cli", "client", "crypto", "mcp_server", "runtime"):
    try:
        _module = __import__("aamio." + _name, fromlist=[_name])
    except ImportError:  # a trimmed install; nothing to forward
        continue

    _sys.modules[__name__ + "." + _name] = _module
    globals()[_name] = _module


def __getattr__(name):
    return getattr(_aamio, name)
