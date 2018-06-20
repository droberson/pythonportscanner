"""
Secondary scans. This will import mod_*.py as secondary scan modules.
See README.md for more information or else!@#$
"""

import os

from .secondary import *

__all__ = []

def _import_secondary_scan_modules():
    globalz = globals()
    localz = locals()

    for modulefile in os.listdir(__name__):
        if modulefile.startswith("mod_") and modulefile.endswith(".py"):
            modulename = modulefile.split(".")[0]
            modulepackage = ".".join([__name__, modulename])

            module = __import__(modulepackage, globalz, localz, [modulename])

            for name in module.__dict__:
                if not name.startswith("_"):
                    globalz[name] = module.__dict__[name]
                    __all__.append(name)


_import_secondary_scan_modules()

