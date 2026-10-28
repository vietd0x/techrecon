"""Scan engines — pluggable technology detection backends."""

from .httpx import HttpxEngine
from .nuclei import NucleiEngine
from .whatweb import WhatwebEngine
from .webanalyze import WebanalyzeEngine
from .katana import KatanaEngine
from .tlsx import TlsxEngine
from .favicon import FaviconEngine

ENGINES = {
    "httpx": HttpxEngine,
    "nuclei": NucleiEngine,
    "whatweb": WhatwebEngine,
    "webanalyze": WebanalyzeEngine,
    "katana": KatanaEngine,
    "tlsx": TlsxEngine,
    "favicon": FaviconEngine,
}


def get_engine(name: str):
    cls = ENGINES.get(name)
    if not cls:
        raise ValueError(f"Unknown engine: {name}. Available: {', '.join(ENGINES)}")
    return cls()
