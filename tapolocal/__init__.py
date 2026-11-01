"""Clientes para câmeras TP-Link Tapo, a partir da engenharia reversa do app Tapo."""

from .api import (
    ACCESS_KEY,
    LOCAL_QUERIES,
    TapoAuthError,
    TapoCloud,
    TapoCloudError,
    TapoCommandError,
    TapoLocal,
    TapoMFARequired,
    sign,
)
from .events import EVENT_TYPES, RECORD_TYPES

__all__ = [
    "ACCESS_KEY", "EVENT_TYPES", "LOCAL_QUERIES", "RECORD_TYPES", "TapoAuthError", "TapoCloud",
    "TapoCloudError", "TapoCommandError", "TapoLocal", "TapoMFARequired", "sign",
]
__version__ = "0.1.0"
