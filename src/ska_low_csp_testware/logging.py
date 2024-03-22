"""
Module to help set up logging for TANGO devices.
"""

import functools
import logging

import ska_ser_logging
from tango.server import Device

__all__ = [
    "configure_logging",
    "get_logger",
]


class _EnsureTagsFilter(logging.Filter):  # pylint: disable=too-few-public-methods
    def filter(self, record: logging.LogRecord) -> bool | logging.LogRecord:
        if not hasattr(record, "tags"):
            record.tags = ""
        return True


class _AddDeviceNameTag(logging.Filter):  # pylint: disable=too-few-public-methods
    def __init__(self, device: Device, name: str = "") -> None:
        self._device = device
        super().__init__(name)

    @functools.cached_property
    def _device_name_tag(self) -> str:
        return f"tango-device:{self._device.get_name()}"

    def filter(self, record: logging.LogRecord) -> bool | logging.LogRecord:
        record.tags = self._device_name_tag
        return True


def configure_logging():
    """
    Configure the Python logging library with SKAO defaults.
    """
    ska_ser_logging.configure_logging(tags_filter=_EnsureTagsFilter)


def get_logger(device: Device, name: str | None = None) -> logging.Logger:
    """
    Creates a new Python logger for a TANGO device.
    """
    logger = logging.getLogger(name)
    logger.addFilter(_AddDeviceNameTag(device))
    return logger
