"""
Module to set up logging for TANGO devices.

This module is loosely based on ``ska_tango_base.base.logging``.
"""

import enum
import logging

import tango

__all__ = ["TangoLoggingServiceHandler"]


class _Log4TangoLoggingLevel(enum.IntEnum):
    """
    Python enumerated type for Tango log4tango logging levels.

    This is different to tango.LogLevel, and is required if using
    a device's set_log_level() method.  It is not currently exported
    via PyTango, so we hard code it here in the interim.

    Source:
       https://gitlab.com/tango-controls/cppTango/blob/
       4feffd7c8e24b51c9597a40b9ef9982dd6e99cdf/log4tango/include/log4tango/Level.hh
       #L86-93
    """

    OFF = 100
    FATAL = 200
    ERROR = 300
    WARN = 400
    INFO = 500
    DEBUG = 600


_PYTHON_TO_TANGO_LOGGING_LEVEL = {
    logging.CRITICAL: _Log4TangoLoggingLevel.FATAL,
    logging.ERROR: _Log4TangoLoggingLevel.ERROR,
    logging.WARNING: _Log4TangoLoggingLevel.WARN,
    logging.INFO: _Log4TangoLoggingLevel.INFO,
    logging.DEBUG: _Log4TangoLoggingLevel.DEBUG,
}


class TangoLoggingServiceHandler(logging.Handler):
    """
    Logging handler that forwards logs to the Tango Logging Service.
    """

    def __init__(self, tango_logger: tango.Logger) -> None:
        super().__init__()
        self.tango_logger = tango_logger

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            tango_level = _PYTHON_TO_TANGO_LOGGING_LEVEL[record.levelno]
            self.acquire()
            try:
                self.tango_logger.log(tango_level, msg)
            finally:
                self.release()
        except Exception:  # pylint: disable=broad-except
            self.handleError(record)
