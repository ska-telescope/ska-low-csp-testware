# pylint: disable=c-extension-no-member
"""
Module for the ``VisibilityReceiverDevice``.
"""

import logging
import threading
import time
from typing import cast

import netifaces
from tango import AttrQuality, AttrWriteType, DevState
from tango.server import Device, attribute, device_property

from ska_low_csp_testware.logging import configure_logging, get_logger

__all__ = ["VisibilityReceiverDevice", "main"]


class VisibilityReceiverDevice(Device):
    """
    TANGO device that uses tcpdump to capture received visibilities.
    """

    output_dir: str = device_property(  # type: ignore
        default_value="/tmp",
        doc="Path to the directory where the captured files are stored.",
    )

    interface: str = device_property(  # type: ignore
        mandatory=True,
        doc="Network interface to listen on.",
    )

    port: int = device_property(  # type: ignore
        default_value=9999,
        doc="Port to listen on",
    )

    logging_level: str = attribute(  # type: ignore
        access=AttrWriteType.READ_WRITE,
        doc="Attribute that controls the logging level for this device.",
    )

    mac_address: str = attribute(  # type: ignore
        access=AttrWriteType.READ,
        doc="MAC address the receiver is listening on.",
    )

    ip_address: str = attribute(  # type: ignore
        access=AttrWriteType.READ,
        doc="IP address the receiver is listening on.",
    )

    def __init__(self, *args, **kwargs):
        self._logger = get_logger(self, __name__)
        self._lock = threading.Lock()
        self._capture_thread: threading.Thread | None = None

        super().__init__(*args, **kwargs)

    def init_device(self):
        super().init_device()
        self.set_state(DevState.INIT)
        self._logger.info("Device init started")

        all_interfaces = netifaces.interfaces()
        if self.interface not in all_interfaces:
            self.set_state(DevState.FAULT)
            status = (
                f"Unknown network interface '{self.interface}', "
                f"available interfaces: %{', '.join(all_interfaces)}"
            )
            self.set_status(status)
            self._logger.error(status)
            return

        self.set_state(DevState.ON)
        self.set_status("Not capturing")
        self._logger.info("Device init complete")

    def delete_device(self) -> None:
        self._logger.info("Device deinit started")

        self._logger.info("Device deinit completed")
        super().delete_device()

    def read_logging_level(self) -> str:
        """
        Read method for the ``logging_level`` device attribute.
        """
        return logging.getLevelName(self._logger.level)

    def write_logging_level(self, logging_level: str) -> None:
        """
        Write method for the ``logging_level`` device attribute.

        :param logging_level: Python logging level, such as "INFO", "DEBUG".
        """
        self._logger.setLevel(logging_level)
        self._logger.log(
            getattr(logging, logging_level),
            "Logging level set to %s",
            logging_level,
        )

    def read_mac_address(self) -> tuple[str, float, AttrQuality]:
        """
        Read method for the ``mac_address`` device attribute.
        """
        if self.dev_state() != DevState.ON:
            return "", time.time(), AttrQuality.ATTR_INVALID

        return (
            netifaces.ifaddresses(self.interface)[netifaces.IF_LINK],
            time.time(),
            AttrQuality.ATTR_VALID,
        )

    def read_ip_address(self) -> tuple[str, float, AttrQuality]:
        """
        Read method for the ``ip_address`` device attribute.
        """
        if self.dev_state() != DevState.ON:
            return "", time.time(), AttrQuality.ATTR_INVALID

        return (
            netifaces.ifaddresses(self.interface)[netifaces.IF_INET],
            time.time(),
            AttrQuality.ATTR_VALID,
        )


def main(*args: str, **kwargs: str) -> int:
    """
    Entry point for module.

    :param args: positional arguments
    :param kwargs: named arguments

    :return: exit code
    """
    configure_logging()
    return cast(
        int, VisibilityReceiverDevice.run_server(args=args or None, **kwargs)
    )


if __name__ == "__main__":
    main()
