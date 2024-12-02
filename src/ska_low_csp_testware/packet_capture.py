# pylint: disable=c-extension-no-member
"""
Module for the ``PacketCapture``.
"""

import logging
import os
import threading
import time
from typing import cast

import netifaces
import pyshark
from tango import AttrQuality, AttrWriteType, DevState
from tango.server import Device, attribute, command, device_property

from ska_low_csp_testware.logging import configure_logging, get_logger

__all__ = ["PacketCapture", "main"]


class PacketCapture(Device):
    """
    TANGO device that uses tshark to capture network packets.
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

    def __init__(self, *args, **kwargs):
        self._logger = get_logger(self, __name__)
        self._lock = threading.Lock()
        self._cancel = threading.Event()
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

        if self._capture_thread is not None:
            self._logger.debug("Cancelling active capture thread")
            self._cancel.set()
            self._capture_thread.join()
            self._logger.debug("Capture thread cancelled")

        self._cancel.clear()
        self._capture_thread = None

        self._logger.info("Device deinit completed")
        super().delete_device()

    logging_level: str = attribute(  # type: ignore
        access=AttrWriteType.READ_WRITE,
        doc="Attribute that controls the logging level for this device.",
    )

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

    @attribute
    def mac_address(self) -> tuple[str, float, AttrQuality]:
        """
        The MAC address of the interface the device is listening on.
        """
        if self.dev_state() != DevState.ON:
            return "", time.time(), AttrQuality.ATTR_INVALID

        addresses = netifaces.ifaddresses(self.interface)
        return (
            addresses[netifaces.AF_LINK][0]["addr"],
            time.time(),
            AttrQuality.ATTR_VALID,
        )

    @attribute
    def ip_address(self) -> tuple[str, float, AttrQuality]:
        """
        The IP address of the interface the device is listening on.
        """
        if self.dev_state() != DevState.ON:
            return "", time.time(), AttrQuality.ATTR_INVALID

        addresses = netifaces.ifaddresses(self.interface)
        return (
            addresses[netifaces.AF_INET][0]["addr"],
            time.time(),
            AttrQuality.ATTR_VALID,
        )

    @command
    def StartCapture(  # pylint: disable=invalid-name
        self,
        output_file_name: str,
    ):
        """
        Handler for the ``StartCapture`` TANGO command.
        """
        self._cancel.clear()
        self._capture_thread = threading.Thread(
            target=self._capture,
            args=(output_file_name),
        )
        self._logger.debug("Starting capture thread")
        self._capture_thread.start()
        self._logger.debug("Capture thread started")

    @command
    def StopCapture(self):  # pylint: disable=invalid-name
        """
        Handler for the ``StopCapture`` TANGO command.
        """
        if self._capture_thread is not None:
            self._logger.debug("Stopping capture thread")
            self._cancel.set()
            self._capture_thread.join()
            self._logger.debug("Capture thread stopped")

        self._cancel.clear()
        self._capture_thread = None

    def _capture(self, output_file_name: str):
        capture = pyshark.LiveCapture(
            interface=self.interface,
            output_file=os.path.join(self.output_dir, output_file_name),
            only_summaries=True,
        )

        self._logger.debug("Starting capture")

        for packet in capture.sniff_continuously():
            self._logger.debug("Received packet: %s", packet)

            if self._cancel.is_set():
                self._logger.debug("Stopping capture")
                capture.close()
                break


def main(*args: str, **kwargs: str) -> int:
    """
    Entry point for module.

    :param args: positional arguments
    :param kwargs: named arguments

    :return: exit code
    """
    configure_logging()
    return cast(
        int,
        PacketCapture.run_server(args=args or None, **kwargs),
    )


if __name__ == "__main__":
    main()
