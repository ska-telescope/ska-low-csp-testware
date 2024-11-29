# pylint: disable=c-extension-no-member
"""
Module for the ``VisibilityReceiverDevice``.
"""

import logging
import subprocess
import threading
import time
from typing import cast

import netifaces
from tango import AttrQuality, AttrWriteType, DevState, EnsureOmniThread
from tango.server import Device, attribute, command, device_property

from ska_low_csp_testware.logging import configure_logging, get_logger


def _capture(interface: str, port: int, path: str):
    with EnsureOmniThread():
        process = subprocess.Popen(  # pylint: disable=consider-using-with
            ["tcpdump", "-i", interface, "-w", path, "udp", "port", str(port)],
            shell=True,
        )
        process.wait()


class VisibilityReceiverDevice(Device):
    """
    TANGO device that uses tcpdump to capture received visibilities.
    """

    output_dir: str = device_property()  # type: ignore
    interface: str = device_property()  # type: ignore
    port: int = device_property()  # type: ignore

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

        self.set_state(DevState.ON)
        self.set_status("Not capturing")
        self._logger.info("Device init complete")

    def delete_device(self) -> None:
        self._logger.info("Device deinit started")

        self._logger.info("Stopping background task executor")
        self._executor.shutdown(cancel_futures=True)

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
        if self.interface not in netifaces.interfaces():
            return "", time.time(), AttrQuality.ATTR_INVALID

        return (
            netifaces.ifaddresses(self.interface)[netifaces.IF_INET],
            time.time(),
            AttrQuality.ATTR_VALID,
        )

    def read_ip_address(self) -> tuple[str, float, AttrQuality]:
        """
        Read method for the ``ip_address`` device attribute.
        """
        if self.interface not in netifaces.interfaces():
            return "", time.time(), AttrQuality.ATTR_INVALID

        return (
            netifaces.ifaddresses(self.interface)[netifaces.IF_INET],
            time.time(),
            AttrQuality.ATTR_VALID,
        )

    @command
    def StartCapture(
        self, capture_file_name: str
    ):  # pylint: disable=invalid-name
        """
        Start a new capture.
        """
        self._logger.info("Start capturing to %s", capture_file_name)
        with self._lock:
            self._capture_thread = threading.Thread(
                target=_capture,
                args=[self.interface, self.port, capture_file_name],
                daemon=True,
            )
            self._capture_thread.start()
        self.set_status(f"Capturing {capture_file_name}")

    @command
    def StopCapture(self):  # pylint: disable=invalid-name
        """
        Stop a running capture.
        """
        self._logger.info("Stop capturing")
        with self._lock:
            if self._capture_thread is not None:
                self._capture_thread.join()
        self.set_status("Not capturing")


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
