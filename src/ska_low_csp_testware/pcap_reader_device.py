"""
Module for the ``PcapReader`` TANGO device.
"""

import io
import json
import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from functools import partial
from pathlib import Path

import numpy as np
import numpy.typing as npt
import pandas as pd
from ska_control_model import TestMode
from tango import AttrQuality, AttrWriteType, DevState, DispLevel
from tango.server import Device, attribute, command, device_property, run
from watchdog.events import (
    EVENT_TYPE_CREATED,
    EVENT_TYPE_DELETED,
    EVENT_TYPE_MODIFIED,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from ska_low_csp_testware.common_types import PcapFileContents
from ska_low_csp_testware.logging import configure_logging, get_logger
from ska_low_csp_testware.low_cbf_vis import read_visibilities

__all__ = ["PcapReader", "main"]


def _is_monitored_file(path: Path):
    return path.suffix == ".pcap"


def _encode_dataframe(df: pd.DataFrame) -> bytes:
    buffer = io.BytesIO()
    df.to_pickle(buffer)
    return buffer.getvalue()


def _encode_ndarray(array: npt.NDArray) -> bytes:
    buffer = io.BytesIO()
    np.save(buffer, array)
    return buffer.getvalue()


class PcapReader(Device, FileSystemEventHandler):
    """
    TANGO device that monitors a directory for PCAP files.
    """

    pcap_dir: str = device_property(  # type: ignore
        doc="Absolute path on disk that points to a directory containing PCAP files",
        mandatory=True,
    )

    test_mode: int = device_property(  # type: ignore
        default_value=TestMode.NONE,
        doc=(
            "Test mode can be used to interact with the device in environments "
            "where actually reading PCAP file contents is not possible"
        ),
    )

    files = attribute(
        doc="Attribute exposing file information for all monitored PCAP files.",
        dtype=str,
        label="PCAP files",
    )

    logging_level: str = attribute(  # type: ignore
        access=AttrWriteType.READ_WRITE,
        doc="Attribute that controls the logging level for this device.",
        label="Logging level",
    )

    spead_headers = attribute(
        display_level=DispLevel.EXPERT,
        doc=(
            "Attribute to which SPEAD headers are published. "
            "This attribute can't be read directly as the value depends on which file is read. "
            "Users must subscribe to USER_EVENT events instead."
        ),
        dtype="DevEncoded",
        label="SPEAD headers",
    )

    spead_data = attribute(
        display_level=DispLevel.EXPERT,
        doc=(
            "Attribute to which SPEAD data is published. "
            "This attribute can't be read directly as the value depends on which file is read. "
            "Users must subscribe to USER_EVENT events instead."
        ),
        dtype="DevEncoded",
        label="SPEAD data",
    )

    def __init__(self, *args, **kwargs):
        self._logger = get_logger(self, __name__)
        self._lock = threading.Lock()
        self._observer = Observer()
        self._executor = ThreadPoolExecutor()

        self._files = {}

        super().__init__(*args, **kwargs)

    @property
    def pcap_dir_path(self) -> Path:
        """
        Property wrapper for the ``pcap_dir`` device property.
        """
        return Path(self.pcap_dir)

    def init_device(self) -> None:
        super().init_device()

        self.set_state(DevState.INIT)
        self._logger.info("Device init started")

        for attribute_name in ["files"]:
            self.set_change_event(attribute_name, True, False)

        self._logger.info("Updating state to match monitored directory state")
        for file in self.pcap_dir_path.rglob("*.pcap"):
            self._update_file(file)

        if self._observer.is_alive():
            self._logger.debug("File observer already running, no need to start it again")
        else:
            self._logger.info("Starting file observer")
            self._observer.schedule(self, self.pcap_dir_path, recursive=True)
            self._observer.start()

        self.set_state(DevState.ON)
        self._logger.info("Device init completed")

    def delete_device(self) -> None:
        self._logger.info("Device deinit started")

        if self._observer.is_alive():
            self._logger.info("Stopping file observer")
            self._observer.stop()
            self._observer.join()
        else:
            self._logger.debug("File observer not running, no need to stop it")

        self._logger.info("Stopping background task executor")
        self._executor.shutdown(cancel_futures=True)

        self._logger.info("Device deinit completed")
        super().delete_device()

    def _update_file(self, file: Path) -> None:
        file_name = str(file.relative_to(self.pcap_dir_path))
        self._logger.info("Updating file %s", file_name)

        file_info = file.stat()

        with self._lock:
            self._files[file_name] = {
                "size": file_info.st_size,
                "mtime": file_info.st_mtime,
            }
            self.push_change_event("files", json.dumps(self._files))

    def _remove_file(self, file: Path) -> None:
        file_name = str(file.relative_to(self.pcap_dir_path))
        self._logger.info("Removing file %s", file_name)

        with self._lock:
            if file_name in self._files:
                del self._files[file_name]
                self.push_change_event("files", json.dumps(self._files))

    def on_any_event(self, event: FileSystemEvent) -> None:
        file = Path(event.src_path)
        if _is_monitored_file(file):
            self._logger.debug("Received %s event for file %s", event.event_type, file)

            if event.event_type in {EVENT_TYPE_CREATED, EVENT_TYPE_MODIFIED}:
                self._update_file(file)
            elif event.event_type == EVENT_TYPE_DELETED:
                self._remove_file(file)

    def read_files(self) -> str:
        """
        Read method for the ``files`` device attribute.
        """
        return json.dumps(self._files)

    def read_logging_level(self) -> str:
        """
        Read method for the ``logging_level`` device attribute.
        """
        return logging.getLevelName(self._logger.level)

    def write_logging_level(self, logging_level: str) -> None:
        """
        Write method for the ``logging_level`` device attribute.

        :param logging_level: Python logging level, such as "INFO", "DEBUG" etc.
        """
        self._logger.setLevel(logging_level)
        self._logger.info("Logging level set to %s", logging_level)

    def read_spead_headers(self) -> tuple[str, bytes, float, AttrQuality]:
        """
        Read method for the ``spead_headers`` device attribute.
        """
        return (
            "",
            bytes(),
            time.time(),
            AttrQuality.ATTR_INVALID,
        )

    def read_spead_data(self) -> tuple[str, bytes, float, AttrQuality]:
        """
        Read method for the ``spead_data`` device attribute.
        """
        return (
            "",
            bytes(),
            time.time(),
            AttrQuality.ATTR_INVALID,
        )

    @command
    def RemoveFile(self, file_name: str) -> None:  # pylint: disable=invalid-name
        """
        Remove the specified file from the file system.
        """
        with self._lock:
            if file_name not in self._files:
                raise ValueError("Unknown file")

        self._logger.info("Removing file %s", file_name)
        self.pcap_dir_path.joinpath(file_name).unlink(missing_ok=True)

    @command
    def ReadVisibilityData(self, file_name: str) -> None:  # pylint: disable=invalid-name
        """
        Read visibility data from the specified file.
        """
        with self._lock:
            if file_name not in self._files:
                raise ValueError("Unknown file")

        self._logger.info("Reading visibility data from file %s", file_name)
        future = self._executor.submit(
            read_visibilities,
            self.pcap_dir_path.joinpath(file_name),
            test_mode=TestMode(self.test_mode),
            logger=self._logger,
        )
        future.add_done_callback(partial(self._on_visibility_data, file_name))

    def _on_visibility_data(self, file_name: str, data: Future[PcapFileContents]) -> None:
        def _push_event(attr_name: str, data: bytes):
            self._logger.debug("Pushing user event for attribute %s and file %s", attr_name, file_name)
            self.push_event(
                attr_name,
                [],
                [],
                file_name,
                data,
                time.time(),
                AttrQuality.ATTR_VALID,
            )

        if e := data.exception():
            self._logger.warning("Failed reading visibility data from file %s: %s", file_name, e)
            return

        self._logger.info("Finished reading visibility data from file %s", file_name)
        file_contents = data.result()
        _push_event("spead_headers", _encode_dataframe(file_contents.spead_headers))
        _push_event("spead_data", _encode_ndarray(file_contents.spead_data))


def main(args=None, **kwargs):  # pylint: disable=missing-function-docstring
    configure_logging()
    return run((PcapReader,), args=args, **kwargs)


if __name__ == "__main__":
    main()
