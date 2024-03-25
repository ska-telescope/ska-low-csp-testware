"""
Module for the ``PcapReader`` TANGO device.
"""

import base64
import hashlib
import io
import json
import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from functools import partial
from pathlib import Path
from typing import Any

import numpy as np
import numpy.typing as npt
import pandas as pd
from ska_control_model import TestMode
from tango import AttrQuality, AttrWriteType, DevFailed, DevState
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


def _encode_dataframe(df: pd.DataFrame) -> bytes:
    buffer = io.BytesIO()
    df.to_pickle(buffer)
    return buffer.getvalue()


def _encode_ndarray(array: npt.NDArray) -> bytes:
    buffer = io.BytesIO()
    np.save(buffer, array)
    return buffer.getvalue()


class CustomJsonEncoder(json.JSONEncoder):
    """
    Custom JSON encoder that allows encoding of ``bytes``.
    """

    def default(self, o: Any) -> Any:
        if isinstance(o, bytes):
            return base64.b64encode(o).decode("ascii")
        return super().encode(o)


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

    file_name_mapping = attribute(
        doc="Attribute exposing file information for all monitored PCAP files.",
        dtype=str,
        label="PCAP files",
    )

    logging_level: str = attribute(  # type: ignore
        access=AttrWriteType.READ_WRITE,
        doc="Attribute that controls the logging level for this device.",
        label="Logging level",
    )

    def __init__(self, *args, **kwargs):
        self._logger = get_logger(self, __name__)
        self._lock = threading.Lock()
        self._observer = Observer()
        self._executor = ThreadPoolExecutor()

        self._file_name_mapping = {}
        self._dynamic_attr_data = {}

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

        for attribute_name in ["file_name_mapping"]:
            self.set_change_event(attribute_name, True, False)

        self._logger.info("Updating state to match monitored directory state")
        for file_path in self.pcap_dir_path.rglob("*.pcap"):
            file_name = str(file_path.relative_to(self.pcap_dir_path))
            self._sync_file_present(file_name)
            self._update_file_info(file_name)

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

    def read_file_name_mapping(self) -> str:
        """
        Read method for the ``file_name_mapping`` device attribute.
        """
        return json.dumps(self._file_name_mapping)

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
        self._logger.log(getattr(logging, logging_level), "Logging level set to %s", logging_level)

    def read_dynamic_attr(self, attr) -> tuple[str, float, AttrQuality]:
        """
        Read method for the dynamic attributes.
        """
        attr_name = attr.get_name()
        with self._lock:
            if attr_name in self._dynamic_attr_data:
                return self._dynamic_attr_data[attr_name], time.time(), AttrQuality.ATTR_VALID

        return "", time.time(), AttrQuality.ATTR_INVALID

    @command
    def RemoveFile(self, file_name: str) -> None:  # pylint: disable=invalid-name
        """
        Remove the specified file from the file system.
        """
        with self._lock:
            if file_name not in self._file_name_mapping:
                raise ValueError("Unknown file")

        self._logger.info("Removing file %s", file_name)
        self.pcap_dir_path.joinpath(file_name).unlink(missing_ok=True)

    @command
    def ReadVisibilityData(self, file_name: str) -> None:  # pylint: disable=invalid-name
        """
        Read visibility data from the specified file.
        """
        with self._lock:
            if file_name not in self._file_name_mapping:
                raise ValueError("Unknown file")

        attr_prefix = self._file_name_mapping[file_name]

        self._logger.info("Reading visibility data from file %s", file_name)
        future = self._executor.submit(
            read_visibilities,
            self.pcap_dir_path.joinpath(file_name),
            test_mode=TestMode(self.test_mode),
            logger=self._logger,
        )
        future.add_done_callback(partial(self._on_visibility_data, file_name, f"{attr_prefix}_data"))

    def on_any_event(self, event: FileSystemEvent) -> None:
        file_name = str(Path(event.src_path).relative_to(self.pcap_dir_path))
        if not file_name.endswith(".pcap"):
            return

        self._logger.debug("Received %s event for file %s", event.event_type, file_name)
        if event.event_type == EVENT_TYPE_CREATED:
            self._sync_file_present(file_name)
            self._update_file_info(file_name)
        elif event.event_type == EVENT_TYPE_MODIFIED:
            self._update_file_info(file_name)
        elif event.event_type == EVENT_TYPE_DELETED:
            self._sync_file_absent(file_name)

    def _sync_file_present(self, file_name: str) -> None:
        with self._lock:
            if file_name in self._file_name_mapping:
                attr_prefix = self._file_name_mapping[file_name]
            else:
                attr_prefix = self._attr_key(file_name)
                self._file_name_mapping[file_name] = attr_prefix
                self.push_change_event("file_name_mapping", json.dumps(self._file_name_mapping))

        for attr_suffix in ["data", "info"]:
            attr_name = f"{attr_prefix}_{attr_suffix}"
            if self._attr_exists(attr_name):
                continue

            self._logger.debug("Creating dynamic attribute %s", attr_name)
            attr = attribute(
                name=attr_name,
                dtype=str,
                fget=self.read_dynamic_attr,
                label=f"{file_name} - {attr_suffix}",
            )
            self.add_attribute(attr)
            self.set_change_event(attr_name, True, False)

    def _sync_file_absent(self, file_name: str) -> None:
        with self._lock:
            if file_name not in self._file_name_mapping:
                return

            attr_prefix = self._file_name_mapping[file_name]
            del self._file_name_mapping[file_name]
            self.push_change_event("file_name_mapping", json.dumps(self._file_name_mapping))

            for attr_suffix in ["data", "info"]:
                attr_name = f"{attr_prefix}_{attr_suffix}"
                if not self._attr_exists(attr_name):
                    continue

                self._logger.debug("Removing dynamic attribute %s", attr_name)
                self.remove_attribute(attr_name)
                if attr_name in self._dynamic_attr_data:
                    del self._dynamic_attr_data[attr_name]

    def _update_file_info(self, file_name: str) -> None:
        self._logger.debug("Updating file info %s", file_name)

        file_info = self.pcap_dir_path.joinpath(file_name).stat()

        with self._lock:
            attr_name = f"{self._file_name_mapping[file_name]}_info"
            attr_value = json.dumps(
                {
                    "size": file_info.st_size,
                    "mtime": file_info.st_mtime,
                }
            )
            self._dynamic_attr_data[attr_name] = attr_value
            self.push_change_event(attr_name, attr_value)

    def _attr_key(self, file_name: str) -> str:
        return hashlib.sha1(file_name.encode(), usedforsecurity=False).hexdigest()

    def _on_visibility_data(self, file_name: str, attr_name: str, data: Future[PcapFileContents]) -> None:
        if e := data.exception():
            self._logger.warning("Failed reading visibility data from file %s: %s", file_name, e)
            return

        self._logger.info("Finished reading visibility data from file %s", file_name)
        file_contents = data.result()
        attr_value = json.dumps(
            {
                "headers": _encode_dataframe(file_contents.spead_headers),
                "averaged_data": _encode_ndarray(file_contents.spead_data),
            },
            cls=CustomJsonEncoder,
        )

        self.push_change_event(attr_name, attr_value, time.time(), AttrQuality.ATTR_VALID)

        with self._lock:
            self._dynamic_attr_data[attr_name] = attr_value

    def _attr_exists(self, attr_name: str) -> bool:
        try:
            self.get_attribute_config([attr_name])
            return True
        except DevFailed:
            return False


def main(args=None, **kwargs):  # pylint: disable=missing-function-docstring
    configure_logging()
    return run((PcapReader,), args=args, **kwargs)


if __name__ == "__main__":
    main()
