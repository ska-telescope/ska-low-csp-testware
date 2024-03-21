"""
Module for the ``PcapReader`` TANGO device.
"""

import io
import json
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from functools import partial
from pathlib import Path

import numpy as np
import numpy.typing as npt
import pandas as pd
from ska_control_model import TestMode
from tango import AttrQuality, DevState, DispLevel
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
    )

    files = attribute(
        dtype=str,
        label="PCAP files",
    )

    spead_headers = attribute(
        display_level=DispLevel.EXPERT,
        dtype="DevEncoded",
    )

    spead_data = attribute(
        display_level=DispLevel.EXPERT,
        dtype="DevEncoded",
    )

    def __init__(self, *args, **kwargs):
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
        self.debug_stream("Device init started")

        self.set_state(DevState.INIT)

        for attribute_name in ["files"]:
            self.set_change_event(attribute_name, True, False)

        self._process_existing_files()
        self._observer.schedule(self, self.pcap_dir_path, recursive=True)
        self._observer.start()

        self.set_state(DevState.ON)
        self.debug_stream("Device init completed")

    def delete_device(self) -> None:
        self.debug_stream("Device deinit started")
        self._observer.stop()
        self._observer.join()
        self._executor.shutdown(cancel_futures=True)
        self.debug_stream("Device deinit completed")

        super().delete_device()

    def _process_existing_files(self) -> None:
        for file in self.pcap_dir_path.rglob("*.pcap"):
            self._update_file(file)

    def _update_file(self, file: Path) -> None:
        file_name = str(file.relative_to(self.pcap_dir_path))
        self.info_stream("Updating file %s", file_name)

        file_info = file.stat()

        with self._lock:
            self._files[file_name] = {
                "size": file_info.st_size,
                "mtime": file_info.st_mtime,
            }
            self.push_change_event("files", json.dumps(self._files))

    def _remove_file(self, file: Path) -> None:
        file_name = str(file.relative_to(self.pcap_dir_path))
        self.info_stream("Removing file %s", file_name)

        with self._lock:
            if file_name in self._files:
                del self._files[file_name]
                self.push_change_event("files", json.dumps(self._files))

    def on_any_event(self, event: FileSystemEvent) -> None:
        file = Path(event.src_path)
        if _is_monitored_file(file):
            if event.event_type in {EVENT_TYPE_CREATED, EVENT_TYPE_MODIFIED}:
                self._update_file(file)
            elif event.event_type == EVENT_TYPE_DELETED:
                self._remove_file(file)

    def read_files(self) -> str:
        """
        Read method for the ``files`` device attribute.
        """
        return json.dumps(self._files)

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

        self.info_stream("Removing file %s", file_name)
        self.pcap_dir_path.joinpath(file_name).unlink(missing_ok=True)

    @command
    def ReadVisibilityData(self, file_name: str) -> None:  # pylint: disable=invalid-name
        """
        Read visibility data from the specified file.
        """
        with self._lock:
            if file_name not in self._files:
                raise ValueError("Unknown file")

        self.info_stream("Reading visibility data from file %s", file_name)
        future = self._executor.submit(
            read_visibilities,
            self.pcap_dir_path.joinpath(file_name),
            test_mode=TestMode(self.test_mode),
        )
        future.add_done_callback(partial(self._on_visibility_data, file_name))

    def _on_visibility_data(self, file_name: str, data: Future[PcapFileContents]) -> None:
        def _push_event(attr_name: str, data: bytes):
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
            self.warn_stream("Failed reading visibility data: %s", e)
            return

        file_contents = data.result()
        _push_event("spead_headers", _encode_dataframe(file_contents.spead_headers))
        _push_event("spead_data", _encode_ndarray(file_contents.spead_data))


def main(args=None, **kwargs):  # pylint: disable=missing-function-docstring
    return run((PcapReader,), args=args, **kwargs)


if __name__ == "__main__":
    main()
