"""
Module for the ``PcapFile`` TANGO device.
"""

import asyncio
import io
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import numpy.typing as npt
import pandas as pd
import watchfiles
from ska_control_model import TestMode
from tango import AttrWriteType, DevState, GreenMode
from tango.server import Device, attribute, command, device_property

from ska_low_csp_testware.common_types import DataType
from ska_low_csp_testware.low_cbf_vis import read_visibilities

__all__ = [
    "PcapFile",
]

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"

module_logger = logging.getLogger(__name__)


def _encode_spead_headers(spead_headers: pd.DataFrame) -> str:
    return spead_headers.to_json()


def _encode_spead_data(spead_data: npt.NDArray) -> bytes:
    buffer = io.BytesIO()
    np.save(buffer, spead_data)
    return buffer.getvalue()


class PcapFile(Device):
    """
    TANGO device representing a PCAP file.
    """

    green_mode = GreenMode.Asyncio

    pcap_file_path: str = device_property(  # type: ignore
        doc="Absolute path on disk that points to a valid PCAP file",
    )

    test_mode: int = device_property(  # type: ignore
        default_value=TestMode.NONE,
    )

    data_type: DataType = attribute(  # type: ignore
        label="Data type",
        access=AttrWriteType.READ_WRITE,
    )

    file_size: int = attribute(  # type: ignore
        label="File size",
        unit="byte",
        standard_unit="byte",
        display_unit="byte",
    )

    file_modification_timestamp: float = attribute(  # type: ignore
        label="File modification Unix timestamp",
        unit="s",
        standard_unit="s",
        display_unit="s",
    )

    file_modification_datetime: str = attribute(  # type: ignore
        label="File modification date time",
    )

    def __init__(self, *args, **kwargs):
        self._logger = module_logger
        self._file_size = 0
        self._file_modification_datetime = datetime.fromtimestamp(0).strftime(DATETIME_FORMAT)
        self._file_modification_timestamp = 0.0
        self._data_type = DataType.NOT_CONFIGURED
        self._stop_event = asyncio.Event()
        self._background_tasks: set[asyncio.Task] = set()
        super().__init__(*args, **kwargs)

    async def init_device(self) -> None:  # pylint: disable=invalid-overridden-method
        await super().init_device()  # type: ignore

        self.set_state(DevState.INIT)

        for attr_name in [
            "file_size",
            "file_modification_datetime",
            "file_modification_timestamp",
        ]:
            self.set_change_event(attr_name, True, False)

        await self._start_monitoring_file()

        self.set_state(DevState.ON)

    async def delete_device(self) -> None:  # pylint: disable=invalid-overridden-method
        self._stop_event.set()
        await asyncio.gather(*self._background_tasks)
        await super().delete_device()  # type: ignore

    async def _start_monitoring_file(self) -> None:
        await self._update_file_attributes()

        task = asyncio.create_task(self._monitor_file())
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _monitor_file(self) -> None:
        async for changes in watchfiles.awatch(self.pcap_file_path, stop_event=self._stop_event):
            for change, _ in changes:
                match change:
                    case watchfiles.Change.modified:
                        await self._update_file_attributes()
                    case watchfiles.Change.deleted:
                        self.set_state(DevState.OFF)
                        return

    async def _update_file_attributes(self):
        path = Path(self.pcap_file_path)
        if not path.is_file():
            self._logger.warning("PCAP file does not exist (yet), skipping file attribute update")
            return

        file_info = path.stat()
        self._update_attribute("file_size", file_info.st_size)
        self._update_attribute("file_modification_timestamp", file_info.st_mtime)
        self._update_attribute(
            "file_modification_datetime", datetime.fromtimestamp(file_info.st_mtime).strftime(DATETIME_FORMAT)
        )

    def _update_attribute(self, attr_name: str, attr_value: Any) -> None:
        setattr(self, f"_{attr_name}", attr_value)
        self.push_change_event(attr_name, attr_value)

    def read_file_size(self) -> int:
        """
        Read method for the ``file_size`` device attribute.
        """
        return self._file_size

    def read_file_modification_datetime(self) -> str:
        """
        Read method for the ``file_modification_datetime`` device attribute.
        """
        return self._file_modification_datetime

    def read_file_modification_timestamp(self) -> float:
        """
        Read method for the ``file_modification_timestamp`` device attribute.
        """
        return self._file_modification_timestamp

    def read_data_type(self) -> DataType:
        """
        Read method for the ``data_type`` device attribute.
        """
        return self._data_type

    def write_data_type(self, data_type: DataType) -> None:
        """
        Write method for the ``data_type`` device attribute.
        """
        self._data_type = data_type

    @command
    async def DeleteFile(self) -> None:  # pylint: disable=invalid-name
        """
        Delete the PCAP file on disk.
        """
        Path(self.pcap_file_path).unlink()

    @command(
        dtype_out="DevEncoded",
        doc_out="Tuple containing the result code and corresponding message",
    )
    async def ReadFile(self) -> tuple[str, bytes]:  # pylint: disable=invalid-name
        """
        Read the SPEAD headers and SPEAD data contained in the PCAP file.

        :returns: A tuple containing the SPEAD headers and SPEAD data.
        """
        match self._data_type:
            case DataType.VIS:
                file_contents = await read_visibilities(Path(self.pcap_file_path), TestMode(self.test_mode))
            case DataType.NOT_CONFIGURED:
                raise ValueError("Data type not configured")
            case _:
                raise ValueError("Unsupported data type")

        return (
            _encode_spead_headers(file_contents.spead_headers),
            _encode_spead_data(file_contents.spead_data),
        )
