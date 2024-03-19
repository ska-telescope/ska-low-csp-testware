"""
Module for the ``PcapFile`` TANGO device.
"""

import asyncio
import io
import os
from pathlib import Path
from typing import Any

import numpy as np
import numpy.typing as npt
import pandas as pd
import watchfiles
from ska_control_model import TestMode
from tango import DevState, GreenMode
from tango.server import Device, attribute, command, device_property

from ska_low_csp_testware.common_types import DataType
from ska_low_csp_testware.low_cbf_vis import read_visibilities

__all__ = [
    "PcapFile",
]


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

    def __init__(self, *args, **kwargs):
        self._file_size = 0
        self._file_time_modified = 0
        self._stop_event = asyncio.Event()
        self._background_tasks: set[asyncio.Task] = set()
        super().__init__(*args, **kwargs)

    async def init_device(self) -> None:  # pylint: disable=invalid-overridden-method
        await super().init_device()  # type: ignore
        self.set_state(DevState.INIT)
        for attr_name in [
            "file_size",
            "file_time_modified",
        ]:
            self.set_change_event(attr_name, True, False)
        await self._update_file_attributes()
        watch_task = asyncio.create_task(self._watch_file())
        self._background_tasks.add(watch_task)
        watch_task.add_done_callback(self._background_tasks.discard)
        self.set_state(DevState.ON)

    async def delete_device(self) -> None:  # pylint: disable=invalid-overridden-method
        self._stop_event.set()
        await asyncio.gather(*self._background_tasks)
        await super().delete_device()  # type: ignore

    async def _watch_file(self) -> None:
        async for changes in watchfiles.awatch(self.pcap_file_path, stop_event=self._stop_event):
            for change, _ in changes:
                match change:
                    case watchfiles.Change.modified:
                        await self._update_file_attributes()
                    case watchfiles.Change.deleted:
                        self.set_state(DevState.OFF)
                        return

    async def _update_file_attributes(self):
        file_info = os.stat(self.pcap_file_path)
        self._update_attribute("file_size", file_info.st_size)
        self._update_attribute("file_time_modified", file_info.st_mtime_ns)

    def _update_attribute(self, attr_name: str, attr_value: Any) -> None:
        setattr(self, f"_{attr_name}", attr_value)
        self.push_change_event(attr_name, attr_value)

    @attribute(
        label="File size",
        unit="byte",
        standard_unit="byte",
        display_unit="byte",
    )
    def file_size(self) -> int:
        """
        The size of the PCAP file.

        :returns: File size in bytes.
        """
        return self._file_size

    @attribute(
        label="File modification time",
        unit="ns",
        standard_unit="s",
        display_unit="ns",
    )
    def file_time_modified(self) -> int:
        """
        The last modification time of the PCAP file.

        :returns: Unix timestamp in nanoseconds.
        """
        return self._file_time_modified

    @command
    async def DeleteFile(self) -> None:  # pylint: disable=invalid-name
        """
        Delete the PCAP file on disk.
        """
        Path(self.pcap_file_path).unlink()

    @command(
        doc_in="The type of data contained in the PCAP file",
        dtype_out="DevEncoded",
        doc_out="Tuple containing the result code and corresponding message",
    )
    async def ReadFile(self, data_type: DataType) -> tuple[str, bytes]:  # pylint: disable=invalid-name
        """
        Read the file contents.

        This reads the SPEAD headers and SPEAD data contained in the PCAP file.

        :param data_type: The type of data contained in the PCAP file.
        :returns: A tuple containing the SPEAD headers and SPEAD data.
        """
        match data_type:
            case DataType.VIS:
                file_contents = await read_visibilities(Path(self.pcap_file_path), TestMode(self.test_mode))
            case _:
                raise ValueError("Unsupported data type")

        return self._encode_spead_headers(file_contents.spead_headers), self._encode_spead_data(file_contents.spead_data)

    def _encode_spead_headers(self, spead_headers: pd.DataFrame) -> str:
        return spead_headers.to_json()

    def _encode_spead_data(self, spead_data: npt.NDArray) -> bytes:
        buffer = io.BytesIO()
        np.save(buffer, spead_data)
        return buffer.getvalue()
