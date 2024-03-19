"""
Module for the ``PcapReader`` TANGO device.
"""

import asyncio
import io
import json
from pathlib import Path

import numpy as np
import numpy.typing as npt
import pandas as pd
import watchfiles
from ska_control_model import TestMode
from tango import DevState, GreenMode
from tango.server import Device, attribute, command, device_property, run

from ska_low_csp_testware.low_cbf_vis import read_visibilities

__all__ = ["PcapReader", "main"]


def _is_monitored_file(path: Path):
    return path.suffix == ".pcap"


def _monitor_filter(change: watchfiles.Change, path: str):  # pylint: disable=unused-argument
    return _is_monitored_file(Path(path))


def _encode_spead_headers(spead_headers: pd.DataFrame) -> str:
    return spead_headers.to_json()


def _encode_spead_data(spead_data: npt.NDArray) -> bytes:
    buffer = io.BytesIO()
    np.save(buffer, spead_data)
    return buffer.getvalue()


class PcapReader(Device):
    """
    TANGO device that monitors a directory for PCAP files.
    """

    green_mode = GreenMode.Asyncio

    pcap_dir: str = device_property(  # type: ignore
        doc="Absolute path on disk that points to a directory containing PCAP files",
        mandatory=True,
    )

    test_mode: int = device_property(  # type: ignore
        default_value=TestMode.NONE,
    )

    files: str = attribute(  # type: ignore
        label="PCAP files",
    )

    def __init__(self, *args, **kwargs):
        self._background_tasks: set[asyncio.Task] = set()
        self._stop_event = asyncio.Event()
        self._lock = asyncio.Lock()

        self._files = {}

        super().__init__(*args, **kwargs)

    async def init_device(self) -> None:  # pylint: disable=invalid-overridden-method
        await super().init_device()  # type: ignore
        self.debug_stream("Device init started")

        self.set_state(DevState.INIT)

        for attribute_name in ["files"]:
            self.set_change_event(attribute_name, True, False)

        await self._start_monitoring()

        self.set_state(DevState.ON)
        self.debug_stream("Device init completed")

    async def delete_device(self) -> None:  # pylint: disable=invalid-overridden-method
        self.debug_stream("Device deinit started")
        self._stop_event.set()
        await asyncio.gather(*self._background_tasks)
        self.debug_stream("Device deinit completed")

        await super().delete_device()  # type: ignore

    async def _process_existing_files(self) -> None:
        path = Path(self.pcap_dir)
        for root, _, file_names in path.walk():  # pylint: disable=no-member
            for file_name in file_names:
                file = root / file_name
                if _is_monitored_file(file):
                    await self._update_file(file)

    async def _start_monitoring(self) -> None:
        await self._process_existing_files()

        task = asyncio.create_task(self._monitor())
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _monitor(self) -> None:
        self.info_stream("Start monitoring files")
        async for changes in watchfiles.awatch(
            self.pcap_dir,
            watch_filter=_monitor_filter,
            ignore_permission_denied=True,
            rust_timeout=0,
            stop_event=self._stop_event,
        ):
            for change, path in changes:
                match change:
                    case watchfiles.Change.added | watchfiles.Change.modified:
                        await self._update_file(Path(path))
                    case watchfiles.Change.deleted:
                        await self._remove_file(Path(path))

        self.info_stream("Stop monitoring files")
        self.set_state(DevState.OFF)

    async def _update_file(self, file: Path) -> None:
        file_name = str(file.relative_to(self.pcap_dir))
        self.info_stream("Updating file %s", file_name)

        file_info = file.stat()

        async with self._lock:
            self._files[file_name] = {
                "size": file_info.st_size,
                "mtime": file_info.st_mtime,
            }
            self.push_change_event("files", json.dumps(self._files))

    async def _remove_file(self, file: Path) -> None:
        file_name = str(file.relative_to(self.pcap_dir))
        self.info_stream("Removing file %s", file_name)

        async with self._lock:
            if file_name in self._files:
                del self._files[file_name]
                self.push_change_event("files", json.dumps(self._files))

    def read_files(self) -> str:
        """
        Read method for the ``files`` device attribute.
        """
        return json.dumps(self._files)

    @command
    async def RemoveFile(self, file_name: str) -> None:  # pylint: disable=invalid-name
        """
        Remove the specified file from the file system.
        """
        async with self._lock:
            if file_name not in self._files:
                raise ValueError("Unknown file")

        self.info_stream("Removing file %s", file_name)
        file_path = Path(self.pcap_dir, file_name)
        file_path.unlink(missing_ok=True)

    @command(dtype_out="DevEncoded")
    async def ReadVisibilityData(self, file_name: str) -> tuple[str, bytes]:  # pylint: disable=invalid-name
        """
        Read visibility data from the specified file.
        """
        file_path = Path(self.pcap_dir, file_name)
        file_contents = await read_visibilities(file_path, TestMode(self.test_mode))
        return (
            _encode_spead_headers(file_contents.spead_headers),
            _encode_spead_data(file_contents.spead_data),
        )


def main(args=None, **kwargs):  # pylint: disable=missing-function-docstring
    return run((PcapReader,), args=args, **kwargs)


if __name__ == "__main__":
    main()
