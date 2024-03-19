"""
Module for the ``PcapReader`` TANGO device.
"""

import asyncio
import json
from pathlib import Path

import watchfiles
from ska_control_model import TestMode
from tango import DevState, GreenMode
from tango.server import Device, attribute, device_property, run

__all__ = ["PcapReader", "main"]


def _is_monitored_file(path: Path):
    return path.suffix == ".pcap"


def _monitor_filter(change: watchfiles.Change, path: str):  # pylint: disable=unused-argument
    return _is_monitored_file(Path(path))


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
        self._files = {}
        self._stop_event = asyncio.Event()
        self._background_tasks: set[asyncio.Task] = set()
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
        for file in path.iterdir():
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
            stop_event=self._stop_event,
        ):
            for change, path in changes:
                match change:
                    case watchfiles.Change.added, watchfiles.Change.modified:
                        await self._update_file(Path(path))
                    case watchfiles.Change.deleted:
                        await self._remove_file(Path(path))

        self.info_stream("Stop monitoring files")
        self.set_state(DevState.OFF)

    async def _update_file(self, file: Path) -> None:
        file_name = str(file.relative_to(self.pcap_dir))
        self.info_stream("Updating file %s", file_name)

        file_info = file.stat()
        self._files[file_name] = {
            "size": file_info.st_size,
            "mtime": file_info.st_mtime,
        }
        self.push_change_event("files", json.dumps(self._files))

    async def _remove_file(self, file: Path) -> None:
        file_name = str(file.relative_to(self.pcap_dir))
        self.info_stream("Removing file %s", file_name)

        if file_name in self._files:
            del self._files[file_name]
            self.push_change_event("files", json.dumps(self._files))

    def read_files(self) -> str:
        """
        Read method for the ``files`` device attribute.
        """
        return json.dumps(self._files)


def main(args=None, **kwargs):  # pylint: disable=missing-function-docstring
    return run((PcapReader,), args=args, **kwargs)


if __name__ == "__main__":
    main()
