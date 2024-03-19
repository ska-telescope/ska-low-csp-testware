"""
Module for the ``PcapFileWatcher`` TANGO device.
"""

import asyncio
import functools
import logging
from pathlib import Path

import watchfiles
from ska_control_model import TestMode
from tango import DevState, GreenMode, Util
from tango.server import Device, attribute, device_property

__all__ = ["PcapFileMonitor"]

PCAP_FILE_DEVICE_CLASS = "PcapFile"

module_logger = logging.getLogger(__name__)


def _is_monitored_file(path: Path):
    return path.suffix == ".pcap"


def _monitor_filter(change: watchfiles.Change, path: str):  # pylint: disable=unused-argument
    return _is_monitored_file(Path(path))


class PcapFileMonitor(Device):
    """
    TANGO device that monitors a directory for PCAP files and spawns :py:class:`PcapFile`` devices to represent them.
    """

    green_mode = GreenMode.Asyncio

    pcap_dir: str = device_property(  # type: ignore
        doc="Absolute path on disk that points to a directory containing PCAP files",
        mandatory=True,
    )

    test_mode: int = device_property(  # type: ignore
        default_value=TestMode.NONE,
    )

    files: list[str] = attribute(  # type: ignore
        max_dim_x=9999,
    )

    def __init__(self, *args, **kwargs):
        self._logger = module_logger
        self._file_names: list[str] = []
        self._stop_event = asyncio.Event()
        self._background_tasks: set[asyncio.Task] = set()
        super().__init__(*args, **kwargs)

    async def init_device(self) -> None:  # pylint: disable=invalid-overridden-method
        await super().init_device()  # type: ignore

        self.set_state(DevState.INIT)

        for attribute_name in ["files"]:
            self.set_change_event(attribute_name, True, False)

        await self._start_monitoring()

        self.set_state(DevState.ON)

    async def delete_device(self) -> None:  # pylint: disable=invalid-overridden-method
        self._stop_event.set()
        await asyncio.gather(*self._background_tasks)
        await super().delete_device()  # type: ignore

    async def _process_existing_files(self) -> None:
        path = Path(self.pcap_dir)
        for file in path.iterdir():
            if _is_monitored_file(file):
                await self._add_file(file)

    async def _start_monitoring(self) -> None:
        await self._process_existing_files()

        task = asyncio.create_task(self._monitor())
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _monitor(self) -> None:
        async for changes in watchfiles.awatch(
            self.pcap_dir,
            watch_filter=_monitor_filter,
            recursive=False,
            stop_event=self._stop_event,
        ):
            for change, path in changes:
                match change:
                    case watchfiles.Change.added:
                        await self._add_file(Path(path))
                    case watchfiles.Change.deleted:
                        await self._remove_file(Path(path))

    def read_files(self) -> list[str]:
        """
        Read method for the ``files`` device attribute.
        """
        return self._file_names

    async def _add_file(self, file: Path) -> None:
        file_name = str(file.relative_to(self.pcap_dir))

        if file_name not in self._file_names:
            self._file_names.append(file_name)
            self.push_change_event("files", self._file_names)

        self._create_pcap_file_device(file)

    async def _remove_file(self, file: Path) -> None:
        file_name = str(file.relative_to(self.pcap_dir))

        if file_name in self._file_names:
            self._file_names.remove(file_name)
            self.push_change_event("files", self._file_names)

        self._remove_pcap_file_device(file)

    def _create_pcap_file_device(self, file: Path) -> None:
        if self.test_mode == TestMode.TEST:
            self._logger.info("Test mode enabled, skipping device creation")
            return

        dev_name = self._get_dev_name(file)

        if self._is_device_defined(dev_name):
            self._logger.info("Device %s already exists, skipping device creation", dev_name)
            return

        self._logger.info("Creating device %s", dev_name)

        try:
            Util.instance().create_device(
                PCAP_FILE_DEVICE_CLASS,
                dev_name,
                cb=functools.partial(self._create_pcap_file_device_properties, file),
            )
        except Exception:  # pylint: disable=broad-exception-caught
            self._logger.error("Failed to create device %s", dev_name, exc_info=True)

    def _create_pcap_file_device_properties(self, file: Path, dev_name: str) -> None:
        db = Util.instance().get_database()
        db.put_device_property(dev_name, {"pcap_file_path": [file.absolute()]})

    def _remove_pcap_file_device(self, file: Path) -> None:
        if self.test_mode == TestMode.TEST:
            self._logger.info("Test mode enabled, skipping device removal")
            return

        dev_name = self._get_dev_name(file)

        if not self._is_device_defined(dev_name):
            self._logger.info("Device %s does not exist, no need to remove", dev_name)
            return

        self._logger.info("Removing device %s", dev_name)
        try:
            Util.instance().delete_device(PCAP_FILE_DEVICE_CLASS, dev_name)
        except Exception:  # pylint: disable=broad-exception-caught
            self._logger.error("Failed to remove device %s", dev_name, exc_info=True)

    def _is_device_defined(self, dev_name: str) -> bool:
        util = Util.instance()
        db = util.get_database()

        devices = db.get_device_name(util.get_ds_name(), PCAP_FILE_DEVICE_CLASS)
        return dev_name in devices.value_string

    def _get_dev_name(self, file: Path) -> str:
        return f"test/pcap-file/{file.name.lower()}"
