# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,broad-exception-caught

import functools
import os

from ska_control_model import PowerState
from ska_tango_base.base import SKABaseDevice
from tango import Util
from tango.server import attribute, device_property

from ska_low_csp_testware.pcap_file_watcher_component_manager import PcapFileWatcherComponentManager

__all__ = ["PcapFileWatcherDevice"]

PCAP_FILE_DEVICE_CLASS = "PcapFileDevice"


class PcapFileWatcherDevice(SKABaseDevice):
    pcap_dir: str = device_property()  # type: ignore

    def __init__(self, *args, **kwargs):
        self._files: list[str] = []
        super().__init__(*args, **kwargs)

    def create_component_manager(self) -> PcapFileWatcherComponentManager:
        return PcapFileWatcherComponentManager(
            pcap_dir=self.pcap_dir,
            logger=self.logger,
            communication_state_callback=self._communication_state_changed,
            component_state_callback=self._component_state_changed,
            files=self._files,
        )

    @attribute(max_dim_x=9999)
    def files(self) -> list[str]:
        return self._files

    def is_Off_allowed(self) -> bool:
        return False

    def is_On_allowed(self) -> bool:
        return False

    def is_Reset_allowed(self) -> bool:
        return False

    def is_Standby_allowed(self) -> bool:
        return False

    def _component_state_changed(
        self,
        fault: bool | None = None,
        power: PowerState | None = None,
        files: list[str] | None = None,
    ) -> None:
        super()._component_state_changed(fault, power)

        if files is not None:
            self._process_file_changes(files)
            self._update_files(files)

    def _process_file_changes(self, files: list[str]) -> None:
        added = [file for file in files if file not in self._files]
        removed = [file for file in self._files if file not in files]

        for file in added:
            self._create_pcap_file_device(file)

        for file in removed:
            self._delete_pcap_file_device(file)

    def _update_files(self, files: list[str]) -> None:
        self._files = files
        self.push_change_event("files", files)
        self.push_archive_event("files", files)

    def _create_pcap_file_device(self, file_name: str) -> None:
        dev_name = self._get_dev_name(file_name)

        if self._is_device_defined(dev_name):
            self.logger.info("Device %s already exists, skipping device creation", dev_name)
            return

        self.logger.info("Creating device %s", dev_name)

        try:
            Util.instance().create_device(
                PCAP_FILE_DEVICE_CLASS,
                dev_name,
                cb=functools.partial(self._create_pcap_file_device_properties, file_name),
            )
        except Exception:
            self.logger.error("Failed to create device %s", dev_name, exc_info=True)

    def _create_pcap_file_device_properties(self, file_name: str, dev_name: str) -> None:
        db = Util.instance().get_database()
        db.put_device_property(dev_name, {"pcap_file_path": [os.path.join(self.pcap_dir, file_name)]})

    def _delete_pcap_file_device(self, file_name: str) -> None:
        dev_name = self._get_dev_name(file_name)

        if not self._is_device_defined(dev_name):
            self.logger.info("Device %s does not exist, no need to remove", dev_name)
            return

        self.logger.info("Removing device %s", dev_name)
        try:
            Util.instance().delete_device(PCAP_FILE_DEVICE_CLASS, dev_name)
        except Exception:
            self.logger.error("Failed to remove device %s", dev_name, exc_info=True)

    def _is_device_defined(self, dev_name: str) -> bool:
        util = Util.instance()
        db = util.get_database()

        devices = db.get_device_name(util.get_ds_name(), PCAP_FILE_DEVICE_CLASS)
        return dev_name in devices.value_string

    def _get_dev_name(self, file_name: str) -> str:
        return f"test/pcap-file/{file_name.lower()}"
