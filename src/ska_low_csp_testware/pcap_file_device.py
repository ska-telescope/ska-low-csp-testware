# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,broad-exception-caught

import functools
import os

import pandas
import spead2
import spead2.recv
from ska_control_model import PowerState
from ska_tango_base.base import SKABaseDevice
from tango import DevFailed, Util
from tango.server import attribute, command, device_property, run

from ska_low_csp_testware.pcap_file_component_manager import PcapFileComponentManager, PcapFileWatcherComponentManager
from ska_low_csp_testware.spead import SpeadHeapVisitor, process_pcap_file

__all__ = ["PcapFileWatcher", "PcapFile", "main"]


class PcapFileWatcher(SKABaseDevice):
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

    def _create_pcap_file_device(self, file_path: str) -> None:
        file_name = os.path.basename(file_path)
        dev_name = f"test/pcap-file/{file_name}"

        if self._is_device_defined(dev_name):
            self.logger.info("Device %s already exists, skipping device creation", dev_name)
            return

        self.logger.info("Creating device %s", dev_name)

        try:
            Util.instance().create_device(
                "PcapFile",
                dev_name,
                cb=functools.partial(self._create_pcap_file_device_properties, file_path),
            )
        except Exception:
            self.logger.error("Failed to create device %s", dev_name, exc_info=True)

    def _create_pcap_file_device_properties(self, file_path: str, dev_name: str) -> None:
        db = Util.instance().get_database()
        db.put_device_property(dev_name, {"pcap_file_path": [file_path]})

    def _delete_pcap_file_device(self, file_path: str) -> None:
        file_name = os.path.basename(file_path)
        dev_name = f"test/pcap-file/{file_name}"

        if not self._is_device_defined(dev_name):
            self.logger.info("Device %s does not exist, no need to remove", dev_name)
            return

        self.logger.info("Removing device %s", dev_name)
        try:
            Util.instance().delete_device("PcapFile", dev_name)
        except Exception:
            self.logger.error("Failed to remove device %s", dev_name, exc_info=True)

    def _is_device_defined(self, dev_name: str) -> bool:
        db = Util.instance().get_database()
        try:
            db.get_device_info(dev_name)
            return True
        except DevFailed:
            return False


class ExtractVisibilityMetadata(SpeadHeapVisitor):
    def __init__(self) -> None:
        self._metadata = []

    def visit_start_of_stream_heap(self, heap: spead2.recv.Heap, items: dict[str, spead2.Item]) -> None:
        row = {}
        for key, item in items.items():
            row[key] = item.value
        self._metadata.append(row)

    @property
    def metadata(self) -> pandas.DataFrame:
        return pandas.DataFrame(self._metadata)


class PcapFile(SKABaseDevice):
    pcap_file_path: str = device_property()  # type: ignore

    _metadata: pandas.DataFrame | None = None

    def create_component_manager(self) -> PcapFileComponentManager:
        return PcapFileComponentManager(
            pcap_file_path=self.pcap_file_path,
            logger=self.logger,
            communication_state_callback=self._communication_state_changed,
            component_state_callback=self._component_state_changed,
        )

    @attribute
    def metadata(self) -> str:
        if self._metadata is None:
            return "{}"

        return self._metadata.to_json()

    @command
    def load(self) -> None:
        self.logger.debug("Start unpacking file")
        visitor = ExtractVisibilityMetadata()
        process_pcap_file(self.pcap_file_path, visitor)
        self._metadata = visitor.metadata
        self.logger.debug("Finished unpacking file")


def main(args=None, **kwargs):
    return run((PcapFileWatcher, PcapFile), args=args, **kwargs)


if __name__ == "__main__":
    main()
