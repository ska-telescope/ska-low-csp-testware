# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,broad-exception-caught

import functools
import os

import pandas
import spead2
import spead2.recv
from ska_tango_base.base import SKABaseDevice
from tango import Util
from tango.server import attribute, command, device_property, run

from ska_low_csp_testware.pcap_file_component_manager import PcapFileComponentManager, PcapFileWatcherComponentManager
from ska_low_csp_testware.spead import SpeadHeapVisitor, process_pcap_file

__all__ = ["PcapFileWatcher", "PcapFile", "main"]


class PcapFileWatcher(SKABaseDevice):
    pcap_dir: str = device_property()  # type: ignore

    def create_component_manager(self) -> PcapFileWatcherComponentManager:
        return PcapFileWatcherComponentManager(
            pcap_dir=self.pcap_dir,
            logger=self.logger,
            communication_state_callback=self._communication_state_changed,
            component_state_callback=self._component_state_changed,
            pcap_file_created_callback=self._pcap_file_created,
            pcap_file_deleted_callback=self._pcap_file_deleted,
        )

    def _pcap_file_created(self, file_path: str) -> None:
        file_name = os.path.basename(file_path)
        dev_name = f"test/pcap-file/{file_name}"
        self.logger.info("Creating device %s", dev_name)

        try:
            Util.instance().create_device(
                "PcapFile",
                dev_name,
                cb=functools.partial(self._create_pcap_file_device_properties, file_path),
            )
        except Exception:
            self.logger.error("Failed to create device %s", dev_name, exc_info=True)

    def _pcap_file_deleted(self, file_path: str) -> None:
        file_name = os.path.basename(file_path)
        dev_name = f"test/pcap-file/{file_name}"
        self.logger.info("Removing device %s", dev_name)
        try:
            Util.instance().delete_device("PcapFile", dev_name)
        except Exception:
            self.logger.error("Failed to remove device %s", dev_name, exc_info=True)

    def _create_pcap_file_device_properties(self, file_path: str, dev_name: str) -> None:
        db = Util.instance().get_database()
        db.put_device_property(dev_name, {"pcap_file_path": [file_path]})


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
            return "\\{\\}"

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
