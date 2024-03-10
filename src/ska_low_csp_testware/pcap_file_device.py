# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,broad-exception-caught

import functools
import logging
import os

import pandas
import spead2
import spead2.recv
from tango import Util
from tango.server import Device, attribute, command, device_property, run
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from ska_low_csp_testware.spead import SpeadHeapVisitor, process_pcap_file

__all__ = ["PcapFileWatcher", "PcapFile", "main"]


class PcapFileWatcher(Device, FileSystemEventHandler):
    pcap_dir: str = device_property()  # type: ignore

    def init_device(self):
        super().init_device()
        self.logger = logging.getLogger(self.get_name())
        self.observer = Observer()
        self.logger.warning("Start watching directory %s", self.pcap_dir)
        self.observer.schedule(self, self.pcap_dir)
        self.observer.start()
        self.logger.warning("Watcher started")
        for f in os.listdir(self.pcap_dir):
            self.logger.warning("Found existing file %s", f)
            if os.path.isfile(f):
                self._create_pcap_file_device(f)
            else:
                self.logger.warning("%s is not a regular file, skipping", f)

    def delete_device(self):
        self.logger.warning("Stop watching directory %s", self.pcap_dir)
        self.observer.stop()
        self.observer.join()
        self.logger.warning("Watcher stopped")
        super().delete_device()

    def _create_pcap_file_device(self, file_path: str) -> None:
        if not file_path.endswith(".pcap"):
            return

        file_name = os.path.basename(file_path)
        dev_name = f"test/pcap-file/{file_name}"
        self.logger.warning("Creating device %s", dev_name)

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

    def _remove_pcap_file_device(self, file_path: str) -> None:
        file_name = os.path.basename(file_path)
        dev_name = f"test/pcap-file/{file_name}"
        self.logger.warning("Removing device %s", dev_name)
        try:
            Util.instance().delete_device("PcapFile", dev_name)
        except Exception:
            self.logger.error("Failed to remove device %s", dev_name, exc_info=True)

    def on_created(self, event: FileSystemEvent) -> None:
        self.logger.warning("File created: %s", event.src_path)
        self._create_pcap_file_device(event.src_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self.logger.warning("File deleted: %s", event.src_path)
        self._remove_pcap_file_device(event.src_path)


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


class PcapFile(Device):
    pcap_file_path: str = device_property()  # type: ignore

    _metadata: pandas.DataFrame | None = None

    def init_device(self):
        super().init_device()
        self.logger = logging.getLogger(self.get_name())
        self.logger.warning("I'm representing %s", self.pcap_file_path)

    @attribute
    def metadata(self) -> str:
        if self._metadata is None:
            return "{}"

        return self._metadata.to_json()

    @command
    def load(self) -> None:
        self.logger.warning("Start unpacking file")
        visitor = ExtractVisibilityMetadata()
        process_pcap_file(self.pcap_file_path, visitor)
        self._metadata = visitor.metadata
        self.logger.warning("Finished unpacking file")


def main(args=None, **kwargs):
    return run((PcapFileWatcher, PcapFile), args=args, **kwargs)


if __name__ == "__main__":
    main()
