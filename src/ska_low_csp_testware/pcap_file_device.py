# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,broad-exception-caught

import logging
import os

from tango import Util
from tango.server import Device, device_property, run
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

__all__ = ["PcapFileWatcher", "PcapFile", "main"]


class PcapFileWatcher(Device, FileSystemEventHandler):
    pcap_dir = device_property(dtype="DevString")

    def init_device(self):
        super().init_device()
        self.logger = logging.getLogger(self.get_name())
        self.observer = Observer()
        self.logger.warning("Start watching directory %s", self.pcap_dir)
        self.observer.schedule(self, self.pcap_dir)
        self.observer.start()
        self.logger.warning("Watcher started")

    def delete_device(self):
        self.logger.warning("Stop watching directory %s", self.pcap_dir)
        self.observer.stop()
        self.observer.join()
        self.logger.warning("Watcher stopped")
        super().delete_device()

    def on_created(self, event: FileSystemEvent) -> None:
        self.logger.warning("Creating new device to represent %s", event.src_path)
        try:
            Util.instance().create_device(
                "PcapFile",
                f"test/pcap-file/{os.path.basename(event.src_path)}",
                cb=self._fill_device_properties,
            )
        except Exception:
            self.logger.error("Failed to create device", exc_info=True)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self.logger.warning("Removing device representing %s", event.src_path)
        try:
            Util.instance().delete_device("PcapFile", f"test/pcap-file/{os.path.basename(event.src_path)}")
        except Exception:
            self.logger.error("Failed to delete device", exc_info=True)

    def _fill_device_properties(self, dev_name: str) -> None:
        pcap_file_name = dev_name.removeprefix("test/pcap-file/")
        pcap_file_path = os.path.join(self.pcap_dir, pcap_file_name)  # type: ignore
        properties = {"pcap_file_path": [pcap_file_path]}
        try:
            Util.get_database().put_device_property(dev_name, properties)
        except Exception:
            self.logger.error("Failed to fill device properties", exc_info=True)


class PcapFile(Device):
    pcap_file_path = device_property(dtype="DevString")

    def init_device(self):
        super().init_device()
        self.logger = logging.getLogger(self.get_name())
        self.logger.warning("I'm representing %s", self.pcap_file_path)


def main(args=None, **kwargs):
    return run((PcapFileWatcher, PcapFile), args=args, **kwargs)


if __name__ == "__main__":
    main()
