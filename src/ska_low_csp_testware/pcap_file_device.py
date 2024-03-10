# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring

import logging

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

    def on_any_event(self, event: FileSystemEvent) -> None:
        self.logger.warning(event)


class PcapFile(Device):
    pcap_file_path = device_property(dtype="DevString")

    def init_device(self):
        super().init_device()
        self.logger = logging.getLogger(self.get_name())


def main(args=None, **kwargs):
    return run((PcapFileWatcher, PcapFile), args=args, **kwargs)


if __name__ == "__main__":
    main()
