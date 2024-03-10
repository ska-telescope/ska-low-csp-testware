# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,broad-exception-caught

import logging
import os
from typing import Any, Callable

from ska_control_model import CommunicationStatus, TaskStatus
from ska_tango_base.base import CommunicationStatusCallbackType, TaskCallbackType
from ska_tango_base.executor import TaskExecutorComponentManager
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

__all__ = ["PcapFileComponentManager", "PcapFileWatcherComponentManager"]


class PcapFileComponentManager(TaskExecutorComponentManager):
    def __init__(
        self,
        pcap_file_path: str,
        logger: logging.Logger,
        communication_state_callback: CommunicationStatusCallbackType | None = None,
        component_state_callback: Callable[..., None] | None = None,
        **state: Any
    ) -> None:
        super().__init__(logger, communication_state_callback, component_state_callback, **state)
        self._pcap_file_path = pcap_file_path

    def start_communicating(self) -> None:
        if self.communication_state == CommunicationStatus.ESTABLISHED:
            return

        if self.communication_state == CommunicationStatus.DISABLED:
            self._update_communication_state(CommunicationStatus.NOT_ESTABLISHED)

        self.logger.info("Start communicating")

        self._update_communication_state(CommunicationStatus.ESTABLISHED)

    def stop_communicating(self) -> None:
        if self.communication_state == CommunicationStatus.DISABLED:
            return

        self.logger.info("Stop communicating")

        self._update_communication_state(CommunicationStatus.DISABLED)

    def on(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def standby(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def off(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def reset(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"


class PcapFileWatcherComponentManager(TaskExecutorComponentManager, FileSystemEventHandler):
    def __init__(  # pylint: disable=too-many-arguments
        self,
        pcap_dir: str,
        logger: logging.Logger,
        communication_state_callback: CommunicationStatusCallbackType | None = None,
        component_state_callback: Callable[..., None] | None = None,
        pcap_file_created_callback: Callable[[str], None] | None = None,
        pcap_file_deleted_callback: Callable[[str], None] | None = None,
        **state: Any
    ) -> None:
        super().__init__(logger, communication_state_callback, component_state_callback, **state)
        self._pcap_dir = pcap_dir
        self._pcap_file_created_callback = pcap_file_created_callback
        self._pcap_file_deleted_callback = pcap_file_deleted_callback
        self._observer = Observer()
        self._observer.schedule(self, self._pcap_dir)

    def start_communicating(self) -> None:
        if self.communication_state == CommunicationStatus.ESTABLISHED:
            return

        if self.communication_state == CommunicationStatus.DISABLED:
            self._update_communication_state(CommunicationStatus.NOT_ESTABLISHED)

        self.logger.info("Start observing directory %s for changes", self._pcap_dir)
        self._observer.start()

        self.logger.info("Loading existing files")
        for file_name in os.listdir(self._pcap_dir):
            file_path = os.path.join(self._pcap_dir, file_name)
            if os.path.isfile(file_path) and self._pcap_file_created_callback is not None:
                self._pcap_file_created_callback(file_path)

        self._update_communication_state(CommunicationStatus.ESTABLISHED)

    def stop_communicating(self) -> None:
        if self.communication_state == CommunicationStatus.DISABLED:
            return

        self.logger.info("Stop observing directory %s for changes", self._pcap_dir)
        self._observer.stop()
        self._observer.join()

        self._update_communication_state(CommunicationStatus.DISABLED)

    def on(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def standby(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def off(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def reset(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.src_path.endswith(".pcap"):
            return

        self.logger.info("File created: %s", event.src_path)
        if self._pcap_file_created_callback is not None:
            self._pcap_file_created_callback(event.src_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.src_path.endswith(".pcap"):
            return

        self.logger.info("File deleted: %s", event.src_path)
        if self._pcap_file_deleted_callback is not None:
            self._pcap_file_deleted_callback(event.src_path)
