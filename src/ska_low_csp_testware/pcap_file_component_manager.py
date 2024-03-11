# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,broad-exception-caught

import logging
import os
import threading
from typing import Any, Callable

import pandas
import spead2
import spead2.recv
from ska_control_model import CommunicationStatus, PowerState, TaskStatus
from ska_tango_base.base import CommunicationStatusCallbackType, TaskCallbackType
from ska_tango_base.executor import TaskExecutorComponentManager

from ska_low_csp_testware.pcap_file_metadata import PcapFileMetadata
from ska_low_csp_testware.spead import SpeadHeapVisitor, read_pcap_file

__all__ = ["PcapFileComponentManager"]


class _ExtractMetadata(SpeadHeapVisitor):
    def __init__(self) -> None:
        self._headers = []
        self._heap_count = 0

    def visit_start_of_stream_heap(self, heap: spead2.recv.Heap, items: dict[str, spead2.Item]) -> None:
        row = {}
        for key, item in items.items():
            row[key] = item.value
        self._headers.append(row)
        self._heap_count += 1

    def visit_data_heap(self, heap: spead2.recv.Heap, items: dict[str, spead2.Item]) -> None:
        self._heap_count += 1

    def visit_end_of_stream_heap(self, heap: spead2.recv.Heap, items: dict[str, spead2.Item]) -> None:
        self._heap_count += 1

    @property
    def metadata(self) -> PcapFileMetadata:
        return PcapFileMetadata(
            heap_count=self._heap_count,
            spead_headers=pandas.DataFrame(self._headers),
        )


class PcapFileComponentManager(TaskExecutorComponentManager):
    def __init__(
        self,
        pcap_file_path: str,
        logger: logging.Logger,
        communication_state_callback: CommunicationStatusCallbackType | None = None,
        component_state_callback: Callable[..., None] | None = None,
        **state: Any
    ) -> None:
        self._pcap_file_path = pcap_file_path
        super().__init__(
            logger,
            communication_state_callback,
            component_state_callback,
            power=PowerState.UNKNOWN,
            fault=None,
            **state,
        )

    def start_communicating(self) -> None:
        if self.communication_state == CommunicationStatus.ESTABLISHED:
            return

        if self.communication_state == CommunicationStatus.DISABLED:
            self._update_communication_state(CommunicationStatus.NOT_ESTABLISHED)

        self._update_component_state(power=PowerState.ON, fault=False)
        self._update_communication_state(CommunicationStatus.ESTABLISHED)

    def stop_communicating(self) -> None:
        if self.communication_state == CommunicationStatus.DISABLED:
            return

        self._update_component_state(power=PowerState.UNKNOWN, fault=None)
        self._update_communication_state(CommunicationStatus.DISABLED)

    def on(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def standby(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def off(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def reset(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def delete(self) -> None:
        file_path = self._pcap_file_path
        self.logger.info("Deleting file %s", file_path)
        try:
            os.remove(file_path)
        except Exception:
            self.logger.error("Failed to delete file %s", file_path, exc_info=True)
            raise

    def load(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return self.submit_task(self._load, task_callback=task_callback)

    def _load(
        self,
        task_callback: TaskCallbackType,
        task_abort_event: threading.Event,
    ) -> None:
        task_callback(status=TaskStatus.IN_PROGRESS)
        visitor = _ExtractMetadata()
        try:
            read_pcap_file(
                pcap_file_path=self._pcap_file_path,
                visitors=[visitor],
                logger=self.logger,
                task_abort_event=task_abort_event,
            )

            if task_abort_event.is_set():
                task_callback(status=TaskStatus.ABORTED)
                return

            self._update_component_state(metadata=visitor.metadata, fault=False)
            task_callback(status=TaskStatus.COMPLETED)
        except Exception as e:
            self.logger.error("Failed to load file %s", self._pcap_file_path, exc_info=True)
            self._update_component_state(fault=True)
            task_callback(status=TaskStatus.FAILED, exception=e)
