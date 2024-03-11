# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,broad-exception-caught

import logging
import threading
from typing import Any, Callable

import pandas
import spead2
import spead2.recv
from ska_control_model import CommunicationStatus, PowerState, TaskStatus
from ska_tango_base.base import CommunicationStatusCallbackType, TaskCallbackType, check_communicating
from ska_tango_base.executor import TaskExecutorComponentManager

from ska_low_csp_testware.spead import SpeadHeapVisitor, process_pcap_file

__all__ = ["PcapFileComponentManager"]


class _ExtractVisibilityMetadata(SpeadHeapVisitor):
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

    @check_communicating
    def load(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return self.submit_task(self._load, task_callback=task_callback)

    def _load(  # pylint: disable=unused-argument
        self,
        task_callback: TaskCallbackType,
        task_abort_event: threading.Event,
    ) -> None:
        task_callback(status=TaskStatus.IN_PROGRESS)
        visitor = _ExtractVisibilityMetadata()
        try:
            process_pcap_file(self._pcap_file_path, visitor)
            self._update_component_state(metadata=visitor.metadata, fault=False)
            task_callback(status=TaskStatus.COMPLETED)
        except Exception as e:
            self._update_component_state(fault=True)
            task_callback(status=TaskStatus.FAILED, exception=e)
