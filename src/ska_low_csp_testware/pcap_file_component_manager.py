# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,broad-exception-caught

import logging
import os
import threading
from dataclasses import dataclass
from typing import Any, Callable

import pandas
import spead2
import spead2.recv
from ska_control_model import PowerState, TaskStatus
from ska_tango_base.base import CommunicationStatusCallbackType, TaskCallbackType
from ska_tango_base.executor import TaskExecutor
from ska_tango_base.poller import PollingComponentManager

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


@dataclass
class PollRequest:
    pass


@dataclass
class PollResponse:
    file_info: os.stat_result


class PcapFileComponentManager(PollingComponentManager[PollRequest, PollResponse]):
    def __init__(  # pylint: disable=too-many-arguments
        self,
        pcap_file_path: str,
        logger: logging.Logger,
        communication_state_callback: CommunicationStatusCallbackType,
        component_state_callback: Callable[..., None],
        poll_rate: float = 1.0,
        max_queue_size: int = 32,
        max_workers: int | None = 1,
        **state: Any,
    ) -> None:
        self._pcap_file_path = pcap_file_path
        self._max_queue_size = max_queue_size
        self._task_executor = TaskExecutor(max_workers)
        super().__init__(
            logger,
            communication_state_callback,
            component_state_callback,
            poll_rate,
            **state,
        )

    def get_request(self) -> PollRequest:
        return PollRequest()

    def poll(self, poll_request: PollRequest) -> PollResponse:
        return PollResponse(
            file_info=os.stat(self._pcap_file_path),
        )

    def polling_started(self) -> None:
        super().polling_started()
        self._update_component_state(power=PowerState.ON, fault=False)

    def poll_succeeded(self, poll_response: PollResponse) -> None:
        super().poll_succeeded(poll_response)
        self._update_component_state(
            file_size=poll_response.file_info.st_size,
            file_time_modified=poll_response.file_info.st_mtime_ns,
        )

    def on(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def standby(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def off(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def reset(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def abort_commands(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        if task_callback:
            task_callback(status=TaskStatus.IN_PROGRESS)
        return self._task_executor.abort(task_callback)

    def delete(self) -> None:
        file_path = self._pcap_file_path
        self.logger.info("Deleting file %s", file_path)
        try:
            os.remove(file_path)
        except Exception:
            self.logger.error("Failed to delete file %s", file_path, exc_info=True)
            raise
        self.stop_communicating()

    def load(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return self._submit_task(self._load, task_callback=task_callback)

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

    def _submit_task(  # pylint: disable=too-many-arguments
        self,
        func: Callable[..., None],
        args: Any = None,
        kwargs: Any = None,
        is_cmd_allowed: Callable[[], bool] | None = None,
        task_callback: TaskCallbackType | None = None,
    ) -> tuple[TaskStatus, str]:
        input_queue_size = self._task_executor.get_input_queue_size()
        if input_queue_size < self._max_queue_size:
            return self._task_executor.submit(func, args, kwargs, is_cmd_allowed, task_callback=task_callback)

        return (
            TaskStatus.REJECTED,
            f"Input queue supports a maximum of {self._max_queue_size} commands",
        )
