"""
Module for the ``PcapFile`` TANGO device.
"""

import io
import logging
import os
from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import Any, Callable

import numpy as np
import numpy.typing as npt
import pandas as pd
from ska_control_model import PowerState, ResultCode, TaskStatus
from ska_tango_base.base import CommunicationStatusCallbackType, SKABaseDevice, TaskCallbackType
from ska_tango_base.commands import DeviceInitCommand, FastCommand, SubmittedSlowCommand
from ska_tango_base.executor import TaskExecutor
from ska_tango_base.poller import PollingComponentManager
from tango.server import attribute, command, device_property

from ska_low_csp_testware.common_types import DataType, PcapFileContents
from ska_low_csp_testware.low_cbf_vis import ReadLowCbfVisibilitiesTask

__all__ = [
    "PcapFile",
    "PcapFileComponentManager",
]


@dataclass
class _PollRequest:
    pass


@dataclass
class _PollResponse:
    file_info: os.stat_result


class PcapFileComponentManager(PollingComponentManager[_PollRequest, _PollResponse]):
    """
    Component manager to interact with the PCAP file.

    This component manager periodically polls the file information and exposes it as component state.
    It also exposes methods to read the PCAP file contents.
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        pcap_file_path: Path,
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
            logger=logger,
            communication_state_callback=communication_state_callback,
            component_state_callback=component_state_callback,
            poll_rate=poll_rate,
            **state,
        )

    def get_request(self) -> _PollRequest:
        return _PollRequest()

    def poll(self, poll_request: _PollRequest) -> _PollResponse:
        return _PollResponse(
            file_info=self._pcap_file_path.stat(),
        )

    def polling_started(self) -> None:
        super().polling_started()
        self._update_component_state(
            power=PowerState.ON,
            fault=False,
        )

    def poll_succeeded(self, poll_response: _PollResponse) -> None:
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
        """
        Delete the PCAP file on disk.

        After the file is removed, the component manager automatically stops polling the file information.
        """
        self.stop_communicating()
        file_path = self._pcap_file_path
        self.logger.info("Deleting file %s", file_path)
        try:
            file_path.unlink()
        except Exception:
            self.logger.error("Failed to delete file %s", file_path, exc_info=True)
            self.start_communicating()
            raise

    def load(self, data_type: DataType, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        """
        Load the PCAP file contents into memory.

        When called, the file is read in a background task on a separate thread.
        The supplied ``task_callback`` is invoked as the task progresses and when it finishes.

        :param data_type: The type of data contained in the PCAP file.
        :param task_callback: An optional callback that is invoked with task status updates.
        :returns: The initial task status and message after submitting the task.
        """
        match data_type:
            case DataType.VIS:
                task = ReadLowCbfVisibilitiesTask(
                    pcap_file_path=self._pcap_file_path,
                    result_callback=lambda contents: self._update_component_state(file_contents=contents),
                    logger=self.logger,
                )
            case _:
                return TaskStatus.REJECTED, "Unsupported data type"

        return self._submit_task(task, task_callback=task_callback)

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


class PcapFile(SKABaseDevice[PcapFileComponentManager]):
    """
    TANGO device representing a PCAP file.
    """

    pcap_file_path: str = device_property(doc="Absolute path on disk that points to a valid PCAP file")  # type: ignore

    def __init__(self, *args, **kwargs):
        self._file_contents: PcapFileContents | None = None
        self._file_size = 0
        self._file_time_modified = 0
        super().__init__(*args, **kwargs)

    def create_component_manager(self) -> PcapFileComponentManager:
        return PcapFileComponentManager(
            pcap_file_path=Path(self.pcap_file_path),
            logger=self.logger,
            communication_state_callback=self._communication_state_changed,
            component_state_callback=self._component_state_changed,
            file_contents=self._file_contents,
            file_time_modified=self._file_time_modified,
            file_size=self._file_size,
        )

    class InitCommand(DeviceInitCommand):
        """
        Class for the TANGO device's ``Init()`` command.
        """

        def do(self, *args: Any, **kwargs: Any) -> tuple[ResultCode, str]:
            for attr_name in [
                "file_size",
                "file_time_modified",
                "spead_heap_count",
                "spead_headers",
                "spead_data",
            ]:
                self._device.set_change_event(attr_name, True, False)

            return ResultCode.OK, "Init completed"

    class DeleteCommand(FastCommand[None]):
        """
        Class for the TANGO device's ``Delete()`` command.
        """

        def __init__(
            self,
            component_manager: PcapFileComponentManager,
            logger: Logger | None = None,
        ) -> None:
            self._component_manager = component_manager
            super().__init__(logger)

        def do(self, *args: Any, **kwargs: Any) -> None:
            self._component_manager.delete()

    def init_command_objects(self) -> None:
        super().init_command_objects()

        self.register_command_object(
            "Delete",
            self.DeleteCommand(
                self.component_manager,
                self.logger,
            ),
        )

        self.register_command_object(
            "Load",
            SubmittedSlowCommand(
                "Load",
                self._command_tracker,
                self.component_manager,
                "load",
                callback=None,
                logger=self.logger,
            ),
        )

    @attribute(
        label="File size",
        unit="byte",
        standard_unit="byte",
        display_unit="byte",
    )
    def file_size(self) -> int:
        """
        The size of the PCAP file.

        :returns: File size in bytes.
        """
        return self._file_size

    @attribute(
        label="File modification time",
        unit="ns",
        standard_unit="s",
        display_unit="ns",
    )
    def file_time_modified(self) -> int:
        """
        The last modification time of the PCAP file.

        :returns: Unix timestamp in nanoseconds.
        """
        return self._file_time_modified

    @attribute(label="SPEAD heap count")
    def spead_heap_count(self) -> int:
        """
        The number of SPEAD heaps in the PCAP file.

        :returns: The heap count.
        :raises ValueError: When the file contents are not loaded into memory.
        """
        if self._file_contents:
            return self._file_contents.spead_heap_count

        raise ValueError("File contents not loaded")

    @attribute(label="SPEAD headers")
    def spead_headers(self) -> str:
        """
        The SPEAD header contents of the PCAP file.

        :returns: A ``pandas.DataFrame`` encoded as JSON.
        :raises ValueError: When the file contents are not loaded into memory.
        """
        if self._file_contents:
            return self._encode_spead_headers(self._file_contents.spead_headers)

        raise ValueError("File contents not loaded")

    @attribute(label="SPEAD data", dtype="DevEncoded")
    def spead_data(self) -> tuple[str, bytes]:
        """
        The SPEAD data contents of the PCAP file.

        :returns: A ``numpy.NDArray`` encoded using ``numpy.save``.
        :raises ValueError: When the file contents are not loaded into memory.
        """
        if self._file_contents:
            return "numpy.NDArray", self._encode_spead_data(self._file_contents.spead_data)

        raise ValueError("File contents not loaded")

    @command
    def Delete(self) -> None:  # pylint: disable=invalid-name
        """
        Delete the PCAP file on disk.
        """
        handler = self.get_command_object("Delete")
        handler()

    @command(
        doc_in="The type of data contained in the PCAP file",
        dtype_out="DevVarLongStringArray",
        doc_out="Tuple containing the result code and corresponding message",
    )
    def Load(self, data_type: DataType) -> tuple[list[ResultCode], list[str]]:  # pylint: disable=invalid-name
        """
        Load the PCAP file contents into memory asynchronously.

        This command is implemented as a long-running command.
        For more information, refer to :doc:`ska-tango-base:guide/long_running_command`.

        :returns: Tuple containing the initial command result code and message.
        """
        handler = self.get_command_object("Load")
        result, message = handler(data_type)
        return [result], [message]

    def _encode_spead_headers(self, spead_headers: pd.DataFrame) -> str:
        return spead_headers.to_json()

    def _encode_spead_data(self, spead_data: npt.NDArray) -> bytes:
        buffer = io.BytesIO()
        np.save(buffer, spead_data)
        return buffer.getvalue()

    def _component_state_changed(  # pylint: disable=too-many-arguments
        self,
        fault: bool | None = None,
        power: PowerState | None = None,
        file_contents: PcapFileContents | None = None,
        file_size: int | None = None,
        file_time_modified: int | None = None,
    ) -> None:
        super()._component_state_changed(fault, power)

        if file_contents:
            self._file_contents = file_contents
            self.push_change_event("spead_heap_count", file_contents.spead_heap_count)
            self.push_change_event("spead_headers", self._encode_spead_headers(file_contents.spead_headers))
            self.push_change_event("spead_data", self._encode_spead_data(file_contents.spead_data))

        if file_size is not None:
            self._file_size = file_size
            self.push_change_event("file_size", file_size)

        if file_time_modified is not None:
            self._file_time_modified = file_time_modified
            self.push_change_event("file_time_modified", file_time_modified)
