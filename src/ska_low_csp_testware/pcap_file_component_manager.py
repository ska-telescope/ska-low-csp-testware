# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,broad-exception-caught

import logging
import os
from typing import Any, Callable

from ska_control_model import CommunicationStatus, PowerState, TaskStatus
from ska_tango_base.base import CommunicationStatusCallbackType, TaskCallbackType
from ska_tango_base.executor import TaskExecutorComponentManager
from ska_tango_base.poller import PollingComponentManager

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


class PcapFileWatcherComponentManager(PollingComponentManager[str, list[str]]):
    def __init__(  # pylint: disable=too-many-arguments
        self,
        pcap_dir: str,
        logger: logging.Logger,
        communication_state_callback: CommunicationStatusCallbackType,
        component_state_callback: Callable[..., None],
        poll_rate: float = 5.0,
        **state: Any
    ) -> None:
        super().__init__(logger, communication_state_callback, component_state_callback, poll_rate, **state)
        self._pcap_dir = pcap_dir

    def on(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def standby(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def off(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def reset(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def abort_commands(self, task_callback: TaskCallbackType | None = None) -> tuple[TaskStatus, str]:
        return TaskStatus.REJECTED, "Command not supported"

    def get_request(self) -> str:
        return self._pcap_dir

    def poll(self, poll_request: str) -> list[str]:
        files = []
        for file_name in os.listdir(poll_request):
            file_path = os.path.join(poll_request, file_name)
            if os.path.isfile(file_path) and file_path.endswith(".pcap"):
                files.append(file_path)

        return files

    def poll_succeeded(self, poll_response: list[str]) -> None:
        super().poll_succeeded(poll_response)
        self._update_component_state(power=PowerState.ON, fault=False, files=poll_response)
