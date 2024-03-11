# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,broad-exception-caught

import logging
from typing import Any, Callable

from ska_control_model import CommunicationStatus, TaskStatus
from ska_tango_base.base import CommunicationStatusCallbackType, TaskCallbackType
from ska_tango_base.executor import TaskExecutorComponentManager

__all__ = ["PcapFileComponentManager"]


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
