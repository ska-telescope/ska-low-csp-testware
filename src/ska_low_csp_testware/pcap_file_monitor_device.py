"""
Module for the ``PcapFileWatcher`` TANGO device.
"""

import functools
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable

from ska_control_model import PowerState, TaskStatus
from ska_tango_base.base import CommunicationStatusCallbackType, SKABaseDevice, TaskCallbackType
from ska_tango_base.poller import PollingComponentManager
from tango import Util
from tango.server import attribute, device_property

__all__ = ["PcapFileMonitor"]

PCAP_FILE_DEVICE_CLASS = "PcapFile"


@dataclass
class _PollRequest:
    pass


@dataclass
class _PollResponse:
    file_names: list[str]


class PcapFileMonitorComponentManager(PollingComponentManager[_PollRequest, _PollResponse]):
    """
    Component manager to monitor a specified directory for PCAP files.

    This component manager periodically polls and exposes the contents of the provided ``pcap_dir``.
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        pcap_dir: str,
        logger: logging.Logger,
        communication_state_callback: CommunicationStatusCallbackType,
        component_state_callback: Callable[..., None],
        poll_rate: float = 5.0,
        **state: Any,
    ) -> None:
        self._pcap_dir = pcap_dir
        super().__init__(
            logger=logger,
            communication_state_callback=communication_state_callback,
            component_state_callback=component_state_callback,
            poll_rate=poll_rate,
            **state,
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
        return TaskStatus.REJECTED, "Command not supported"

    def get_request(self) -> _PollRequest:
        return _PollRequest()

    def poll(self, poll_request: _PollRequest) -> _PollResponse:
        files = []
        for file_name in os.listdir(self._pcap_dir):
            file_path = os.path.join(self._pcap_dir, file_name)
            if os.path.isfile(file_path) and file_path.endswith(".pcap"):
                files.append(file_name)

        return _PollResponse(
            file_names=files,
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
            files=poll_response.file_names,
        )


class PcapFileMonitor(SKABaseDevice[PcapFileMonitorComponentManager]):
    """
    TANGO device that monitors a directory for PCAP files and spawns :py:class:`PcapFile`` devices to represent them.
    """

    pcap_dir: str = device_property(  # type: ignore
        doc="Absolute path on disk that points to a directory containing PCAP files"
    )

    def __init__(self, *args, **kwargs):
        self._files: list[str] = []
        super().__init__(*args, **kwargs)

    def create_component_manager(self) -> PcapFileMonitorComponentManager:
        return PcapFileMonitorComponentManager(
            pcap_dir=self.pcap_dir,
            logger=self.logger,
            communication_state_callback=self._communication_state_changed,
            component_state_callback=self._component_state_changed,
            files=self._files,
        )

    @attribute(label="PCAP file names", max_dim_x=9999)
    def files(self) -> list[str]:
        """
        TANGO attribute that exposes the current PCAP files contained in the configured directory.

        :returns: List of file names local to the directory.
        """
        return self._files

    def _component_state_changed(
        self,
        fault: bool | None = None,
        power: PowerState | None = None,
        files: list[str] | None = None,
    ) -> None:
        super()._component_state_changed(fault, power)

        if files is not None:
            self._process_file_changes(files)
            self._update_files(files)

    def _process_file_changes(self, files: list[str]) -> None:
        added = [file for file in files if file not in self._files]
        removed = [file for file in self._files if file not in files]

        for file in added:
            self._create_pcap_file_device(file)

        for file in removed:
            self._delete_pcap_file_device(file)

    def _update_files(self, files: list[str]) -> None:
        self._files = files
        self.push_change_event("files", files)
        self.push_archive_event("files", files)

    def _create_pcap_file_device(self, file_name: str) -> None:
        dev_name = self._get_dev_name(file_name)

        if self._is_device_defined(dev_name):
            self.logger.info("Device %s already exists, skipping device creation", dev_name)
            return

        self.logger.info("Creating device %s", dev_name)

        try:
            Util.instance().create_device(
                PCAP_FILE_DEVICE_CLASS,
                dev_name,
                cb=functools.partial(self._create_pcap_file_device_properties, file_name),
            )
        except Exception:  # pylint: disable=broad-exception-caught
            self.logger.error("Failed to create device %s", dev_name, exc_info=True)

    def _create_pcap_file_device_properties(self, file_name: str, dev_name: str) -> None:
        db = Util.instance().get_database()
        db.put_device_property(dev_name, {"pcap_file_path": [os.path.join(self.pcap_dir, file_name)]})

    def _delete_pcap_file_device(self, file_name: str) -> None:
        dev_name = self._get_dev_name(file_name)

        if not self._is_device_defined(dev_name):
            self.logger.info("Device %s does not exist, no need to remove", dev_name)
            return

        self.logger.info("Removing device %s", dev_name)
        try:
            Util.instance().delete_device(PCAP_FILE_DEVICE_CLASS, dev_name)
        except Exception:  # pylint: disable=broad-exception-caught
            self.logger.error("Failed to remove device %s", dev_name, exc_info=True)

    def _is_device_defined(self, dev_name: str) -> bool:
        util = Util.instance()
        db = util.get_database()

        devices = db.get_device_name(util.get_ds_name(), PCAP_FILE_DEVICE_CLASS)
        return dev_name in devices.value_string

    def _get_dev_name(self, file_name: str) -> str:
        return f"test/pcap-file/{file_name.lower()}"
