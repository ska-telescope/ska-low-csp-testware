# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,broad-exception-caught

from logging import Logger
from typing import Any

from ska_control_model import PowerState, ResultCode
from ska_tango_base.base import SKABaseDevice
from ska_tango_base.commands import FastCommand, SubmittedSlowCommand
from tango.server import attribute, command, device_property

from ska_low_csp_testware.pcap_file_component_manager import PcapFileComponentManager
from ska_low_csp_testware.pcap_file_metadata import PcapFileMetadata

__all__ = ["PcapFileDevice"]


class PcapFileDevice(SKABaseDevice):
    pcap_file_path: str = device_property()  # type: ignore

    def __init__(self, *args, **kwargs):
        self._metadata: PcapFileMetadata | None = None
        super().__init__(*args, **kwargs)

    def create_component_manager(self) -> PcapFileComponentManager:
        return PcapFileComponentManager(
            pcap_file_path=self.pcap_file_path,
            logger=self.logger,
            communication_state_callback=self._communication_state_changed,
            component_state_callback=self._component_state_changed,
            metadata=self._metadata,
        )

    class DeleteCommand(FastCommand[None]):
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

    @attribute
    def heap_count(self) -> int:
        if self._metadata:
            return self._metadata.heap_count

        return -1

    @attribute
    def spead_headers(self) -> str:
        if self._metadata:
            return self._metadata.spead_headers.to_json()

        return "{}"

    @command
    def Delete(self) -> None:  # pylint: disable=invalid-name
        handler = self.get_command_object("Delete")
        handler()

    @command(dtype_out="DevVarLongStringArray")
    def Load(self) -> tuple[list[ResultCode], list[str]]:  # pylint: disable=invalid-name
        handler = self.get_command_object("Load")
        result, message = handler()
        return [result], [message]

    def is_Off_allowed(self) -> bool:
        return False

    def is_On_allowed(self) -> bool:
        return False

    def is_Reset_allowed(self) -> bool:
        return False

    def is_Standby_allowed(self) -> bool:
        return False

    def _update_metadata(self, metadata: PcapFileMetadata) -> None:
        self._metadata = metadata

        heap_count = metadata.heap_count
        self.push_change_event("heap_count", heap_count)
        self.push_archive_event("heap_count", heap_count)

        spead_headers = metadata.spead_headers.to_json()
        self.push_change_event("spead_headers", spead_headers)
        self.push_archive_event("spead_headers", spead_headers)

    def _component_state_changed(
        self,
        fault: bool | None = None,
        power: PowerState | None = None,
        metadata: PcapFileMetadata | None = None,
    ) -> None:
        super()._component_state_changed(fault, power)

        if metadata:
            self._update_metadata(metadata)
