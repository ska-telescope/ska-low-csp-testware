# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring

from logging import Logger
from typing import Any

from ska_control_model import PowerState, ResultCode
from ska_tango_base.base import SKABaseDevice
from ska_tango_base.commands import FastCommand, SubmittedSlowCommand
from tango.server import attribute, command, device_property

from ska_low_csp_testware.pcap_file_component_manager import PcapFileComponentManager
from ska_low_csp_testware.pcap_file_metadata import PcapFileMetadata

__all__ = ["PcapFileDevice"]


class PcapFileDevice(SKABaseDevice[PcapFileComponentManager]):
    pcap_file_path: str = device_property()  # type: ignore

    def __init__(self, *args, **kwargs):
        self._metadata: PcapFileMetadata | None = None
        self._file_time_modified = 0
        self._file_size = 0
        super().__init__(*args, **kwargs)

    def create_component_manager(self) -> PcapFileComponentManager:
        return PcapFileComponentManager(
            pcap_file_path=self.pcap_file_path,
            logger=self.logger,
            communication_state_callback=self._communication_state_changed,
            component_state_callback=self._component_state_changed,
            metadata=self._metadata,
            file_time_created=self._file_time_created,
            file_time_modified=self._file_time_modified,
            file_size=self._file_size,
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

    @attribute(
        label="File size",
        unit="byte",
        standard_unit="byte",
        display_unit="byte",
    )
    def file_size(self) -> int:
        return self._file_size

    @attribute(
        label="File modification time",
        unit="ns",
        standard_unit="s",
        display_unit="ns",
    )
    def file_time_modified(self) -> int:
        return self._file_time_modified

    @attribute(label="Number of SPEAD heaps")
    def heap_count(self) -> int:
        if self._metadata:
            return self._metadata.heap_count

        raise ValueError("Metadata not available")

    @attribute(label="SPEAD header contents")
    def spead_headers(self) -> str:
        if self._metadata:
            return self._metadata.spead_headers.to_json()

        raise ValueError("Metadata not available")

    @command
    def Delete(self) -> None:  # pylint: disable=invalid-name
        handler = self.get_command_object("Delete")
        handler()

    @command(dtype_out="DevVarLongStringArray", doc_out="Tuple containing the result code and corresponding message")
    def Load(self) -> tuple[list[ResultCode], list[str]]:  # pylint: disable=invalid-name
        handler = self.get_command_object("Load")
        result, message = handler()
        return [result], [message]

    def _update_attr(self, attr_name: str, attr_value: Any) -> None:
        setattr(self, f"_{attr_name}", attr_value)
        self.push_change_event(attr_name, attr_value)
        self.push_archive_event(attr_name, attr_value)

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
        **state,
    ) -> None:
        super()._component_state_changed(fault, power)

        if metadata:
            self._update_metadata(metadata)

        for state_attr in ["file_size", "file_time_modified"]:
            if state_attr in state:
                self._update_attr(state_attr, state[state_attr])
