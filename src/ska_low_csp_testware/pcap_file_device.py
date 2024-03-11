# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,broad-exception-caught

import pandas
from ska_control_model import PowerState, ResultCode
from ska_tango_base.base import SKABaseDevice
from ska_tango_base.commands import SubmittedSlowCommand
from tango.server import attribute, command, device_property

from ska_low_csp_testware.pcap_file_component_manager import PcapFileComponentManager

__all__ = ["PcapFileDevice"]


class PcapFileDevice(SKABaseDevice):
    pcap_file_path: str = device_property()  # type: ignore

    def __init__(self, *args, **kwargs):
        self._metadata: pandas.DataFrame | None = None
        super().__init__(*args, **kwargs)

    def create_component_manager(self) -> PcapFileComponentManager:
        return PcapFileComponentManager(
            pcap_file_path=self.pcap_file_path,
            logger=self.logger,
            communication_state_callback=self._communication_state_changed,
            component_state_callback=self._component_state_changed,
            metadata=self._metadata,
        )

    def init_command_objects(self) -> None:
        super().init_command_objects()

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
    def metadata(self) -> str:
        if self._metadata is None:
            return "{}"

        return self._metadata.to_json()

    @command(dtype_out="DevVarLongStringArray")
    def Load(self) -> tuple[list[ResultCode], list[str]]:  # pylint: disable=invalid-name
        handler = self.get_command_object("Load")
        result, message = handler()
        return [result], [message]

    def _update_metadata(self, metadata: pandas.DataFrame) -> None:
        self._metadata = metadata
        self.push_change_event("metadata", metadata)
        self.push_archive_event("metadata", metadata)

    def _component_state_changed(
        self,
        fault: bool | None = None,
        power: PowerState | None = None,
        metadata: pandas.DataFrame | None = None,
    ) -> None:
        super()._component_state_changed(fault, power)

        if metadata is not None:
            self._update_metadata(metadata)
