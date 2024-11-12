from ska_control_model import ObsState
from ska_integration_test_harness.actions.command_action import (
    TransientQuiescentCommandAction,
)
from ska_integration_test_harness.actions.expected_event import (
    ExpectedEvent,
    ExpectedStateChange,
)
from ska_integration_test_harness.inputs import JSONInput


class AssignResources(TransientQuiescentCommandAction):
    def __init__(self, input: JSONInput):
        super().__init__()
        self.input = input
        self.termination_condition_timeout = (
            5 + self.telescope.csp.csp_subarray.commandTimeout
        )

    def _action(self):
        self._log("Invoking AssignResources on CSP Subarray")
        self.telescope.csp.csp_subarray.AssignResources(self.input.as_str())

    def termination_condition_for_transient_state(self) -> list[ExpectedEvent]:
        return [
            ExpectedStateChange(
                self.telescope.csp.csp_subarray, "obsState", ObsState.RESOURCING
            )
        ]

    def termination_condition_for_quiescent_state(self) -> list[ExpectedEvent]:
        return [
            ExpectedStateChange(
                self.telescope.csp.csp_subarray, "obsState", ObsState.IDLE
            )
        ]
