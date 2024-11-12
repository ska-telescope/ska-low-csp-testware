from ska_control_model import ObsState
from ska_integration_test_harness.actions.command_action import (
    TransientQuiescentCommandAction,
)
from ska_integration_test_harness.actions.expected_event import (
    ExpectedEvent,
    ExpectedStateChange,
)


class Abort(TransientQuiescentCommandAction):
    def __init__(self):
        super().__init__()
        self.termination_condition_timeout = (
            5 + self.telescope.csp.csp_subarray.commandTimeout
        )

    def _action(self):
        self._log("Invoking Abort on CSP Subarray")
        self.telescope.csp.csp_subarray.Abort()

    def termination_condition_for_transient_state(self) -> list[ExpectedEvent]:
        return [
            ExpectedStateChange(
                self.telescope.csp.csp_subarray, "obsState", ObsState.ABORTING
            )
        ]

    def termination_condition_for_quiescent_state(self) -> list[ExpectedEvent]:
        return [
            ExpectedStateChange(
                self.telescope.csp.csp_subarray, "obsState", ObsState.ABORTED
            )
        ]
