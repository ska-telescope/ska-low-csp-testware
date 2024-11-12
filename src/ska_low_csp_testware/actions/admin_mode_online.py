from ska_control_model import AdminMode
from ska_integration_test_harness.actions import TelescopeAction
from ska_integration_test_harness.actions.expected_event import (
    ExpectedEvent,
    ExpectedStateChange,
)
from tango import DevState


class AdminModeOnline(TelescopeAction[None]):
    def _action(self):
        self.telescope.csp.csp_master.adminMode = AdminMode.ONLINE

    def termination_condition(self) -> list[ExpectedEvent]:
        return [
            ExpectedStateChange(self.telescope.csp.csp_master, "state", DevState.ON),
            ExpectedStateChange(self.telescope.csp.csp_subarray, "state", DevState.ON),
            ExpectedStateChange(
                self.telescope.csp.csp_master, "cspCbfState", DevState.ON
            ),
            ExpectedStateChange(
                self.telescope.csp.csp_subarray, "cbfSubarrayState", DevState.ON
            ),
            ExpectedStateChange(
                self.telescope.csp.csp_master, "cspCbfAdminMode", AdminMode.ONLINE
            ),
            ExpectedStateChange(
                self.telescope.csp.csp_subarray,
                "cbfSubarrayAdminMode",
                AdminMode.ONLINE,
            ),
        ]
