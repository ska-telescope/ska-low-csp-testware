from ska_integration_test_harness.structure import CSPWrapper
from tango import DeviceProxy, DevState

from ska_low_csp_testware.actions import AdminModeOffline, AdminModeOnline


class LowCSPWrapper(CSPWrapper):
    def is_emulated(self) -> bool:
        return False

    def move_to_on(self) -> None:
        if self.csp_master.state == DevState.DISABLE:
            action = AdminModeOnline()
            action.set_termination_condition_timeout(60)
            action.execute()

    def move_to_off(self) -> None:
        if self.csp_master.state != DevState.DISABLE:
            action = AdminModeOffline()
            action.set_termination_condition_timeout(60)
            action.execute()

    def set_subarray_id(self, subarray_id: str):
        subarray_id = str(subarray_id).zfill(2)
        self.csp_subarray = DeviceProxy(f"low-csp/subarray/{subarray_id}")

    def clear_command_call(self) -> None:
        pass

    def tear_down(self) -> None:
        pass
