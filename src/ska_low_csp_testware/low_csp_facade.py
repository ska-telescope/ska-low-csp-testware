from typing import Any

from ska_integration_test_harness.actions import TelescopeAction
from ska_integration_test_harness.inputs import JSONInput
from ska_integration_test_harness.structure import TelescopeWrapper

from ska_low_csp_testware.actions import (
    Abort,
    AdminModeOffline,
    AdminModeOnline,
    AssignResources,
    Configure,
    Restart,
)


class LowCSPFacade:
    def __init__(self, telescope: TelescopeWrapper):
        self.telescope = telescope

    def set_subarray_id(self, subarray_id: int):
        self.telescope.set_subarray_id(subarray_id)

    def _execute_action(
        self,
        action: TelescopeAction[Any],
        wait: bool = True,
        timeout: float | None = None,
    ):
        action.set_termination_condition_policy(wait=wait)
        if timeout is not None:
            action.set_termination_condition_timeout(timeout=timeout)
        action.execute()

    def admin_mode_online(
        self,
        wait: bool = True,
        timeout: float | None = None,
    ):
        self._execute_action(
            action=AdminModeOnline(),
            wait=wait,
            timeout=timeout,
        )

    def admin_mode_offline(
        self,
        wait: bool = True,
        timeout: float | None = None,
    ):
        self._execute_action(
            action=AdminModeOffline(),
            wait=wait,
            timeout=timeout,
        )

    def assign_resources(
        self,
        input: JSONInput,
        wait: bool = True,
        timeout: float | None = None,
    ):
        self._execute_action(
            action=AssignResources(input),
            wait=wait,
            timeout=timeout,
        )

    def configure(
        self,
        input: JSONInput,
        wait: bool = True,
        timeout: float | None = None,
    ):
        self._execute_action(
            action=Configure(input),
            wait=wait,
            timeout=timeout,
        )

    def abort(
        self,
        wait: bool = True,
        timeout: float | None = None,
    ):
        self._execute_action(
            action=Abort(),
            wait=wait,
            timeout=timeout,
        )

    def restart(
        self,
        wait: bool = True,
        timeout: float | None = None,
    ):
        self._execute_action(
            action=Restart(),
            wait=wait,
            timeout=timeout,
        )
