from typing import cast

from ska_control_model import TaskStatus
from ska_tango_base.base import check_communicating
from ska_tango_base.base.base_component_manager import BaseComponentManager, TaskCallbackType
from ska_tango_base.base.base_device import SKABaseDevice

class RackControllerComponentManager(BaseComponentManager):

    @check_communicating
    def on(self, task_callback: TaskCallbackType | None = None,) -> tuple[TaskStatus, str]:
        return TaskStatus.COMPLETED, ""
        

class RackControllerDevice(SKABaseDevice[RackControllerComponentManager]):
    
    def create_component_manager(self) -> RackControllerComponentManager:
        return RackControllerComponentManager(
            logger=self.logger,
            communication_state_callback=self._communication_state_changed,
            component_state_callback=self._component_state_changed,
        )
    
    def init_command_objects(self) -> None:
        super().init_command_objects()

    

def main(*args: str, **kwargs: str) -> int:
    """
    Entry point for module.

    :param args: positional arguments
    :param kwargs: named arguments

    :return: exit code
    """
    return cast(int, RackControllerDevice.run_server(args=args or None, **kwargs))


if __name__ == "__main__":
    main()
