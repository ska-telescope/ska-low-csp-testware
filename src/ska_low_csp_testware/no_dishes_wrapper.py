from ska_integration_test_harness.config.components_config import DishesConfiguration
from ska_integration_test_harness.structure import DishesWrapper


class NoDishesWrapper(DishesWrapper):
    def is_emulated(self) -> bool:
        return True

    def _pre_init_dish_names(self, dishes_configuration: DishesConfiguration) -> None:
        pass

    def clear_command_call(self) -> None:
        pass

    def tear_down(self) -> None:
        pass
