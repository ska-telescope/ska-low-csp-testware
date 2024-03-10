# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring

from tango import Util
from tango.server import Device, attribute, command, run

__all__ = ["Parent", "Child", "main"]


class Parent(Device):
    _counter = 0

    @command
    def spawn(self):
        self._counter += 1
        util = Util.instance()
        util.create_device("Child", f"test/child/{self._counter}")


class Child(Device):
    @attribute
    def hello(self):
        return "world"


def main(args=None, **kwargs):
    return run((Parent, Child), args=args, **kwargs)


if __name__ == "__main__":
    main()
