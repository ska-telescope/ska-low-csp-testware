"""
Entrypoint for the ``pcap_file_monitor`` TANGO device server.
"""

from tango.server import run

from ska_low_csp_testware.pcap_file_device import PcapFile
from ska_low_csp_testware.pcap_file_monitor_device import PcapFileMonitor


def main(args=None, **kwargs):  # pylint: disable=missing-function-docstring
    return run((PcapFileMonitor, PcapFile), args=args, **kwargs)


if __name__ == "__main__":
    main()
