import tango
from ska_integration_test_harness.structure import TMCWrapper


class LowTMCWrapper(TMCWrapper):
    def is_emulated(self) -> bool:
        return False

    def tear_down(self) -> None:
        pass

    def set_subarray_id(self, subarray_id: int):
        self.subarray_node = tango.DeviceProxy(
            f"ska_low/tm_subarray_node/{subarray_id}"
        )

        # NOTE: why zfill(2) after the first DeviceProxy creation?
        subarray_id = str(subarray_id).zfill(2)

        self.csp_subarray_leaf_node = tango.DeviceProxy(
            f"ska_low/tm_leaf_node/csp_subarray{subarray_id}"
        )
        self.sdp_subarray_leaf_node = tango.DeviceProxy(
            f"ska_low/tm_leaf_node/sdp_subarray{subarray_id}"
        )
