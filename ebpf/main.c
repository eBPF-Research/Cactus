
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-but-set-variable"

#include "tc/tc_drop.h"
#include "tc/tc_padding.h"

#include "xdp/xdp_op.h"
#include "xdp/xdp_tail_call.h"


#pragma clang diagnostic pop

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;