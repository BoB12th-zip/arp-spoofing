#pragma once

#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    Ip sip_;
    Ip dip_;

    Ip sip() { return sip_; }
    Ip dip() { return dip_; }
    
};
#pragma pack(pop)