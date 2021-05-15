// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#ifndef __SRM_SERDES_ADDRESS_H__
#define __SRM_SERDES_ADDRESS_H__

namespace silicon_one
{

//  In SRM API, 'die' is a semi-opaque 32 bit value that should identify the SerDes on a device in the system.
//  Lower 8 bits are reserved by SRM.
//  Higher 24bit are free for custom use.
//
//  Addressing scheme:
//
//  Bit 30-31:  Select addressing mode (default 0 gives a single SerDes die).
//  Bits 25-29: Reserved for future expansion.
//  Bits 16-24: Select device ID, support up to 512 devices on a system.
//  Bit 13-15:  Select Slice 0-5.
//  Bit 12:     Select IFG 0-1.
//  Bits 8-11:  Select SerDes die 0-11 (each die shares 2 channels/lanes).
//  Bits 0-7:   Reserved by SRM, used to specify the SerDes within the package (0 or 1).

/// @brief SRM SerDes address.
union srm_serdes_address {
    struct fields_s {
        uint32_t serdes_index : 8;    // [7:0]
        uint32_t serdes_package : 4;  // [11:8]
        uint32_t ifg : 1;             // [12]
        uint32_t slice : 3;           // [15:13]
        uint32_t device_id : 9;       // [16:24]
        uint32_t reserved : 5;        // [25:29]
        uint32_t addressing_mode : 2; // [30:31]
    } fields;
    uint32_t u32;
};

#ifndef SWIG
static_assert(sizeof(srm_serdes_address) == sizeof(uint32_t), "size must be 4 bytes");
#endif

enum class srm_serdes_addressing_mode_e {
    SERDES = 0, ///< srm_serdes_address targets an individual device/slice/ifg/serdes_pool/package.
    IFG,        ///< srm_serdes_address targets all serdeses in device/slice/ifg/serdes_pool/*.
    DEVICE,     ///< srm_serdes_address targets all serdeses dies in a device.
};

} // namespace silicon_one

#endif
