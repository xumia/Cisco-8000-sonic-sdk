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

#ifndef __SAI_CONSTANTS_H__
#define __SAI_CONSTANTS_H__

#include <stdint.h>

#define SAI_VERSION_CODE(a, b, c) (((a) << 16) + ((b) << 8) + (c))

namespace silicon_one
{
namespace sai
{
enum class hw_device_type_e { NONE, PACIFIC, GIBRALTAR, INVALID };
enum class port_entry_type_e { MAC = 0, PCI = 1, INTERNAL_PCI = 2, NPUH = 3, RECYCLE = 4 };

// Supported switch init mode
enum class lsai_sw_init_mode_e {
    NONE = 0, // Do not init.
    L2BRIDGE, // Default l2 bridge setup
    PORTONLY  // Create port only; this is useful for user to define bridge ports.
};

// Serdes Media Type in SI parameters files
enum class lsai_serdes_media_type_e {
    NOT_PRESENT = 0, // SDK default
    COPPER,          // cable wire or front panel port
    OPTIC,           // optic/fiber module connection
    CHIP2CHIP,       // chip-to-chip connection include fabric, ASIC, or PCB loopback.
    LOOPBACK         // Electrical loopback
};

// lsai_device class resource controls
static constexpr int NUM_QUEUE_PER_PORT = 8;

static constexpr uint32_t MAX_SAI_EGRESS_BUFFER_POOL_SIZE_PA = 64 * 1024 * 1024;
static constexpr uint32_t MAX_SAI_EGRESS_BUFFER_POOL_SIZE_GB = 108 * 1024 * 1024;
static constexpr uint32_t MAX_BUFFER_POOL_COUNT = 1;
static constexpr uint16_t BUFFER_POOL_ENTRY_SIZE = 384;
static constexpr uint32_t BUFFER_POOL_SIZE_IN_BYTES = BUFFER_POOL_ENTRY_SIZE * 1024 * 1024;

static constexpr int SAI_MAX_TAM_REPORT = 8;
static constexpr int SAI_MAX_TAM_EVENT_ACTION = 32;
static constexpr int SAI_MAX_TAM_EVENT = 256;
static constexpr int SAI_MAX_TAM = 1;

static constexpr int LSAI_MAX_ECMP_GROUPS = 8192;
static constexpr int LSAI_MAX_ECMP_GROUP_MEMBERS = 512;

// Port Speed controls
static constexpr int INJECT_PORT_SPEED = 1000;        // mbps
static constexpr int PUNT_PORT_SPEED = 1000;          // mbps
static constexpr int RECYCLE_PORT_SPEED = 1000 * 100; // mbps

// Hardware/SerDes Defines
static constexpr uint32_t IFGS_PER_SLICE = 2;      // Number of IFGs in Slice
static constexpr uint32_t HW_LANE_PIF_MASK = 0xFF; // Mask of PIF in SAI HW lane number.
static constexpr uint32_t SERDES_PREEMPHASIS_DEFAULT_VALUE = 50;
static constexpr uint32_t PORT_SERDES_ENABLE_SQUELCH_PREEM_VAL = 0; // 0 pre-emphasis value as serdes squelch is enabled.

// Packet buffers controls
static constexpr uint32_t SAI_DEFAULT_MTU_SIZE = 1514;        // SAI default MTU size (defined by SAI)
static constexpr uint32_t SOCKET_IF_DEFAULT_MTU_SIZE = 10240; // Max MTU size of interface for socket packet
static constexpr int INJECT_BUFFER_SIZE = SOCKET_IF_DEFAULT_MTU_SIZE;

// Others Defines
static constexpr float INVALID_CACHED_TEMPERATURE = -273.0;

static constexpr int BOOT_TYPE_COLD = 0;
static constexpr int BOOT_TYPE_WARM = 1;
static constexpr int BOOT_TYPE_FAST = 2;

// CRM Max Values
static constexpr uint64_t SAI_MAX_ROUTES = 450000;
static constexpr uint64_t SAI_MAX_CEM_HACK = 1000000;

static constexpr uint32_t BITS_IN_BYTE = 8;

static constexpr uint32_t LSAI_L2CP_PROFILE = 0x1;

#define SAI_ACL_KEY_PROFILE_FILE "ACL_KEY_PROFILE_FILE"

// clang-format off

/*
 *  id,
 *  {create, remove, set, get}, // implemented
 *  {create, remove, set, get}, // supported
 *  getter, getter_arg,
 *  setter, setter_arg
 */
#define SAI_ATTR_CREATE_ONLY(attr, getfunc)  \
    {attr,                                   \
     { true, false, false, true },           \
     { true, false, false, true },           \
     getfunc, (void*)attr,                   \
     nullptr, nullptr}

#define SAI_ATTR_CREATE_AND_SET(attr, getfunc, setfunc)  \
    {attr,                                               \
     { true, false, true, true },                        \
     { true, false, true, true },                        \
     getfunc, (void*)attr,                               \
     setfunc, (void*)attr}

#define SAI_ATTR_READ_ONLY(attr, getfunc)                \
    {attr,                                               \
     {false, false, false, true},                        \
     {false, false, false, true},                        \
     getfunc, (void*)attr, nullptr, nullptr},
}
}
#endif
