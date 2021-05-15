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

#ifndef __LA_CSS_MEMORY_LAYOUT_H__
#define __LA_CSS_MEMORY_LAYOUT_H__

#include <stdint.h>

namespace silicon_one
{

// CSS memory is used for:
// - bootsrapping ARCs
// - storing PVT samples
// - storing a persistent token for user data
// - storing "reconnect" metadata
//
// ARC execution starts by reading jump offset from CSS offset 0. Then ARC jumps and continuous from there.
// The PVT samples, user token, and reconnect metadata are stored immediately after 0th dword.

enum class la_css_memory_layout_e : uint32_t {
    // Byte offsets
    ARC_FIRMWARE = 0x00000000,       ///< ARC firmware for all of the ARCs gets loaded here. ARC reset vector is at 0x0
    ARC_SCRATCH = 0x00040000,        /// ARC scratch area, for each ARC context
    PVT_SAMPLES = 0x00080000,        ///< PVT samples are stored starting at this offset.
    PERSISTENT_TOKEN = 0x00080100,   ///< Persistent token is stored starting at this offset.
    HEARTBEAT_SLOW = 0x00080108,     ///< Slow heartbeat counter.
    INIT_METADATA = 0x00080110,      ///< Stores device initialization metadata.
    RESERVED = 0x00080114,           ///< Reserved space.
    RECONNECT_METADATA = 0x00081004, ///< reconnect_metadata is stored starting at this offset.
    CSS_MEMORY_END = 0x00200000,     ///< End of 2 MiB CSS memory

    // Sizes
    ARC_FIRMWARE_SIZE_MAX = ARC_SCRATCH - ARC_FIRMWARE,                ///< Max size of ARC firmware
    ARC_SCRATCH_SIZE_MAX = PVT_SAMPLES - ARC_SCRATCH,                  ///< Max size of ARC scratch area
    PVT_SAMPLES_SIZE_MAX = PERSISTENT_TOKEN - PVT_SAMPLES,             ///< Max size of PVT samples.
    PERSISTENT_TOKEN_SIZE = HEARTBEAT_SLOW - PERSISTENT_TOKEN,         ///< Size of persistent token.
    HEARTBEAT_SLOW_SIZE = INIT_METADATA - HEARTBEAT_SLOW,              ///< Size of heartbeat slow.
    INIT_METADATA_SIZE = RESERVED - INIT_METADATA,                     ///< Size oof init metadata.
    RECONNECT_METADATA_SIZE_MAX = CSS_MEMORY_END - RECONNECT_METADATA, ///< Max size of reconnect metadata.
};

} // namespace silicon_one

#endif
