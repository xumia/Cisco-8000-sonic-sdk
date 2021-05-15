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

#include "device_simulator/dsim_common/packet_dma_defs.h"
#include "device_simulator/dsim_common/socket_connection.h"

#if defined(__linux__)
#include <arpa/inet.h>
#endif

// copy 8 bytes host<->device, with all the needed shuffling
void
copy_packet_qword(void* dst, const void* src)
{
    uint32_t* dst_dw = (uint32_t*)dst;
    const uint32_t* src_dw = (const uint32_t*)src;

    dst_dw[0] = ntohl(src_dw[1]);
    dst_dw[1] = ntohl(src_dw[0]);
}

// copy 16 bytes host<->device, with all the needed shuffling
void
copy_packet_dqword(void* dst, const void* src)
{
    copy_packet_qword(dst, (uint8_t*)src + sizeof(uint64_t));
    copy_packet_qword((uint8_t*)dst + sizeof(uint64_t), src);
}

// copy a packet host<->device
void
do_copy_packet(uint8_t* dst, const uint8_t* src, uint32_t len)
{
    uint32_t n = 0;

    while ((n + BYTES_IN_QWORD) < len) {
        copy_packet_dqword(dst, src);

        n += BYTES_IN_DQWORD;
        dst += BYTES_IN_DQWORD;
        src += BYTES_IN_DQWORD;
    }

    if (n < len) {
        // surely there are BYTES_IN_QWORD accessible bytes in src even when (len-n < BYTES_IN_QWORD).
        // in case (len-n < BYTES_IN_QWORD) the tail of dst will hold garbage, which is dont-care
        // because it's out of the packet anyway
        copy_packet_qword(dst, src);
    }
}

// copy a packet device <-> host
// Used for Pacific bug simulation
int
copy_packet_with_data_reordering(uint8_t* dst, const uint8_t* src, uint32_t len)
{
    do_copy_packet(dst, src, len);
    return len;
}
