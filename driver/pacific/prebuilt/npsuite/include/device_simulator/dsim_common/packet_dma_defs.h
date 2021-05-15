// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __PACKET_DMA_DEFS__
#define __PACKET_DMA_DEFS__

#include <stdint.h>
#include <limits.h>

#define SBIF_BLOCK_ID 707

#ifdef __GNUC__
#define PACKED(class_to_pack) class_to_pack __attribute__((__packed__))
#else
#define PACKED(class_to_pack) __pragma(pack(push, 1)) class_to_pack __pragma(pack(pop))
#endif

#ifndef CHAR_BIT
#define CHAR_BIT 8 /* Normally in <limits.h> */
#endif

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#ifndef MAX
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#endif

#define ALIGN(_v, _a) (((_v) + (_a)-1) & ~((_a)-1))
#define BUFFER_PTR_ALIGNMENT 8
#define MIN_PACKET_SIZE (64) // bytes

#define DESC_BUFFER_WRAP_BIT (1 << 16)
#define DATA_BUFFER_WRAP_BIT (1 << 31)

// hold description of packets transfered between the host and device - 16 bytes
#define PD_SIZE_FIELD_BITS_NR 14
#define PD_ERR_FIELD_BITS_NR 1
#define PD_EOP_FIELD_BITS_NR 1
PACKED(struct dma_packet_descriptor_t {
    uint64_t phys_addr;
    union {
        struct {
            uint64_t size : PD_SIZE_FIELD_BITS_NR;
            uint64_t err : PD_ERR_FIELD_BITS_NR;
            uint64_t eop : PD_EOP_FIELD_BITS_NR;
            uint64_t padding1 : sizeof(uint64_t) * CHAR_BIT - (PD_SIZE_FIELD_BITS_NR + PD_ERR_FIELD_BITS_NR + PD_EOP_FIELD_BITS_NR);
        };
        uint64_t size_err;
    };
});

enum device_e {
    DEVICE_TYPE_PACIFIC,
    DEVICE_TYPE_GIBRALTAR,
    DEVICE_TYPE_NONE,
};

#define DESC_BUFFER_ELEMENT_SIZE_BYTES sizeof(struct dma_packet_descriptor_t)
#define MAX_DATA_BUFFER_ELEMENT_SIZE_BYTES (10 * 1024)
#define MAX_DATA_BUFFER_DMA_CTX 12

#ifndef BYTES_IN_DWORD
#define BYTES_IN_DWORD sizeof(uint32_t)
#endif

#ifndef DWORDS_IN_QWORD
#define DWORDS_IN_QWORD 2
#endif

#ifndef DWORDS_IN_DQWORD
#define DWORDS_IN_DQWORD 4
#endif

#ifndef BYTES_IN_QWORD
#define BYTES_IN_QWORD (BYTES_IN_DWORD * DWORDS_IN_QWORD)
#endif

#ifndef BYTES_IN_DQWORD
#define BYTES_IN_DQWORD (BYTES_IN_DWORD * DWORDS_IN_DQWORD)
#endif

// copy 8 bytes host<->device, with all the needed shuffling
void copy_packet_qword(void* dst, const void* src);

// copy 16 bytes host<->device, with all the needed shuffling
void copy_packet_dqword(void* dst, const void* src);

// copy a packet host<->device
void do_copy_packet(uint8_t* dst, const uint8_t* src, uint32_t len);

// copy a packet device <-> host
// Used for Pacific bug simulation
int copy_packet_with_data_reordering(uint8_t* dst, const uint8_t* src, uint32_t len);

#endif
