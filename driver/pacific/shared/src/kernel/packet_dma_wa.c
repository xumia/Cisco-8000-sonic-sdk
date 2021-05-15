// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

/*
 * Cisco Systems, Inc.
 *
 */

#include <linux/bug.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>

#include "leaba_module.h"
#include "leaba_packet_headers.h"

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

#define NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS 0x26

struct external_eth_header_t {
    uint8_t dst[6];
    uint8_t src[6];
    uint8_t ethtype0[2];
    uint8_t dot1q[2];
    uint8_t ethtype1[2];
} __attribute__((packed)); /* 18 bytes */

#define INJECT_ETHERTYPE                                                                                                           \
    {                                                                                                                              \
        0x71, 0x03                                                                                                                 \
    }

#define SVL_ETHERTYPE                                                                                                              \
    {                                                                                                                              \
        0x71, 0x04                                                                                                                 \
    }

static const struct external_eth_header_t c_dummy_ext_inject_header = {
    {0xca, 0xfe, 0xca, 0xfe, 0xca, 0xfe}, /* dst */
    {0xde, 0xad, 0xde, 0xad, 0xde, 0xad}, /* src */
    {0x81, 0x00},                         /* ethtype0 */
    {0x51, 0x23},                         /* dot1q */
    INJECT_ETHERTYPE,                     /* ethtype1 : Inject Ethertype */
};

static const struct external_eth_header_t c_dummy_ext_eth_header = {
    {0xca, 0xfe, 0xca, 0xfe, 0xca, 0xfe}, /* dst */
    {0xde, 0xad, 0xde, 0xad, 0xde, 0xad}, /* src */
    {0x81, 0x00},                         /* ethtype0 */
    {0x51, 0x23},                         /* dot1q */
    {0x00, 0x00},                         /* ethtype1 : Next header=none */
};

static const uint8_t c_inject_ethertype[] = INJECT_ETHERTYPE;
static const uint8_t c_svl_ethertype[] = SVL_ETHERTYPE;

#define HDR_SIZE (sizeof(struct external_eth_header_t) + sizeof(struct la_packet_inject_header_up))

/* copy 8 bytes host<->device, with all the needed shuffling */
inline static void
copy_packet_qword(void* dst, const void* src)
{
    uint32_t* dst_dw = (uint32_t*)dst;
    const uint32_t* src_dw = (uint32_t*)src;

    dst_dw[0] = ntohl(src_dw[1]);
    dst_dw[1] = ntohl(src_dw[0]);
}

/* copy 16 bytes host<->device, with all the needed shuffling */
inline static void
copy_packet_dqword(uint8_t* dst, const uint8_t* src)
{
    copy_packet_qword(dst, src + sizeof(uint64_t));
    copy_packet_qword(dst + sizeof(uint64_t), src);
}

/* copy a packet host<->device */
static void
do_copy_packet(uint8_t* dst, const uint8_t* src, uint32_t len)
{
    uint32_t n = 0;

    while ((n + BYTES_IN_DWORD) < len) {
        copy_packet_dqword(dst, src);

        n += BYTES_IN_DQWORD;
        dst += BYTES_IN_DQWORD;
        src += BYTES_IN_DQWORD;
    }

    if (n < len) {
        /* surley there are BYTES_IN_QWORD accessible bytes in src even when (len-n < BYTES_IN_QWORD).
         * in case (len-n < BYTES_IN_QWORD) the tail of dst will hold garbage, which is dont-care
         * because it's out of the packet anyway */
        copy_packet_qword(dst, src);
    }
}

/* Add dummy ethernet header.
   Linux kernel rips off the VLAN tag, so to avoid deletion wrapper ether header is added.
   The packet's data and the sys_port_gid are transmitted as the packet's payload. */
void
add_dummy_vlan_tag_header_gibraltar(uint8_t* dst, const uint8_t* src)
{
    uint32_t header_size = sizeof(c_dummy_ext_eth_header);

    memcpy(dst, &c_dummy_ext_eth_header, header_size);
    dst += header_size;
    // copy the SP
    dst[0] = src[1];
    dst[1] = src[2];
}

uint32_t
add_dummy_vlan_tag_header(uint8_t* dst, const uint8_t* src)
{
    uint32_t header_size = sizeof(c_dummy_ext_eth_header);

    memcpy(dst, &c_dummy_ext_eth_header, header_size);
    dst += header_size;
    // copy the SP
    dst[0] = src[6];
    dst[1] = src[5];
    dst += 2;

    return header_size + 2;
}

/* HW-UNIT-TESTING: return the length of the dummy header in bytes */
uint32_t
get_dummy_vlan_tag_header_len()
{
    return sizeof(c_dummy_ext_eth_header) + 2;
}

/* PACKET-DMA-WA: return the max size of packet-dma workaround header in bytes */
uint32_t
get_max_packet_dma_wa_header_len()
{
    return 16;
}

static int
get_d2h_wa_header_size(const uint8_t* src, uint32_t len)
{
    if (len < BYTES_IN_DQWORD) {
        /* unexpected packet length */
        return -20;
    }

    if (src[15] == 0x10) {
        /* WA header size is 16 bytes */
        return BYTES_IN_DQWORD;
    }

    if (src[15] == 0x8) {
        /* WA header size is 8 bytes */
        return BYTES_IN_QWORD;
    }

    /* unexpected WA header */
    return -21;
}

/* copy a packet from device to host, terminating the WA header */
int
copy_packet_d2h(uint8_t* dst, const uint8_t* src, uint32_t len, bool add_test_mode_header)
{
    int header_size = get_d2h_wa_header_size(src, len);
    int actual_size = 0;

    if (header_size < 0) {
        return header_size;
    }

    if (add_test_mode_header) {
        actual_size += add_dummy_vlan_tag_header(dst, src + BYTES_IN_QWORD);
        dst += actual_size;
    }

    if (header_size == BYTES_IN_QWORD) {
        /* copy the first qword */
        copy_packet_qword(dst, src);
        dst += BYTES_IN_QWORD;
        actual_size += BYTES_IN_QWORD;
    } else if (header_size == BYTES_IN_DQWORD) {
        /* do nothing */
    } else {
        /* illegal header */
        return -10;
    }

    do_copy_packet(dst, src + BYTES_IN_DQWORD, len - BYTES_IN_DQWORD);
    actual_size += len - BYTES_IN_DQWORD;

    return actual_size;
}

/* copy a packet device->host when the cyclic buffer wraps around */
static void
do_copy_packet_with_wrap_around(uint8_t* dst, const uint8_t* src0, uint32_t len0, const uint8_t* src1, uint32_t len1)
{
    uint32_t num_of_dqwords_in_src0 = len0 / BYTES_IN_DQWORD;
    uint32_t tmp_len0 = num_of_dqwords_in_src0 * BYTES_IN_DQWORD;
    uint32_t remaining = len0 - tmp_len0;

    do_copy_packet(dst, src0, tmp_len0);
    dst += tmp_len0;
    src0 += tmp_len0;

    if (remaining == BYTES_IN_QWORD) { /* only possible values are 0 and BYTES_IN_QWORD */
        uint8_t dqword_src[BYTES_IN_DQWORD];

        /* copy 1 QWORD from src0 and 1 QWORD from src1.
         * len1>0 was checked in the caller function.
         * len1<BYTES_IN_QWORD is not a problem (see comment in do_copy_packet) */
        memcpy(dqword_src, src0, BYTES_IN_QWORD);
        memcpy(&dqword_src[BYTES_IN_QWORD], src1, BYTES_IN_QWORD);
        copy_packet_dqword(dst, dqword_src);

        src1 += BYTES_IN_QWORD;
        dst += BYTES_IN_DQWORD;
        if (len1 < BYTES_IN_QWORD) {
            len1 = 0;
        } else {
            len1 -= BYTES_IN_QWORD;
        }
    }

    do_copy_packet(dst, src1, len1);
}

/* copy a packet device->host when the cyclic buffer wraps around, terminating the WA header */
int
copy_packet_d2h_with_wrap_around(uint8_t* dst,
                                 const uint8_t* src0,
                                 uint32_t len0,
                                 const uint8_t* src1,
                                 uint32_t len1,
                                 bool add_test_mode_header)
{
    uint32_t len = 0;

    if ((len0 == 0) || (len1 == 0)) {
        /* unexpected packet length */
        return -30;
    }

    if ((len0 % BYTES_IN_QWORD) != 0) {
        /* unexpected packet length */
        return -31;
    }

    if (len0 == BYTES_IN_QWORD) {
        if (len1 < BYTES_IN_QWORD) {
            /* unexpected packet length */
            return -33;
        }

        if (src1[7] == 0x10) {
            if (add_test_mode_header) {
                len += add_dummy_vlan_tag_header(dst, src1);
                dst += len;
            }

            do_copy_packet(dst, src1 + BYTES_IN_QWORD, len1 - BYTES_IN_QWORD);

            return len1 - BYTES_IN_QWORD + len;
        }

        if (src1[7] == 0x8) {
            if (add_test_mode_header) {
                len += add_dummy_vlan_tag_header(dst, src1);
                dst += len;
            }

            /* WA header size is BYTES_IN_QWORD bytes */
            copy_packet_qword(dst, src0);
            do_copy_packet(dst + BYTES_IN_QWORD, src1 + BYTES_IN_QWORD, len1 - BYTES_IN_QWORD);

            return len1 + len;
        }

        /* unexpected WA header */
        return -34;
    }

    if (len0 == BYTES_IN_DQWORD) {
        if (src0[15] == 0x10) {
            if (add_test_mode_header) {
                len += add_dummy_vlan_tag_header(dst, src0 + BYTES_IN_QWORD);
                dst += len;
            }

            /* WA header size is BYTES_IN_DQWORD bytes */
            do_copy_packet(dst, src1, len1);

            return len1 + len;
        }

        if (src0[15] == 0x8) {
            /* WA header size is BYTES_IN_QWORD bytes */
            if (add_test_mode_header) {
                len += add_dummy_vlan_tag_header(dst, src0 + BYTES_IN_QWORD);
                dst += len;
            }

            copy_packet_qword(dst, src0);
            do_copy_packet(dst + BYTES_IN_QWORD, src1, len1);

            return BYTES_IN_QWORD + len1 + len;
        }

        /* unexpected WA header */
        return -35;
    }

    /* len0 > BYTES_IN_DQWORD */
    if (src0[15] == 0x10) {
        /* WA header size is BYTES_IN_DQWORD bytes */
        if (add_test_mode_header) {
            len += add_dummy_vlan_tag_header(dst, src0 + BYTES_IN_QWORD);
            dst += len;
        }

        do_copy_packet_with_wrap_around(dst, src0 + BYTES_IN_DQWORD, len0 - BYTES_IN_DQWORD, src1, len1);

        return len0 - BYTES_IN_DQWORD + len1 + len;
    }

    if (src0[15] == 0x8) {
        /* WA header size is BYTES_IN_QWORD bytes */
        if (add_test_mode_header) {
            len += add_dummy_vlan_tag_header(dst, src0 + BYTES_IN_QWORD);
            dst += len;
        }

        copy_packet_qword(dst, src0);
        do_copy_packet_with_wrap_around(dst + BYTES_IN_QWORD, src0 + BYTES_IN_DQWORD, len0 - BYTES_IN_DQWORD, src1, len1);

        return len0 - BYTES_IN_QWORD + len1 + len;
    }

    /* unexpected WA header */
    return -36;
}

/* check whether the given packet has an inject header */
int
is_inject_packet(const uint8_t* packet, uint32_t len)
{
    if (len < (sizeof(struct external_eth_header_t) + sizeof(c_inject_ethertype))) {
        return 0;
    }

    return ((packet[sizeof(struct external_eth_header_t) - 2] == c_inject_ethertype[0])
            && (packet[sizeof(struct external_eth_header_t) - 1] == c_inject_ethertype[1]));
}

/* check whether the given packet has an svl header */
int
is_svl_packet(const uint8_t* packet, uint32_t len)
{
    if (len < (sizeof(struct external_eth_header_t) + sizeof(c_svl_ethertype))) {
        return 0;
    }

    return ((packet[sizeof(struct external_eth_header_t) - 2] == c_svl_ethertype[0])
            && (packet[sizeof(struct external_eth_header_t) - 1] == c_svl_ethertype[1]));
}

/* check whether the given packet should have a trailer */
static int
need_trailer(uint32_t len)
{
    return (((len % BYTES_IN_DQWORD) > 0) && ((len % BYTES_IN_DQWORD) < 9));
}

/* copy the inject headers */
#define C_TMP_BUF_SIZE (4 * BYTES_IN_DQWORD)
/* in PTP flows, can add 4 extra bytes (for time stamp) after inject header. */
#define MAX_INJECT_HDR_EXTRA_BYTES 4
static uint32_t
copy_inject_headers(uint8_t* tmp_dst, const uint8_t* src, uint32_t len, uint32_t copy_size)
{
    uint8_t* tmp_p = tmp_dst;
    int with_trailer = need_trailer(len);

    /* ensure tmp_buf is large enough to hold the headers + needed trailer */
    BUILD_BUG_ON((HDR_SIZE + MAX_INJECT_HDR_EXTRA_BYTES + 1 + BYTES_IN_QWORD) > C_TMP_BUF_SIZE);

    if (len < C_TMP_BUF_SIZE) {
        /* illegal size */
        return -40;
    }

    memcpy(tmp_p, src, copy_size);
    tmp_p += copy_size;
    if (with_trailer) {
        if (g_leaba_module_debug_level > 0) {
            printk(KERN_DEBUG "%s: with trailer\n", __func__);
        }
        *(tmp_dst + HDR_SIZE - 1) += BYTES_IN_QWORD; /* last byte in the header is the trailer size */
        *(uint64_t*)tmp_p = 0;
        tmp_p += BYTES_IN_QWORD;
    }

    return (tmp_p - tmp_dst);
}

/* copy the packet's body */
static void
copy_packet_h2d_body(uint8_t* dst, const uint8_t* src, uint32_t len)
{
    uint8_t tmp_dst[BYTES_IN_DQWORD];
    const uint8_t c_padding_char = 0xcc;
    uint32_t tmp_len = -1;
    uint32_t remaining = -1;

    tmp_len = round_down(len, BYTES_IN_DQWORD);
    do_copy_packet(dst, src, tmp_len);

    /* packet tail smaller than a DQWORD should be padded */
    remaining = len - tmp_len;
    if (remaining == 0) {
        return;
    }

    src += tmp_len;
    dst += tmp_len;
    memset(tmp_dst, c_padding_char, BYTES_IN_DQWORD);
    memcpy(tmp_dst, src, remaining);
    do_copy_packet(dst, tmp_dst, BYTES_IN_DQWORD);

    return;
}

/* copy packet with inject header */
static int
copy_packet_h2d_with_inject_header(uint8_t* dst, const uint8_t* src, uint32_t len)
{
    uint8_t tmp_dst[C_TMP_BUF_SIZE];
    uint8_t* tmp_p = tmp_dst;
    // last byte of inject header indicates the amount of extra bytes added
    uint8_t copy_size = HDR_SIZE + *(src + HDR_SIZE - 1);
    uint32_t actual_hdr_bytes_nr = copy_inject_headers(tmp_dst, src, len, copy_size);
    uint32_t remaining = C_TMP_BUF_SIZE - actual_hdr_bytes_nr;
    int actual_size = len - copy_size + actual_hdr_bytes_nr;

    if ((signed)actual_hdr_bytes_nr < 0) {
        return actual_hdr_bytes_nr;
    }

    src += copy_size;
    len -= copy_size;
    tmp_p += C_TMP_BUF_SIZE - remaining;

    memcpy(tmp_p, src, remaining);
    src += remaining;
    len -= remaining;

    do_copy_packet(dst, tmp_dst, C_TMP_BUF_SIZE);
    dst += C_TMP_BUF_SIZE;

    copy_packet_h2d_body(dst, src, len);

    return actual_size;
}

void
get_inject_header(uint8_t* buf, uint32_t interface, int is_gibraltar)
{
    struct la_packet_inject_header_up inj_hdr;

    memset(&inj_hdr, 0, sizeof(inj_hdr));
    INJECT_HEADER_UP_SET_TYPE(inj_hdr, NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS);
    if (!is_gibraltar) {
        INJECT_HEADER_UP_SET_IFG_PIF(inj_hdr, interface);
    } else {
        INJECT_HEADER_UP_SET_IFG_PIF_GIBRALTAR(inj_hdr, interface);
    }

    memcpy(buf, &c_dummy_ext_inject_header, sizeof(c_dummy_ext_inject_header));
    memcpy(buf + sizeof(c_dummy_ext_inject_header), &inj_hdr, sizeof(inj_hdr));
}

uint32_t
get_inject_headers_len()
{
    return sizeof(struct la_packet_inject_header_up) + sizeof(c_dummy_ext_inject_header);
}

/* copy packet with inject header */
static int
copy_packet_h2d_without_inject_header(uint8_t* dst, const uint8_t* src, uint32_t len, uint32_t interface)
{
    uint8_t tmp_dst[C_TMP_BUF_SIZE];
    uint8_t tmp_src[C_TMP_BUF_SIZE];
    uint8_t* tmp_p = tmp_dst;
    int actual_size;
    uint32_t remaining;
    uint32_t actual_hdr_bytes_nr;

    get_inject_header(tmp_src, interface, 0 /*is_gibraltar*/);
    actual_hdr_bytes_nr = copy_inject_headers(tmp_dst, tmp_src, len + HDR_SIZE, HDR_SIZE);

    if (g_leaba_module_debug_level > 0) {
        char dbg_buff[512];
        char* p = dbg_buff;
        int remaining = sizeof(dbg_buff);
        unsigned int jj;
        for (jj = 0; jj < actual_hdr_bytes_nr; jj++) {
            size_t curlen;
            snprintf(p, remaining, "%02x ", tmp_dst[jj]);
            curlen = strlen(p);
            remaining -= curlen;
            if (remaining <= 0)
                break;
            p += curlen;
        }

        printk(KERN_DEBUG "%s: HDR_SIZE=%lu actual_hdr_bytes_nr=%u data=%s\n", __func__, HDR_SIZE, actual_hdr_bytes_nr, dbg_buff);
    }

    if (actual_hdr_bytes_nr == (uint32_t)-1) {
        return -1;
    }

    remaining = C_TMP_BUF_SIZE - actual_hdr_bytes_nr;
    tmp_p += actual_hdr_bytes_nr;

    memcpy(tmp_p, src, remaining);
    src += remaining;
    len -= remaining;
    actual_size = C_TMP_BUF_SIZE + len;
    do_copy_packet(dst, tmp_dst, C_TMP_BUF_SIZE);
    dst += C_TMP_BUF_SIZE;

    copy_packet_h2d_body(dst, src, len);

    return actual_size;
}

/* copy packet from host to device */
int
copy_packet_h2d(uint8_t* dst, const uint8_t* src, uint32_t len, uint32_t interface)
{
    if (is_inject_packet(src, len) || is_svl_packet(src, len)) {
        return copy_packet_h2d_with_inject_header(dst, src, len);
    }

    return copy_packet_h2d_without_inject_header(dst, src, len, interface);
}
