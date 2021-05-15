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

#ifndef __LEABA_PACKET_HEADERS_H__
#define __LEABA_PACKET_HEADERS_H__

#define SIZEOF_INJECT_HEADER_UP 17

#pragma pack(push, 1)
struct la_packet_inject_header_up {
    uint8_t bytes[SIZEOF_INJECT_HEADER_UP];
};
#pragma pack(pop)

#define INJECT_HEADER_UP_SET_TYPE(_h, _t)                                                                                          \
    do {                                                                                                                           \
        _h.bytes[0] = _t;                                                                                                          \
    } while (0)

/* write IFG-0 PIF-18 in the inject header */
#define INJECT_HEADER_UP_SET_IFG_PIF(_h, _interface)                                                                               \
    do {                                                                                                                           \
        int flip = ((_interface == 0) || (_interface == 3) || (_interface == 4)) ? 1 : 0;                                          \
        if (flip == 0) {                                                                                                           \
            _h.bytes[4] = 0x48;                                                                                                    \
        } else {                                                                                                                   \
            _h.bytes[4] = 0xc8;                                                                                                    \
        }                                                                                                                          \
    } while (0)

/* write IFG-0 PIF-24 in the inject header */
#define INJECT_HEADER_UP_SET_IFG_PIF_GIBRALTAR(_h, _interface)                                                                     \
    do {                                                                                                                           \
        int flip = ((_interface == 1) || (_interface == 2) || (_interface == 5)) ? 1 : 0;                                          \
        if (flip == 0) {                                                                                                           \
            _h.bytes[4] = 0x60;                                                                                                    \
        } else {                                                                                                                   \
            _h.bytes[4] = 0xe0;                                                                                                    \
        }                                                                                                                          \
    } while (0)

#endif // __LEABA_PACKET_HEADERS_H__
