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

#ifndef __INTERRUPT_TYPES_H__
#define __INTERRUPT_TYPES_H__

namespace silicon_one
{

/// @brief Interrupt types, based on pacific_interrupt_tree.xlsx.
enum class interrupt_type_e {
    MEM_PROTECT, ///< CIF block memory protection - ECC 1b, ECC 2b, Parity
    FIRST = MEM_PROTECT,
    ECC_1B,                    ///< ECC 1b error reported by anything other than CIF block protected memory
    ECC_2B,                    ///< ECC 2b error reported by anything other than CIF block protected memory
    MAC_LINK_DOWN,             ///< MAC link down
    LINK_DOWN,                 ///< Link down
    MISCONFIGURATION,          ///< Misconfiguration
    MAC_LINK_ERROR,            ///< MAC link error
    LINK_ERROR,                ///< Link error
    LACK_OF_RESOURCES,         ///< Lack of resources
    RESERVED_UNUSED,           ///< Reserved for future use
    THRESHOLD_CROSSED,         ///< Threshold crossed
    OTHER,                     ///< Other
    SUMMARY,                   ///< Summary
    INFORMATIVE,               ///< Informative
    DESIGN_BUG,                ///< Design bug
    NO_ERR_NOTIFICATION,       ///< No error notification
    NO_ERR_INTERNAL,           ///< No error internal (e.g. Access Engine interrupts)
    COUNTER_THRESHOLD_CROSSED, ///< Counter Threshold crossed
    CREDIT_DEV_UNREACHABLE,    ///< Credit grant destination device unreachable
    LPM_SRAM_ECC_1B,           ///< LPM shared-sram 1b ECC
    LPM_SRAM_ECC_2B,           ///< LPM shared-sram 2b ECC
    QUEUE_AGED_OUT,            ///< Queue aged out: Packets are waiting to be sent and no credits arrived
    DRAM_CORRUPTED_BUFFER,     ///< MMU has error buffer, this inidicates a 2b-ecc in HBM DRAM buffer.
    LAST = DRAM_CORRUPTED_BUFFER,
};

enum class interrupt_default_threshold_e {
    MEM_CONFIG_ECC_1B = 100,
    MEM_CONFIG_ECC_2B = 100,
    MEM_CONFIG_PARITY = 100,

    MEM_VOLATILE_ECC_1B = 100,
    MEM_VOLATILE_ECC_2B = 10,
    MEM_VOLATILE_PARITY = 10,

    LPM_SRAM_ECC_1B = 100,
    LPM_SRAM_ECC_2B = 10,
};

} // namespace silicon_one
#endif
