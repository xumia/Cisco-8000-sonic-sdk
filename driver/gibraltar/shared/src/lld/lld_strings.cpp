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

#include "lld/lld_strings.h"
#include "common/gen_utils.h"

namespace silicon_one
{

std::string
to_string(lld_memory_type_e memory_type)
{
    static const char* strs[] = {
            [(int)lld_memory_type_e::CONFIG] = "CONFIG",
            [(int)lld_memory_type_e::DYNAMIC] = "DYNAMIC",
            [(int)lld_memory_type_e::DOC_ONLY] = "DOC_ONLY",
    };

    if ((size_t)memory_type < array_size(strs)) {
        return strs[(size_t)memory_type];
    }

    return "Unknown memory type";
}

std::string
to_string(lld_memory_subtype_e memory_subtype)
{
    static const char* strs[] = {
            [(int)lld_memory_subtype_e::NONE] = "NONE",
            [(int)lld_memory_subtype_e::X_Y_TCAM] = "X_Y_TCAM",
            [(int)lld_memory_subtype_e::KEY_MASK_TCAM] = "KEY_MASK_TCAM",
            [(int)lld_memory_subtype_e::REG_TCAM] = "REG_TCAM",
            [(int)lld_memory_subtype_e::REG_CAM] = "REG_CAM",
    };

    if ((size_t)memory_subtype < array_size(strs)) {
        return strs[(size_t)memory_subtype];
    }

    return "Unknown memory sub-type";
}

std::string
to_string(lld_memory_protection_e memory_protection)
{
    static const char* strs[] = {
            [(int)lld_memory_protection_e::NONE] = "NONE",
            [(int)lld_memory_protection_e::ECC] = "ECC",
            [(int)lld_memory_protection_e::EXT_ECC] = "EXT_ECC",
            [(int)lld_memory_protection_e::PARITY] = "PARITY",
            [(int)lld_memory_protection_e::EXT_PARITY] = "EXT_PARITY",
    };

    if ((size_t)memory_protection < array_size(strs)) {
        return strs[(size_t)memory_protection];
    }

    return "Unknown memory sub-type";
}

std::string
to_string(interrupt_type_e type)
{
    static const char* strs[] = {
            [(int)interrupt_type_e::MEM_PROTECT] = "MEM_PROTECT",
            [(int)interrupt_type_e::ECC_1B] = "ECC_1B",
            [(int)interrupt_type_e::ECC_2B] = "ECC_2B",
            [(int)interrupt_type_e::MAC_LINK_DOWN] = "MAC_LINK_DOWN",
            [(int)interrupt_type_e::LINK_DOWN] = "LINK_DOWN",
            [(int)interrupt_type_e::MISCONFIGURATION] = "MISCONFIGURATION",
            [(int)interrupt_type_e::MAC_LINK_ERROR] = "MAC_LINK_ERROR",
            [(int)interrupt_type_e::LINK_ERROR] = "LINK_ERROR",
            [(int)interrupt_type_e::LACK_OF_RESOURCES] = "LACK_OF_RESOURCES",
            [(int)interrupt_type_e::RESERVED_UNUSED] = "RESERVED_UNUSED",
            [(int)interrupt_type_e::THRESHOLD_CROSSED] = "THRESHOLD_CROSSED",
            [(int)interrupt_type_e::OTHER] = "OTHER",
            [(int)interrupt_type_e::SUMMARY] = "SUMMARY",
            [(int)interrupt_type_e::INFORMATIVE] = "INFORMATIVE",
            [(int)interrupt_type_e::DESIGN_BUG] = "DESIGN_BUG",
            [(int)interrupt_type_e::NO_ERR_NOTIFICATION] = "NO_ERR_NOTIFICATION",
            [(int)interrupt_type_e::NO_ERR_INTERNAL] = "NO_ERR_INTERNAL",
            [(int)interrupt_type_e::COUNTER_THRESHOLD_CROSSED] = "COUNTER_THRESHOLD_CROSSED",
            [(int)interrupt_type_e::CREDIT_DEV_UNREACHABLE] = "CREDIT_DEV_UNREACHABLE",
            [(int)interrupt_type_e::LPM_SRAM_ECC_1B] = "LPM_SRAM_ECC_1B",
            [(int)interrupt_type_e::LPM_SRAM_ECC_2B] = "LPM_SRAM_ECC_2B",
            [(int)interrupt_type_e::QUEUE_AGED_OUT] = "QUEUE_AGED_OUT",
            [(int)interrupt_type_e::DRAM_CORRUPTED_BUFFER] = "DRAM_CORRUPTED_BUFFER",
    };

    static_assert(array_size(strs) == (size_t)interrupt_type_e::LAST + 1, "");

    if ((size_t)type < array_size(strs)) {
        return strs[(size_t)type];
    }

    return "Unknown interrupt type";
}

std::string
to_string(init_stage_e init_stage)
{
    static const char* strs[]
        = {[(size_t)init_stage_e::PRE_SOFT_RESET] = "PRE_SOFT_RESET", [(size_t)init_stage_e::POST_SOFT_RESET] = "POST_SOFT_RESET"};

    if ((size_t)init_stage < array_size(strs)) {
        return strs[(size_t)init_stage];
    }

    return "Unknown init stage";
}

std::string
to_string(init_expression_slice_mode_e init_mode)
{
    static const char* strs[] = {[to_utype(init_expression_slice_mode_e::INIT_VALUE_SA)] = "INIT_VALUE_SA",
                                 [to_utype(init_expression_slice_mode_e::INIT_VALUE_LC_NWK)] = "INIT_VALUE_LC_NWK",
                                 [to_utype(init_expression_slice_mode_e::INIT_VALUE_LC_FAB)] = "INIT_VALUE_LC_FAB",
                                 [to_utype(init_expression_slice_mode_e::INIT_VALUE_FE)] = "INIT_VALUE_FE",
                                 [to_utype(init_expression_slice_mode_e::SLICE_OUT_OF_RANGE)] = "SLICE_OUT_OF_RANGE"};

    if ((size_t)init_mode < array_size(strs)) {
        return strs[(size_t)init_mode];
    }

    return "Unknown init mode";
}

} // namespace silicon_one
