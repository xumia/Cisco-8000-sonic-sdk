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

#ifndef __LEABA_LLD_UTILS_H__
#define __LEABA_LLD_UTILS_H__

#include <list>
#include <stdint.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "common/bit_vector.h"
#include "common/logger.h"
#include "lld/ll_device.h"
#include "lld/lld_fwd.h"
#include "lld/lld_memory.h"
#include "lld/lld_register.h"

namespace silicon_one
{
/// @brief Leaba register and value pair
typedef std::pair<lld_register_scptr, bit_vector> lld_register_value_pair_t;

/// @brief List of Leaba register and value pairs
typedef std::list<lld_register_value_pair_t> lld_register_value_list_t;

/// @brief Leaba memory and value pair
typedef std::pair<lld_memory_scptr, bit_vector> lld_memory_value_pair_t;

/// @brief List of Leaba memory and value pairs
typedef std::list<lld_memory_value_pair_t> lld_memory_value_list_t;

/// @brief Leaba memory and line pair
typedef std::pair<lld_memory_scptr, size_t> lld_memory_line_pair_t;

/// @brief Leaba memory and line paired with value
typedef std::pair<lld_memory_line_pair_t, bit_vector> lld_memory_line_value_pair_t;

/// @brief List of Leaba memory, line and value pairs
typedef std::list<lld_memory_line_value_pair_t> lld_memory_line_value_list_t;

/// @brief Tcam entry value
typedef std::pair<bit_vector, bit_vector> tcam_entry_value_t;

/// @brief Tcam entry paired with its value
typedef std::pair<lld_memory_line_pair_t, tcam_entry_value_t> tcam_line_value_pair_t;

/// @brief List of Tcam memories, line and value pairs
typedef std::list<tcam_line_value_pair_t> tcam_line_value_list_t;

/// @brief List of memory-lines and registers. Allows orderly interleaving writes.
struct lld_reg_mem_line {
    bool is_register;
    lld_memory_line_pair_t mem_line;
    lld_register_scptr reg;

    lld_reg_mem_line(lld_register_scptr r) : is_register(true), reg(r)
    {
    }
    lld_reg_mem_line(lld_memory_scptr mem, size_t line) : is_register(false), mem_line(std::make_pair(mem, line))
    {
    }
};
typedef std::pair<lld_reg_mem_line, bit_vector> lld_reg_mem_line_value_t;
typedef std::list<lld_reg_mem_line_value_t> lld_reg_mem_line_value_list_t;

/// @brief Write list of register instances and values.
///
/// @param[in]  device              Low level device to use.
/// @param[in]  reg_val_list        List of register and value pairs.
///
/// @retval     LA_STATUS_SUCCESS   Command completed successfully.
/// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
/// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
la_status lld_write_register_list(ll_device_sptr device, const lld_register_value_list_t& reg_val_list);

/// @brief Write list of memory instances and values.
///
/// @param[in]  device              Low level device to use.
/// @param[in]  mem_val_list        List of memory and value pairs.
///
/// @retval     LA_STATUS_SUCCESS   Command completed successfully.
/// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
/// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
la_status lld_write_memory_list(ll_device_sptr device, const lld_memory_value_list_t& mem_val_list);

/// @brief Write list of memory entries and values.
///
/// @param[in]  device              Low level device to use.
/// @param[in]  mem_line_val_list   List of memory, line and value pairs.
///
/// @retval     LA_STATUS_SUCCESS   Command completed successfully.
/// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
/// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
la_status lld_write_memory_line_list(ll_device_sptr device, const lld_memory_line_value_list_t& mem_line_val_list);

/// @brief Write list of tcam entries and values.
///
/// @param[in]  device              Low level device to use.
/// @param[in]  tcam_line_val_list  List of tcam, line and value pairs.
///
/// @retval     LA_STATUS_SUCCESS   Command completed successfully.
/// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
/// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
la_status lld_write_tcam_line_list(ll_device_sptr device, const tcam_line_value_list_t& tcam_line_val_list);

/// @brief Write list of register or memory-entries and values.
///
/// @param[in]  device              Low level device to use.
/// @param[in]  write_list          List of memory-lines/registers and value pairs.
///
/// @retval     LA_STATUS_SUCCESS   Command completed successfully.
/// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
/// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
la_status lld_write_memory_line_or_register_list(ll_device_sptr device, const lld_reg_mem_line_value_list_t& write_list);

/// @brief  Merge non-unique register writes using OR logic.
///
/// @note   The write_list is modified, it potentially becomes shorter. There is no promise on order.
///
/// @param[in]  write_list          List of registe and value pairs.
void lld_unordered_merge_register_value_list(lld_register_value_list_t& write_list);

static inline la_entry_width_t
get_width(const lld_register& reg)
{
    return reg.get_desc()->width;
}

static inline la_entry_width_t
get_width(const lld_memory& mem)
{
    return mem.get_desc()->width_total;
}

static inline la_entry_width_t
get_width(const lld_register_array_container& reg_array)
{
    return reg_array.get_desc()->width * reg_array.get_desc()->instances;
}

// Sanity checks to verify ll operation correctness.

template <class _Resource>
bool
is_matching_device_revision(ll_device* ldev, const _Resource& regmem)
{
    bool match = (IS_SIM_BLOCK_ID(regmem.get_block_id()) || (regmem.get_block()->get_revision() == ldev->get_device_revision()));
    return match;
}

template <class _Resource>
la_status
validate_params(const char* func, const _Resource& regmem, int is_volatile, bool is_write_action)
{
    const char* errstr;
    la_status rc;

    if (is_write_action && (!regmem.get_desc()->writable)) {
        log_err(LLD, "%s: resource is not writable, %s", __PRETTY_FUNCTION__, regmem.get_desc()->name.c_str());
        return LA_STATUS_EACCES;
    }

    if (!regmem.is_valid()) {
        errstr = "invalid resource";
        rc = LA_STATUS_EINVAL;
    } else if (is_volatile != -1 && is_volatile != (int)regmem.get_desc()->is_volatile()) {
        errstr = is_volatile ? "resource should be volatile" : "resource should not be volatile";
        rc = LA_STATUS_EACCES;
    } else if (!get_width(regmem)) {
        errstr = "zero width resource";
        rc = LA_STATUS_ENOTINITIALIZED;
    } else {
        return LA_STATUS_SUCCESS;
    }

    log_err(LLD, "%s: %s, %s", func, errstr, regmem.get_desc()->name.c_str());

    return rc;
}

static inline la_status
validate_params(const char* func, const lld_memory& mem, int is_volatile, size_t first_entry, size_t count, bool is_write_action)
{
    la_status rc = validate_params(func, mem, is_volatile, is_write_action);
    return_on_error(rc);

    const lld_memory_desc_t* mdesc = mem.get_desc();
    if (first_entry + count > mdesc->entries) {
        log_err(LLD,
                "%s: out of range, %s, first entry %ld, count %ld, entries %u",
                func,
                mdesc->name.c_str(),
                first_entry,
                count,
                mdesc->entries);
        return LA_STATUS_EOUTOFRANGE;
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
#endif // __LEABA_LLD_UTILS_H__
