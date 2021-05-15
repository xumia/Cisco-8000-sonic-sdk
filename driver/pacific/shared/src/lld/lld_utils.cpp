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

#include "lld/lld_utils.h"
#include "common/defines.h"
#include "lld/ll_device.h"
#include "lld/ll_transaction.h"
#include "lld/lld_memory.h"
#include "lld/lld_register.h"

#include <unordered_map>

namespace silicon_one
{

static void
resize_register_value_bv(lld_register_scptr reg, bit_vector& value_bv)
{
    size_t correct_size = reg->get_desc()->width_in_bits;
    if (value_bv.get_minimal_width() <= correct_size) {
        value_bv.resize(correct_size);
    }
}

la_status
lld_write_register_list(ll_device_sptr device, const lld_register_value_list_t& reg_val_list)
{
    ll_transaction transaction(device);
    for (const auto& lld_reg_val : reg_val_list) {
        lld_register_scptr reg = lld_reg_val.first;
        bit_vector bv = lld_reg_val.second;
        resize_register_value_bv(reg, bv);

        la_status stat = transaction.write_register(*(lld_reg_val.first), bv);
        return_on_error(stat);
    }

    la_status stat = transaction.commit();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
lld_write_memory_list(ll_device_sptr device, const lld_memory_value_list_t& mem_val_list)
{
    for (const auto& lld_mem_val : mem_val_list) {
        const auto& mem = *(lld_mem_val.first);
        la_status rc = device->fill_memory(mem, 0 /* first_entry */, mem.get_desc()->entries, lld_mem_val.second);
        if (rc) {
            return rc;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lld_write_memory_line_list(ll_device_sptr device, const lld_memory_line_value_list_t& mem_line_val_list)
{
    ll_transaction transaction(device);

    for (const auto& lld_mem_line_val : mem_line_val_list) {
        auto lld_mem_line = lld_mem_line_val.first;
        la_status stat
            = transaction.write_memory(*(lld_mem_line.first), lld_mem_line.second, 1 /* count */, lld_mem_line_val.second);
        return_on_error(stat);
    }

    la_status stat = transaction.commit();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
lld_write_tcam_line_list(ll_device_sptr device, const tcam_line_value_list_t& tcam_line_val_list)
{
    ll_transaction transaction(device);

    for (const auto& tcam_line_val : tcam_line_val_list) {
        const auto& tcam_line = tcam_line_val.first;
        const auto& tcam_val = tcam_line_val.second;
        la_status stat = transaction.write_tcam(*(tcam_line.first), tcam_line.second, tcam_val.first, tcam_val.second);
        return_on_error(stat);
    }

    la_status stat = transaction.commit();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
lld_write_memory_line_or_register_list(ll_device_sptr device, const lld_reg_mem_line_value_list_t& write_list)
{
    ll_transaction transaction(device);

    for (const auto& mem_line_or_reg_val : write_list) {
        const auto& mem_line_or_reg = mem_line_or_reg_val.first;
        auto val = mem_line_or_reg_val.second;

        la_status status;
        if (mem_line_or_reg.is_register) {
            auto reg = mem_line_or_reg.reg;
            resize_register_value_bv(reg, val);

            status = transaction.write_register(*reg, val);
        } else {
            const auto& mem_line = mem_line_or_reg.mem_line;
            auto mem = mem_line.first;
            auto line = mem_line.second;
            status = transaction.write_memory(*mem, line, 1 /* count */, val);
        }

        return_on_error(status);
    }

    return transaction.commit();
}

void
lld_unordered_merge_register_value_list(lld_register_value_list_t& reg_val_list)
{
    std::unordered_map<lld_register_scptr, bit_vector, lld_register_scptr_ops> uniq_reg_val;

    // Combine non-unique reg_val entries, values are combined with OR logic.
    for (const auto& el : reg_val_list) {
        lld_register_scptr reg = el.first;
        bit_vector bv = el.second;

        resize_register_value_bv(reg, bv);

        auto it = uniq_reg_val.find(reg);
        if (it == uniq_reg_val.end()) {
            uniq_reg_val[reg] = bv;
        } else {
            uniq_reg_val[reg] |= bv;
        }
    }

    // Re-fill the list
    reg_val_list.clear();
    for (const auto& el : uniq_reg_val) {
        reg_val_list.push_back({el.first, el.second});
    }
}

} // namespace silicon_one
