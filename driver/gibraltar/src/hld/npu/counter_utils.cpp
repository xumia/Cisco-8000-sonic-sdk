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

#include "npu/counter_utils.h"
#include "api/types/la_object.h"
#include "lld/device_tree.h"
#include "nplapi/npl_types.h"
#include "npu/la_counter_set_impl.h"
#include "qos/la_meter_set_impl.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

static npl_counter_ptr_t
do_populate_counter_ptr_slice(const la_counter_or_meter_set_wcptr& counter_or_meter,
                              la_slice_id_t slice,
                              counter_direction_e direction,
                              size_t offset)
{

    npl_counter_ptr_t counter_ptr;
    counter_ptr = (direction == COUNTER_DIRECTION_INGRESS) ? NPU_COUNTER_INVALID : NPU_COUNTER_NOP;

    if (counter_or_meter == nullptr) {
        return counter_ptr;
    }

    if ((counter_or_meter->type() == la_object::object_type_e::METER_SET) && (direction != COUNTER_DIRECTION_INGRESS)) {
        // Meters can be configured only on INGRESS
        return counter_ptr;
    }

    counter_allocation allocation;
    la_status status = LA_STATUS_SUCCESS;

    if (counter_or_meter->type() == la_object::object_type_e::COUNTER_SET) {
        const auto& counter = counter_or_meter.weak_ptr_static_cast<const la_counter_set_impl>();
        status = counter->get_allocation(slice, direction, allocation);
    } else {
        const auto& meter = counter_or_meter.weak_ptr_static_cast<const la_meter_set_impl>();
        la_slice_ifg slice_ifg = {.slice = slice, .ifg = 0};
        status = meter->get_allocation(slice_ifg, allocation);
    }

    if (status != LA_STATUS_SUCCESS) {
        log_warning(HLD, "%s: failed to get counter/meter allocation %s", __func__, la_status2str(status).c_str());
        return counter_ptr;
    }

    counter_ptr.cb_id = counter_manager::counter_bank_id_to_npu_bank_id(allocation.get_bank_id());
    counter_ptr.cb_set_base = allocation.get_index();
    counter_ptr.cb_set_base += offset;

    return counter_ptr;
}

npl_counter_ptr_t
populate_counter_ptr_slice_with_offset(const la_counter_or_meter_set_wcptr& counter_or_meter,
                                       la_slice_id_t slice,
                                       counter_direction_e direction,
                                       size_t offset)
{
    return do_populate_counter_ptr_slice(counter_or_meter, slice, direction, offset);
}

npl_counter_ptr_t
populate_counter_ptr_slice(const la_counter_or_meter_set_wcptr& counter_or_meter,
                           la_slice_id_t slice,
                           counter_direction_e direction)
{
    return do_populate_counter_ptr_slice(counter_or_meter, slice, direction, 0 /* offset */);
}

npl_counter_ptr_t
populate_counter_ptr_slice_pair(const la_counter_or_meter_set_wcptr& counter_or_meter,
                                la_slice_pair_id_t pair_idx,
                                counter_direction_e direction)
{
    la_slice_id_t slice = pair_idx * 2;

    return populate_counter_ptr_slice(counter_or_meter, slice, direction);
}

npl_counter_ptr_t
populate_q_counter_ptr(const la_counter_or_meter_set_wcptr& counter_or_meter, la_slice_id_t slice, counter_direction_e direction)
{

    return populate_counter_ptr_slice_pair(counter_or_meter, slice / 2, direction);
}

} // namespace silicon_one
