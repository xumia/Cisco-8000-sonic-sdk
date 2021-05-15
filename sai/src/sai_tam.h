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

#ifndef __SAI_TAM_H__
#define __SAI_TAM_H__

#include "saitypes.h"
#include "saitam.h"

extern "C" {
#include "sai_attr_ext.h"
}

#include <string>
#include <map>
#include <vector>
#include <iterator>
#include <thread>
#include <condition_variable>
#include <chrono>
#include "la_sai_object.h"
#include "common/weak_ptr_unsafe.h"

namespace silicon_one
{
namespace sai
{

static constexpr sai_uint32_t TAM_DEFAULT_REPORT_INTERVAL = 1000;

union lsai_tam_event_s {
    // when lsai_tam_event_desc::type == SAI_TAM_EVENT_TYPE_SWITCH
    // sai_tam_switch_event_t switch_event;
    struct switch_event_s {
        sai_switch_event_type_t type;

        union switch_event_data_s {
            struct parity_error_s {
                sai_tam_switch_event_ecc_err_type_e err_type;
                la_entry_addr_t instance_addr;
                uint64_t data;
            } parity_error;

            // struct stable_full_s {
            //     ...
            // }
            // struct stable_error_s {
            // ...
            // }
            // struct warmboot_downgrade_s {
            // ...
            // }
        } data;
    } switch_event;

    // when lsai_tam_event_desc::type == SAI_TAM_EVENT_ATTR_PACKET_DROP_TYPE_INGRESS
    // sai_tam_ingress_pkt_drop_event_t ingress_pkt_drop_event;

    // when lsai_tam_event_desc::type == SAI_TAM_EVENT_ATTR_PACKET_DROP_TYPE_EGRESS
    // sai_tam_egress_pkt_drop_event_t egress_pkt_drop_event;

    // when lsai_tam_event_desc::type == SAI_TAM_EVENT_ATTR_PACKET_DROP_TYPE_MMU
    // sai_tam_mmu_pkt_drop_event_t mmu_pkt_drop_event;

    // when lsai_tam_event_desc::type == SAI_TAM_EVENT_TYPE_RESOURCE_UTILIZATION
    // sai_tam_resource_util_t resource_util;
};

struct lsai_tam_event_desc {
    /// Block ID of interrupt source register
    la_block_id_t block_id;

    /// Address of interrupt source register. For debugging only
    la_entry_addr_t addr;

    /// Time stamp of the notification in nano-seconds based on CLOCK_MONOTONIC.
    uint64_t timestamp_ns;

    /// SAI TAM event type
    sai_tam_event_type_t type;

    /// SAI TAM event information
    lsai_tam_event_s event;

    lsai_tam_event_desc& operator=(const la_notification_desc& desc);

    string types_in_str();
};

class lsai_device;

class lsai_tam_report_entry;

class lsai_tam_event_action_entry;

class lsai_tam_event_entry;

class lsai_tam_entry;

using lsai_tam_report_entry_ptr = std::shared_ptr<silicon_one::sai::lsai_tam_report_entry>;
using lsai_tam_event_action_entry_ptr = std::shared_ptr<silicon_one::sai::lsai_tam_event_action_entry>;
using lsai_tam_event_entry_ptr = std::shared_ptr<silicon_one::sai::lsai_tam_event_entry>;
using lsai_tam_entry_ptr = std::shared_ptr<silicon_one::sai::lsai_tam_entry>;

// sai tam report object contains reporting methods.
class lsai_tam_report_entry : public std::enable_shared_from_this<lsai_tam_report_entry>
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

    friend class lsai_tam_event_entry;

public:
    // SAI_TAM_REPORT object ID
    sai_object_id_t m_oid = SAI_NULL_OBJECT_ID;

    sai_tam_report_type_t m_type = SAI_TAM_REPORT_TYPE_VENDOR_EXTN;
    sai_tam_report_mode_t m_mode = SAI_TAM_REPORT_MODE_ALL;
    sai_uint32_t m_interval = TAM_DEFAULT_REPORT_INTERVAL;

    weak_ptr_unsafe<lsai_device> m_sdev;

    lsai_tam_report_entry() = default;

    explicit lsai_tam_report_entry(weak_ptr_unsafe<lsai_device> sai_dev) : m_sdev(sai_dev)
    {
    }

    explicit lsai_tam_report_entry(weak_ptr_unsafe<lsai_device> sai_dev, sai_object_id_t oid, sai_tam_report_type_t t)
        : m_oid(oid), m_type(t), m_sdev(sai_dev)
    {
    }

    la_status set_type(sai_tam_report_type_t report_type);
    la_status set_interval(sai_uint32_t time_interval);

    /// @brief	send descriptors to report, and remove those descriptors from buffer after sent.
    ///
    /// @return     la_status
    la_status report_and_erase();

    /// @brief	Emptying m_buffer by reporting all descriptors.
    ///
    /// @return     la_status
    la_status flush();

private:
    // TODO: should use sai_tam_event_desc_t data type instead. Currently, this is a work-around for cereal autogen.
    std::vector<lsai_tam_event_desc> m_buffer;

    std::vector<lsai_tam_event_action_entry_ptr>::iterator find_event_action(const sai_object_id_t& event_action_oid);

    /// @brief	Report those given descriptors
    ///
    /// @param[in]  tam_oid 	TAM object ID for this report
    /// @param[in]  desc_count	Number of descriptors in desc_array.
    /// @param[in]  desc_array	Array of descriptors
    ///
    /// @return     la_status
    /// /// @retval
    la_status report(const sai_object_id_t& tam_oid, const uint32_t& desc_count, sai_tam_event_desc_t* desc_array);

    /// @brief	Enqueue a descriptor into report m_buffer
    ///
    /// @param[in]  desc	input descriptor
    /// @param[in]  tam_oid	TAM object ID for this descriptor
    ///
    /// @return     la_status
    la_status enqueue(lsai_tam_event_desc desc, const sai_object_id_t& tam_oid);

    /// @brief	Enqueue a list of descriptors into report m_buffer.
    ///
    /// @param[in]  desc_list	vector of descriptors
    /// @param[in]  tam_oid 	TAM object ID for those descriptors
    ///
    /// @return     la_status
    la_status enqueue(std::vector<lsai_tam_event_desc> desc_list, const sai_object_id_t& tam_oid);
};

// sai tam event action which binds with a lsai_tam_report_entry object and contains message buffer.
class lsai_tam_event_action_entry : public std::enable_shared_from_this<lsai_tam_event_action_entry>
{
public:
    // SAI_TAM_EVENT_ACTION object ID
    sai_object_id_t m_oid = SAI_NULL_OBJECT_ID;

    lsai_tam_report_entry_ptr m_reporter = nullptr;

    weak_ptr_unsafe<lsai_device> m_sdev;

    lsai_tam_event_action_entry() = default;

    la_status bind_reporter(lsai_tam_report_entry_ptr report_ptr);

    la_status unbind_reporter();
};

// sai tam event
class lsai_tam_event_entry : public std::enable_shared_from_this<lsai_tam_event_entry>
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

    friend class lsai_tam_entry;

public:
    // SAI_TAM_EVENT object ID
    sai_object_id_t m_oid = SAI_NULL_OBJECT_ID;

    /// SAI TAM event type
    // lsai_tam_entry_type_e type;
    sai_tam_event_type_t m_type;

    // only valid if m_type == SAI_TAM_EVENT_TYPE_SWITCH
    std::vector<sai_switch_event_type_t> m_switch_event_types;

    // union sai_tam_event_sub_type_t {
    // only valid if m_type == SAI_TAM_EVENT_TYPE_SWITCH
    //     std::vector<sai_switch_event_type_t> switch_event;
    //
    // only valid if m_type == SAI_TAM_EVENT_TYPE_PACKET_DROP or SAI_TAM_EVENT_TYPE_PACKET_DROP_STATEFUL
    // not supported yet
    // struct packet_drop_type_t{
    //     std::vector<sai_packet_drop_type_ingress_t> ingress;
    //     std::vector<sai_packet_drop_type_mmu_t> mmu;
    //     std::vector<sai_packet_drop_type_egress_t> egress;
    // } packet_drop_event;
    // } sub_type;

    weak_ptr_unsafe<lsai_device> m_sdev;

    std::vector<lsai_tam_event_action_entry_ptr> m_event_action_list;
    std::vector<sai_object_id_t> m_event_collector_list;

    lsai_tam_event_entry() = default;

    la_status bind_event_action(lsai_tam_event_action_entry_ptr event_action_ptr);
    la_status unbind_event_action(const sai_object_id_t& event_action_oid);
    la_status unbind_all_event_action();

private:
    std::vector<lsai_tam_event_action_entry_ptr>::iterator find_event_action(const sai_object_id_t& event_action_oid);

    bool match_event_types(lsai_tam_event_desc desc);

    la_status send_to_reporters(lsai_tam_event_desc desc, const sai_object_id_t& tam_oid);

    la_status send_to_reporters(std::vector<lsai_tam_event_desc> desc_list, const sai_object_id_t& tam_oid);
};

// sai tam
class lsai_tam_entry : public std::enable_shared_from_this<lsai_tam_entry>
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // SAI_TAM_EVENT object ID
    sai_object_id_t m_oid = SAI_NULL_OBJECT_ID;

    weak_ptr_unsafe<lsai_device> m_sdev;

    std::vector<sai_tam_bind_point_type_t> m_bind_point_types;

    // events map of different type
    std::vector<lsai_tam_event_entry_ptr> m_switch_events;
    // std::vector<lsai_tam_event_entry_ptr> m_ingress_pkt_drop_events;
    // std::vector<lsai_tam_event_entry_ptr> m_egress_pkt_drop_events;

    lsai_tam_entry() = default;

    // called by lsai_device::tam_notification_handler when notification descriptor is received.
    la_status event_handler(const la_notification_desc& desc);

    la_status register_tam_event(lsai_tam_event_entry_ptr tam_event);

    la_status find_event(std::vector<lsai_tam_event_entry_ptr>::iterator& it,
                         std::vector<lsai_tam_event_entry_ptr>*& vec,
                         const sai_object_id_t& event_oid);

    la_status remove_all_registries();

private:
    std::vector<lsai_tam_event_entry_ptr>::iterator find_event_in(const sai_tam_event_type_t& type,
                                                                  const sai_object_id_t& event_oid);
};

template <typename entry_ptr_t, typename entry_t>
static sai_status_t
check_object_id_list(std::vector<entry_ptr_t>& entry_ptr_vec,
                     sai_object_type_t obj_type,
                     std::shared_ptr<silicon_one::sai::lsai_device> sdev,
                     obj_db<entry_t>& object_db,
                     const sai_object_list_t& objlist)
{
    // check if objects are exist ...
    for (uint32_t idx = 0; idx < objlist.count; idx++) {
        auto obj_id = objlist.list[idx];
        lsai_object la_obj(obj_id);
        if (la_obj.type != obj_type || la_obj.get_device() != sdev) {
            sai_return_on_error(
                SAI_STATUS_INVALID_PARAMETER, "Bad object ID, 0x%lx, type(%s)", obj_id, to_string(obj_type).c_str());
        }

        entry_ptr_t obj_entry_ptr;
        la_status status = object_db.get(la_obj.index, obj_entry_ptr);
        sai_return_on_la_error(status, "Failed to find entry(type:%s) for object_id (0x%lx)", to_string(obj_type).c_str(), obj_id);

        entry_ptr_vec.push_back(obj_entry_ptr);
    }
    return SAI_STATUS_SUCCESS;
}
}
}
#endif
