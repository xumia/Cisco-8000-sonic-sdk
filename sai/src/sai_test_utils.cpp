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

#include <arpa/inet.h>
#include <stdint.h>
#include <vector>
#include "sai_leaba.h"
#include "sai_logger.h"
#include "sai_device.h"

using namespace std;

namespace silicon_one
{
namespace sai
{

// FDB notification callback for testing purposes
void
sai_fdb_evt(uint32_t count, const sai_fdb_event_notification_data_t* data)
{
    sai_log_debug(SAI_API_FDB, "FDB notifications: %d", count);
    for (uint32_t i = 0; i < count; i++) {
        const sai_fdb_entry_t* fdb_entry = &data[i].fdb_entry;
        sai_fdb_event_t fdb_event = data[i].event_type;

        // Today only SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID is defined
        if (data[i].attr[0].id != SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID) {
            sai_log_debug(SAI_API_FDB,
                          "Failed to retrieve bridge port ID, Event[%d] type: %s, BRIDGE_PORT_ID: UNKNOWN, SWITCH_ID: 0x%lx, "
                          "BV_ID: 0x%lx, MAC: %s, attri count: %d",
                          i,
                          to_string(fdb_event).c_str(),
                          fdb_entry->switch_id,
                          fdb_entry->bv_id,
                          to_string(fdb_entry->mac_address).c_str(),
                          data[i].attr_count);
        } else {
            auto pid = get_attr_value(SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID, data[i].attr[0].value);
            sai_log_debug(SAI_API_FDB,
                          "Event[%2d] type: %s, BRIDGE_PORT_ID: 0x%lx, SWITCH_ID: 0x%lx, BV_ID: 0x%lx, MAC: %s, attri count: %d",
                          i,
                          to_string(fdb_event).c_str(),
                          pid,
                          fdb_entry->switch_id,
                          fdb_entry->bv_id,
                          to_string(fdb_entry->mac_address).c_str(),
                          data[i].attr_count);
        }

        la_switch* bridge = la_get_bridge_by_obj(fdb_entry->bv_id);
        if (bridge == nullptr) {
            sai_log_error(SAI_API_FDB, "Can not get bridge for vlan 0x%lx", fdb_entry->bv_id);
        }
    }
}

// Create num_routes consecutive routes.
// Increasing destination for each added route by 2^inc_start_bit
// This way, we avoid Python overhead when adding big amount of routes
sai_status_t
sai_test_create_route_entries(sai_route_entry_t* route_entry,
                              uint32_t attr_count,
                              const sai_attribute_t* attr_list,
                              const uint32_t num_routes,
                              const uint32_t inc_start_bit,
                              const bool bulk_operation)
{
    sai_status_t status;
    uint32_t htonl_dest = 0;
    uint32_t inc_step;
    uint8_t inc_byte = 0;

    vector<sai_route_entry_t> route_entries(num_routes);
    vector<uint32_t> attr_counts(num_routes, attr_count);
    vector<const sai_attribute_t*> attr_lists(num_routes, attr_list);

    if (route_entry->destination.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        htonl_dest = htonl(route_entry->destination.addr.ip4);
        inc_step = 0x1 << inc_start_bit;
    } else {
        inc_byte = 15 - inc_start_bit / 8;
        inc_step = 0x1 << (inc_start_bit % 8);
    }

    for (uint32_t i = 0; i < num_routes; i++) {
        if (bulk_operation) {
            route_entries[i] = *route_entry;
        } else {
            status = route_api.create_route_entry(route_entry, attr_count, attr_list);
            if (status != SAI_STATUS_SUCCESS) {
                return status;
            }
        }

        if (route_entry->destination.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
            htonl_dest += inc_step;
            route_entry->destination.addr.ip4 = htonl(htonl_dest);
        } else {
            uint8_t tmp_inc_byte = inc_byte;
            // V6 case, tmp_inc_step can't be more than 128
            uint8_t tmp_inc_step = inc_step;
            while (1) {
                route_entry->destination.addr.ip6[tmp_inc_byte] += tmp_inc_step;
                // When current byte overflowed, increase next byte
                if ((route_entry->destination.addr.ip6[tmp_inc_byte] & ~(tmp_inc_step - 1)) == 0) {
                    if (tmp_inc_byte == 0) {
                        // User asked for too many routes
                        return SAI_STATUS_BUFFER_OVERFLOW;
                    }
                    tmp_inc_byte--;
                    // Except for first byte we deal with, we need to increase by 1
                    tmp_inc_step = 1;
                } else {
                    break;
                }
            }
        }
    }

    if (bulk_operation) {
        std::vector<sai_status_t> object_statuses(num_routes, SAI_STATUS_SUCCESS);
        return route_api.create_route_entries(num_routes,
                                              route_entries.data(),
                                              attr_counts.data(),
                                              attr_lists.data(),
                                              SAI_BULK_OP_ERROR_MODE_IGNORE_ERROR,
                                              object_statuses.data());
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_remove_all_routes(sai_object_id_t vrf_id)
{
    sai_start_api(SAI_API_UNSPECIFIED, SAI_OBJECT_TYPE_VIRTUAL_ROUTER, vrf_id, nullptr, "vrf", vrf_id);

    la_vrf* vrf = nullptr;
    la_status status = sdev->m_dev->get_vrf_by_id(la_obj.index, vrf);
    sai_return_on_la_error(status, "Failed to get vrf with index %u", la_obj.index);

    status = vrf->clear_all_ipv4_routes();
    sai_return_on_la_error(status, "Failed to remove all ipv4 routes for vrf=%#lx", vrf_id);

    status = vrf->clear_all_ipv6_routes();
    sai_return_on_la_error(status, "Failed to remove all ipv6 routes for vrf=%#lx", vrf_id);

    return SAI_STATUS_SUCCESS;
}

void
sai_queue_pfc_deadlock_evt(_In_ uint32_t count, _In_ const sai_queue_deadlock_notification_data_t* data)
{
    sai_log_debug(SAI_API_QUEUE, "PFC Deadlock Notifications: %d", count);
    for (uint32_t i = 0; i < count; i++) {
        if (data[i].event == SAI_QUEUE_PFC_DEADLOCK_EVENT_TYPE_DETECTED) {
            sai_log_debug(SAI_API_QUEUE, "PFC Deadlock detected on queue %u", data[i].queue_id);
        } else {
            sai_log_debug(SAI_API_QUEUE, "PFC Deadlock recovered on queue %u", data[i].queue_id);
        }
    }
}
}
}
