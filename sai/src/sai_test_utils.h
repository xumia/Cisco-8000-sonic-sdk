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

#ifndef __SAI_TEST_UTILS_H__
#define __SAI_TEST_UTILS_H__
extern "C" {
#include "sai.h"
}
#include <vector>

// the following sai_get_counters are defined for python to use, need to be defined in this file
sai_status_t
sai_get_counters(sai_object_id_t obj, uint32_t size, sai_buffer_pool_stat_t* counter_ids, uint64_t* counters)
{
    sai_buffer_api_t* buffer_api = nullptr;
    sai_api_query(SAI_API_BUFFER, (void**)(&buffer_api));

    return buffer_api->get_buffer_pool_stats(obj, size, (const sai_stat_id_t*)counter_ids, counters);
}

sai_status_t
sai_get_counters(sai_object_id_t obj, uint32_t size, sai_queue_stat_t* counter_ids, uint64_t* counters)
{
    sai_queue_api_t* queue_api = nullptr;
    sai_api_query(SAI_API_QUEUE, (void**)(&queue_api));
    return queue_api->get_queue_stats(obj, size, (const sai_stat_id_t*)counter_ids, counters);
}

sai_status_t
sai_get_counters(sai_object_id_t obj, uint32_t size, sai_bridge_port_stat_t* counter_ids, uint64_t* counters)
{
    sai_bridge_api_t* bridge_api = nullptr;
    sai_api_query(SAI_API_BRIDGE, (void**)(&bridge_api));
    return bridge_api->get_bridge_port_stats(obj, size, (const sai_stat_id_t*)counter_ids, counters);
}

sai_status_t
sai_get_counters(sai_object_id_t obj, uint32_t size, sai_port_stat_t* counter_ids, uint64_t* counters)
{
    sai_port_api_t* port_api = nullptr;
    sai_api_query(SAI_API_PORT, (void**)(&port_api));
    return port_api->get_port_stats(obj, size, (const sai_stat_id_t*)counter_ids, counters);
}

sai_status_t
sai_get_counters(sai_object_id_t obj, uint32_t size, sai_router_interface_stat_t* counter_ids, uint64_t* counters)
{
    sai_router_interface_api_t* rif_api = nullptr;
    sai_api_query(SAI_API_ROUTER_INTERFACE, (void**)(&rif_api));
    return rif_api->get_router_interface_stats(obj, size, (const sai_stat_id_t*)counter_ids, counters);
}

sai_status_t
sai_get_counters(sai_object_id_t obj, uint32_t size, sai_policer_stat_t* counter_ids, uint64_t* counters)
{
    sai_policer_api_t* policer_api = nullptr;

    sai_api_query(SAI_API_POLICER, (void**)(&policer_api));
    return policer_api->get_policer_stats(obj, size, (const sai_stat_id_t*)counter_ids, counters);
}

template <typename StatsIdType>
std::vector<uint64_t>
get_counters(sai_object_id_t obj, std::vector<StatsIdType> ids)
{
    std::vector<uint64_t> counters(ids.size());
    sai_get_counters(obj, ids.size(), ids.data(), counters.data());
    return counters;
}

// the following sai_get_counters are defined for python to use, need to be defined in this file
sai_status_t
sai_get_counters_ext(sai_object_id_t obj, uint32_t size, sai_queue_stat_t* counter_ids, sai_stats_mode_t mode, uint64_t* counters)
{
    sai_queue_api_t* queue_api = nullptr;
    sai_api_query(SAI_API_QUEUE, (void**)(&queue_api));
    return queue_api->get_queue_stats_ext(obj, size, (const sai_stat_id_t*)counter_ids, mode, counters);
}

sai_status_t
sai_get_counters_ext(sai_object_id_t obj,
                     uint32_t size,
                     sai_bridge_port_stat_t* counter_ids,
                     sai_stats_mode_t mode,
                     uint64_t* counters)
{
    sai_bridge_api_t* bridge_api = nullptr;
    sai_api_query(SAI_API_BRIDGE, (void**)(&bridge_api));
    return bridge_api->get_bridge_port_stats_ext(obj, size, (const sai_stat_id_t*)counter_ids, mode, counters);
}

sai_status_t
sai_get_counters_ext(sai_object_id_t obj, uint32_t size, sai_port_stat_t* counter_ids, sai_stats_mode_t mode, uint64_t* counters)
{
    sai_port_api_t* port_api = nullptr;
    sai_api_query(SAI_API_PORT, (void**)(&port_api));
    return port_api->get_port_stats_ext(obj, size, (const sai_stat_id_t*)counter_ids, mode, counters);
}

sai_status_t
sai_get_counters_ext(sai_object_id_t obj,
                     uint32_t size,
                     sai_router_interface_stat_t* counter_ids,
                     sai_stats_mode_t mode,
                     uint64_t* counters)
{
    sai_router_interface_api_t* rif_api = nullptr;
    sai_api_query(SAI_API_ROUTER_INTERFACE, (void**)(&rif_api));
    return rif_api->get_router_interface_stats_ext(obj, size, (const sai_stat_id_t*)counter_ids, mode, counters);
}

sai_status_t
sai_get_counters_ext(sai_object_id_t obj, uint32_t size, sai_switch_stat_t* counter_ids, sai_stats_mode_t mode, uint64_t* counters)
{
    sai_switch_api_t* switch_api = nullptr;
    sai_api_query(SAI_API_SWITCH, (void**)(&switch_api));
    return switch_api->get_switch_stats_ext(obj, size, (const sai_stat_id_t*)counter_ids, mode, counters);
}

sai_status_t
sai_get_counters_ext(sai_object_id_t obj, uint32_t size, sai_policer_stat_t* counter_ids, sai_stats_mode_t mode, uint64_t* counters)
{
    sai_policer_api_t* policer_api = nullptr;
    sai_api_query(SAI_API_POLICER, (void**)(&policer_api));
    return policer_api->get_policer_stats_ext(obj, size, (const sai_stat_id_t*)counter_ids, mode, counters);
}

template <typename StatsIdType>
std::vector<uint64_t>
get_counters_ext(sai_object_id_t obj, std::vector<StatsIdType> ids, sai_stats_mode_t mode)
{
    std::vector<uint64_t> counters(ids.size());
    sai_get_counters_ext(obj, ids.size(), ids.data(), mode, counters.data());
    return counters;
}

namespace silicon_one
{
namespace sai
{
void sai_fdb_evt(uint32_t count, const sai_fdb_event_notification_data_t* data);
void sai_queue_pfc_deadlock_evt(uint32_t count, const sai_queue_deadlock_notification_data_t* data);
sai_status_t sai_test_create_route_entries(sai_route_entry_t* route_entry,
                                           uint32_t attr_count,
                                           const sai_attribute_t* attr_list,
                                           const uint32_t num_routes,
                                           const uint32_t inc_start_bit,
                                           const bool bulk_operation);
sai_status_t sai_remove_all_routes(sai_object_id_t vrf_id);
}
}
#endif
