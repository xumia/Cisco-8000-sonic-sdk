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

#ifndef __SAI_DEBUG_COUNTER_H__
#define __SAI_DEBUG_COUNTER_H__

#include <set>

#include "api/types/la_event.h"
#include "api/types/la_common_types.h"

#include "saidebugcounter.h"

#include "sai_db.h"
#include "sai_warm_boot.h"

namespace silicon_one
{
namespace sai

{
typedef sai_status_t(debug_counter_val_getter_func)(std::shared_ptr<lsai_device> sdev,
                                                    const std::vector<la_event_e>& arg_list,
                                                    sai_stats_mode_t mode,
                                                    uint64_t& out_val,
                                                    bool is_port_count,
                                                    la_slice_ifg slice_ifg);

class debug_counter_manager;

class debug_counter_entry
{
    friend class debug_counter_manager;
    CEREAL_SUPPORT_PRIVATE_MEMBERS

    void update_drop_reason_list(const sai_s32_list_t& drop_reason_list);
    sai_debug_counter_type_t m_type;
    std::vector<uint32_t> m_drop_reason_list;
};

class debug_counter_val_getter
{
    friend class debug_counter_manager;

public:
    static sai_status_t default_counter_val_getter(std::shared_ptr<lsai_device> sdev,
                                                   const std::vector<la_event_e>& arg_list,
                                                   sai_stats_mode_t mode,
                                                   uint64_t& out_val,
                                                   bool port_counter,
                                                   la_slice_ifg slice_ifg);

    debug_counter_val_getter()
    {
    }

    debug_counter_val_getter(std::vector<la_event_e> arg_list)
    {
        m_arg = arg_list;
        m_get_val_func = &default_counter_val_getter;
        for (auto arg : arg_list) {
            m_la_event_names.insert(arg);
        }
    }

    debug_counter_val_getter(la_event_e arg)
    {
        m_arg.push_back(arg);
        m_get_val_func = &default_counter_val_getter;
        m_la_event_names.insert(arg);
    }

    static std::set<la_event_e> event_names()
    {
        return m_la_event_names;
    }

private:
    // arguments for retreiving function
    std::vector<la_event_e> m_arg;
    // function used for retreiving values for this counter
    debug_counter_val_getter_func* m_get_val_func = nullptr;
    // collect all la event names used, so we can attach counter to each one
    static std::set<la_event_e> m_la_event_names;
};

class lsai_device;
class debug_counter_manager
{
    static constexpr uint32_t MAX_DEBUG_COUNTERS = 1000;
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    friend lsai_device;

public:
    debug_counter_manager() = default;
    debug_counter_manager(std::shared_ptr<lsai_device> sai_device);

    static sai_status_t default_counter_val_getter(std::shared_ptr<lsai_device> sdev,
                                                   const std::vector<uint32_t> arg_list,
                                                   sai_stats_mode_t mode,
                                                   uint64_t& out_val,
                                                   bool is_port_count,
                                                   la_slice_ifg slice_ifg);
    sai_status_t query_attribute_enum_values_capability(sai_attr_id_t attr_id, sai_s32_list_t* enum_values_capability);
    static void debug_counter_key_to_str(_In_ sai_object_id_t debug_counter_id, _Out_ char* key_str);
    static std::string debug_counter_to_string(sai_attribute_t& attr);

    la_status get_sdk_counter_val(const std::shared_ptr<lsai_device>& sdev,
                                  uint32_t counter_name,
                                  sai_stats_mode_t mode,
                                  uint64_t& out_val,
                                  bool is_port_count,
                                  la_slice_ifg slice_ifg);
    sai_status_t get_counter_value(sai_stat_id_t idx,
                                   sai_stats_mode_t mode,
                                   uint64_t& out_val,
                                   bool is_port_count,
                                   la_slice_ifg slice_ifg);
    static sai_status_t debug_counter_attr_set(_In_ const sai_object_key_t* key,
                                               _In_ const sai_attribute_value_t* value,
                                               void* arg);
    static sai_status_t debug_counter_attr_get(_In_ const sai_object_key_t* key,
                                               _Inout_ sai_attribute_value_t* value,
                                               _In_ uint32_t attr_index,
                                               _Inout_ vendor_cache_t* cache,
                                               void* arg);
    static sai_status_t create_debug_counter(_Out_ sai_object_id_t* debug_counter_id,
                                             _In_ sai_object_id_t switch_id,
                                             _In_ uint32_t attr_count,
                                             _In_ const sai_attribute_t* attr_list);
    static sai_status_t remove_debug_counter(_In_ sai_object_id_t debug_counter_id);
    static sai_status_t set_debug_counter_attribute(_In_ sai_object_id_t debug_counter_id, _In_ const sai_attribute_t* attr);
    static sai_status_t get_debug_counter_attribute(_In_ sai_object_id_t debug_counter_id,
                                                    _In_ uint32_t attr_count,
                                                    _Inout_ sai_attribute_t* attr_list);

private:
    std::shared_ptr<lsai_device> m_sai_device;
    // map counter index to debug_counter_entry
    obj_db<debug_counter_entry> m_debug_counter_db{SAI_OBJECT_TYPE_DEBUG_COUNTER, MAX_DEBUG_COUNTERS};

    bool is_supported_drop_reason(sai_in_drop_reason_t reason) const;
    bool are_supported_drop_reasons(const sai_s32_list_t& drop_reasons) const;

    // map SAI in drop reason to value getter class
    const std::unordered_map<uint32_t, debug_counter_val_getter> m_sai_to_la_counter_translation_in = {
        {SAI_IN_DROP_REASON_ACL_ANY, debug_counter_val_getter(LA_EVENT_L3_ACL_DROP)},
        {SAI_IN_DROP_REASON_DIP_LINK_LOCAL, debug_counter_val_getter(LA_EVENT_L3_LOCAL_SUBNET)},
        {SAI_IN_DROP_REASON_EXCEEDS_L3_MTU, debug_counter_val_getter(LA_EVENT_L3_TX_MTU_FAILURE)},
        {SAI_IN_DROP_REASON_FDB_UC_DISCARD, debug_counter_val_getter(LA_EVENT_ETHERNET_UNKNOWN_UC)},
        {SAI_IN_DROP_REASON_FDB_MC_DISCARD, debug_counter_val_getter(LA_EVENT_ETHERNET_UNKNOWN_MC)},
        {SAI_IN_DROP_REASON_INGRESS_VLAN_FILTER, debug_counter_val_getter(LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)},
        {SAI_IN_DROP_REASON_INGRESS_STP_FILTER, debug_counter_val_getter(LA_EVENT_ETHERNET_INGRESS_STP_BLOCK)},
        {SAI_IN_DROP_REASON_IP_HEADER_ERROR,
         debug_counter_val_getter({LA_EVENT_IPV4_HEADER_ERROR,
                                   LA_EVENT_IPV6_HEADER_ERROR,
                                   LA_EVENT_IPV4_CHECKSUM,
                                   LA_EVENT_IPV4_UNKNOWN_PROTOCOL,
                                   LA_EVENT_IPV4_OPTIONS_EXIST})},
        {SAI_IN_DROP_REASON_L2_LOOPBACK_FILTER, debug_counter_val_getter(LA_EVENT_ETHERNET_SAME_INTERFACE)},
        // SAI definition is for all packets. SDK implement for MC packets
        // {SAI_IN_DROP_REASON_L3_LOOPBACK_FILTER, debug_counter_val_getter(LA_EVENT_L3_MC_SAME_INTERFACE)},
        {SAI_IN_DROP_REASON_NO_L3_HEADER, debug_counter_val_getter(LA_EVENT_ETHERNET_UNKNOWN_L3)},
        // disabled intentionally in sai_device.cpp
        {SAI_IN_DROP_REASON_SMAC_EQUALS_DMAC, debug_counter_val_getter(LA_EVENT_ETHERNET_SA_DA_ERROR)},
        {SAI_IN_DROP_REASON_SMAC_MULTICAST, debug_counter_val_getter(LA_EVENT_ETHERNET_SA_MULTICAST)},
        {SAI_IN_DROP_REASON_TTL, debug_counter_val_getter(LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE)},
        {SAI_IN_DROP_REASON_LPM4_MISS, debug_counter_val_getter({LA_EVENT_L3_DROP_ADJ, LA_EVENT_L3_NULL_ADJ})},
        {SAI_IN_DROP_REASON_UNRESOLVED_NEXT_HOP, debug_counter_val_getter(LA_EVENT_L3_GLEAN_ADJ)},
        {SAI_IN_DROP_REASON_ACL_ANY, debug_counter_val_getter({LA_EVENT_ETHERNET_ACL_DROP, LA_EVENT_ETHERNET_ACL_FORCE_PUNT})},
        {SAI_IN_DROP_REASON_L2_ANY, debug_counter_val_getter({LA_EVENT_ETHERNET_ACCEPTABLE_FORMAT,
                                                              LA_EVENT_ETHERNET_NO_SERVICE_MAPPING,
                                                              LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                                              LA_EVENT_ETHERNET_NO_SIP_MAPPING,
                                                              LA_EVENT_ETHERNET_NO_VNI_MAPPING,
                                                              LA_EVENT_ETHERNET_NO_VSID_MAPPING,
                                                              LA_EVENT_ETHERNET_PTP_OVER_ETH,
                                                              LA_EVENT_ETHERNET_ISIS_OVER_L2,
                                                              LA_EVENT_ETHERNET_MACSEC,
                                                              LA_EVENT_ETHERNET_TEST_OAM_AC_MEP,
                                                              LA_EVENT_ETHERNET_TEST_OAM_AC_MIP,
                                                              LA_EVENT_ETHERNET_SYSTEM_MYMAC,
                                                              LA_EVENT_ETHERNET_BCAST_PKT,
                                                              LA_EVENT_ETHERNET_PFC_SAMPLE,
                                                              LA_EVENT_ETHERNET_L2_DLP_NOT_FOUND,
                                                              LA_EVENT_ETHERNET_DSPA_MC_TRIM,
                                                              LA_EVENT_ETHERNET_EGRESS_STP_BLOCK,
                                                              LA_EVENT_ETHERNET_SPLIT_HORIZON,
                                                              LA_EVENT_ETHERNET_DISABLED,
                                                              LA_EVENT_ETHERNET_INCOMPATIBLE_EVE_CMD,
                                                              LA_EVENT_ETHERNET_PADDING_RESIDUE_IN_SECOND_LINE})},
        {SAI_IN_DROP_REASON_L3_ANY,
         debug_counter_val_getter({LA_EVENT_IPV4_MC_FORWARDING_DISABLED,
                                   LA_EVENT_IPV4_UC_FORWARDING_DISABLED,
                                   LA_EVENT_IPV6_MC_FORWARDING_DISABLED,
                                   LA_EVENT_IPV6_UC_FORWARDING_DISABLED,
                                   LA_EVENT_IPV6_HOP_BY_HOP,
                                   LA_EVENT_IPV6_ILLEGAL_SIP,
                                   LA_EVENT_IPV6_ILLEGAL_DIP,
                                   LA_EVENT_IPV6_ZERO_PAYLOAD,
                                   LA_EVENT_IPV6_NEXT_HEADER_CHECK,
                                   LA_EVENT_MPLS_UNKNOWN_PROTOCOL_AFTER_BOS,
                                   LA_EVENT_MPLS_TTL_IS_ZERO,
                                   LA_EVENT_MPLS_BFD_OVER_PWE_TTL,
                                   LA_EVENT_MPLS_BFD_OVER_PWE_RAW,
                                   LA_EVENT_MPLS_BFD_OVER_PWE_IPV4,
                                   LA_EVENT_MPLS_BFD_OVER_PWE_IPV6,
                                   LA_EVENT_MPLS_UNKNOWN_BFD_G_ACH_CHANNEL_TYPE,
                                   LA_EVENT_MPLS_BFD_OVER_PWE_RA,
                                   LA_EVENT_MPLS_MPLS_TP_OVER_PWE,
                                   LA_EVENT_MPLS_UNKNOWN_G_ACH,
                                   LA_EVENT_MPLS_MPLS_TP_OVER_LSP,
                                   LA_EVENT_MPLS_OAM_ALERT_LABEL,
                                   LA_EVENT_MPLS_EXTENSION_LABEL,
                                   LA_EVENT_MPLS_ROUTER_ALERT_LABEL,
                                   LA_EVENT_MPLS_UNEXPECTED_RESERVED_LABEL,
                                   LA_EVENT_MPLS_FORWARDING_DISABLED,
                                   LA_EVENT_MPLS_ILM_MISS,
                                   LA_EVENT_MPLS_IPV4_OVER_IPV6_EXPLICIT_NULL,
                                   LA_EVENT_MPLS_INVALID_TTL,
                                   LA_EVENT_MPLS_TE_MIDPOPINT_LDP_LABELS_MISS,
                                   LA_EVENT_MPLS_ASBR_LABEL_MISS,
                                   LA_EVENT_MPLS_ILM_VRF_LABEL_MISS,
                                   LA_EVENT_L3_IP_MULTICAST_RPF,
                                   LA_EVENT_L3_IP_MC_DROP,
                                   LA_EVENT_L3_IP_MC_PUNT_DC_PASS,
                                   LA_EVENT_L3_IP_MC_SNOOP_DC_PASS,
                                   LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL,
                                   LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL,
                                   LA_EVENT_L3_IP_MC_SNOOP_LOOKUP_MISS,
                                   LA_EVENT_L3_IP_MULTICAST_NOT_FOUND,
                                   LA_EVENT_L3_IP_MC_S_G_PUNT_MEMBER,
                                   LA_EVENT_L3_IP_MC_G_PUNT_MEMBER,
                                   LA_EVENT_L3_IP_MC_EGRESS_PUNT,
                                   LA_EVENT_L3_ISIS_OVER_L3,
                                   LA_EVENT_L3_ISIS_DRAIN,
                                   LA_EVENT_L3_NO_HBM_ACCESS_DIP,
                                   LA_EVENT_L3_NO_HBM_ACCESS_SIP,
                                   LA_EVENT_L3_LPM_ERROR,
                                   LA_EVENT_L3_LPM_DROP,
                                   LA_EVENT_L3_NO_LP_OVER_LAG_MAPPING,
                                   LA_EVENT_L3_ACL_FORCE_PUNT,
                                   LA_EVENT_L3_LPM_DEFAULT_DROP,
                                   LA_EVENT_L3_LPM_INCOMPLETE0,
                                   LA_EVENT_L3_LPM_INCOMPLETE2,
                                   LA_EVENT_L3_BFD_MICRO_IP_DISABLED,
                                   LA_EVENT_L3_NO_VNI_MAPPING,
                                   LA_EVENT_L3_NO_L3_DLP_MAPPING,
                                   LA_EVENT_L3_L3_DLP_DISABLED,
                                   LA_EVENT_L3_SPLIT_HORIZON,
                                   LA_EVENT_L3_NO_VPN_LABEL_FOUND})},
        {SAI_IN_DROP_REASON_MC_DMAC_MISMATCH, debug_counter_val_getter({LA_EVENT_IPV4_NON_COMP_MC, LA_EVENT_IPV6_NON_COMP_MC})},
        {SAI_IN_DROP_REASON_BLACKHOLE_ROUTE, debug_counter_val_getter({LA_EVENT_L3_DROP_ADJ, LA_EVENT_L3_DROP_ADJ_NON_INJECT})},
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
        {SAI_IN_DROP_REASON_FDB_AND_BLACKHOLE_DISCARDS,
         debug_counter_val_getter({LA_EVENT_L3_DROP_ADJ, LA_EVENT_L3_DROP_ADJ_NON_INJECT})},
#endif
    };
    // map SAI out drop reason to value getter class
    const std::unordered_map<uint32_t, debug_counter_val_getter> m_sai_to_la_counter_translation_out;
};
}
}
#endif
