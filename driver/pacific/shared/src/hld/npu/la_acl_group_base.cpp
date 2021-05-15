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

#include "la_acl_group_base.h"
#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "npu/la_acl_delegate.h"
#include "system/la_device_impl.h"
#include <algorithm>

namespace silicon_one
{
la_acl_group_base::la_acl_group_base(const la_device_impl_wptr& device)
    : m_device(device),
      m_ethernet_acls(),
      m_real_ethernet_acls(),
      m_ipv4_acls(),
      m_real_ipv4_acls(),
      m_ipv6_acls(),
      m_real_ipv6_acls()
{
}

la_acl_group_base::~la_acl_group_base()
{
}

la_status
la_acl_group_base::initialize(la_object_id_t oid)
{
    m_oid = oid;

    return LA_STATUS_SUCCESS;
}

void
la_acl_group_base::extract_real_acls(const la_acl_wptr_vec_t& acls, la_acl_wptr_vec_t& real_acls)
{
    for (auto acl : acls) {
        if (acl) {
            real_acls.push_back(acl);
        }
    }
}

la_status
la_acl_group_base::do_set_acls(la_acl_packet_format_e packet_format, const la_acl_wptr_vec_t& acls)
{

    bool notify_acl_group_changed = false;
    la_status status = validate_acls(packet_format, acls);
    return_on_error(status);
    la_acl_wptr_vec_t real_acls{};
    la_acl_wptr_vec_t real_ethernet_acls{};
    la_acl_wptr_vec_t real_ipv4_acls{};
    la_acl_wptr_vec_t real_ipv6_acls{};
    extract_real_acls(acls, real_acls);

    if (packet_format == la_acl_packet_format_e::ETHERNET) {
        for (auto acl : m_ethernet_acls) {
            if (acl != nullptr) {
                m_device->remove_object_dependency(acl, this);
            }
        }
        extract_real_acls(m_ethernet_acls, real_ethernet_acls);
        if (real_ethernet_acls != real_acls) {
            notify_acl_group_changed = true;
        }
        m_ethernet_acls = acls;
        m_real_ethernet_acls = real_acls;
    } else if (packet_format == la_acl_packet_format_e::IPV4) {
        for (auto acl : m_ipv4_acls) {
            if (acl != nullptr) {
                m_device->remove_object_dependency(acl, this);
            }
        }
        extract_real_acls(m_ipv4_acls, real_ipv4_acls);
        if (real_ipv4_acls != real_acls) {
            notify_acl_group_changed = true;
        }
        m_ipv4_acls = acls;
        m_real_ipv4_acls = real_acls;
    } else if (packet_format == la_acl_packet_format_e::IPV6) {
        for (auto acl : m_ipv6_acls) {
            if (acl != nullptr) {
                m_device->remove_object_dependency(acl, this);
            }
        }
        extract_real_acls(m_ipv6_acls, real_ipv6_acls);
        if (real_ipv6_acls != real_acls) {
            notify_acl_group_changed = true;
        }
        m_ipv6_acls = acls;
        m_real_ipv6_acls = real_acls;
    } else {
        return LA_STATUS_EINVAL;
    }

    for (auto acl : real_acls) {
        m_device->add_object_dependency(acl, this);
    }

    if (notify_acl_group_changed) {
        notify_acl_group_change(packet_format);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::set_acls(la_acl_packet_format_e packet_format, const la_acl_vec_t& acls)
{
    start_api_call("packet_format=", packet_format, "acls=", acls);

    la_acl_wptr_vec_t sp_acls{};
    std::transform(acls.cbegin(), acls.cend(), std::back_inserter(sp_acls), [this](silicon_one::la_acl* acl) -> const la_acl_wptr {
        return m_device->get_sptr(acl);
    });
    la_status status = do_set_acls(packet_format, sp_acls);

    return status;
}

la_status
la_acl_group_base::allocate_rtf_conf_set_id_and_config_mapping(la_slice_id_vec_t slices)
{
    la_status status;

    acl_group_rtf_conf_set_id_t rtf_conf_set_id;
    status = allocate_rtf_conf_set_id(rtf_conf_set_id);
    return_on_error(status);

    for (la_slice_id_t slice : slices) {
        status = config_eth_rtf_conf_set_mapping(slice, rtf_conf_set_id, m_real_ethernet_acls);
        return_on_error(status);

        status = config_ipv4_rtf_conf_set_mapping(slice, rtf_conf_set_id, m_real_ipv4_acls);
        return_on_error(status);

        status = config_ipv6_rtf_conf_set_mapping(slice, rtf_conf_set_id, m_real_ipv6_acls);
        return_on_error(status);

        status = config_l2_rtf_conf_set(slice, rtf_conf_set_id);
        return_on_error(status);

        status = config_rtf_conf_set_to_post_fwd_stage(slice, rtf_conf_set_id);
        return_on_error(status);

        status = config_rtf_conf_set_to_og_pcl_configs(slice, rtf_conf_set_id);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::get_real_acls(la_acl_packet_format_e packet_format, la_acl_wptr_vec_t& out_real_acls) const
{
    if (packet_format == la_acl_packet_format_e::ETHERNET) {
        out_real_acls = m_real_ethernet_acls;
    } else if (packet_format == la_acl_packet_format_e::IPV4) {
        out_real_acls = m_real_ipv4_acls;
    } else if (packet_format == la_acl_packet_format_e::IPV6) {
        out_real_acls = m_real_ipv6_acls;
    } else {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::do_get_acls(la_acl_packet_format_e packet_format, la_acl_wptr_vec_t& out_acls) const
{
    la_acl_wptr_vec_t temp_vec{};
    if (packet_format == la_acl_packet_format_e::ETHERNET) {
        temp_vec = m_ethernet_acls;
    } else if (packet_format == la_acl_packet_format_e::IPV4) {
        temp_vec = m_ipv4_acls;
    } else if (packet_format == la_acl_packet_format_e::IPV6) {
        temp_vec = m_ipv6_acls;
    } else {
        return LA_STATUS_EINVAL;
    }
    out_acls = temp_vec;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::get_acls(la_acl_packet_format_e packet_format, la_acl_vec_t& out_acls) const
{
    start_api_getter_call("packet_format=", packet_format);

    la_acl_wptr_vec_t temp_vec{};
    la_status status = do_get_acls(packet_format, temp_vec);
    out_acls.clear();
    std::transform(temp_vec.begin(), temp_vec.end(), std::back_inserter(out_acls), [](la_acl_wptr& acl_sp) -> silicon_one::la_acl* {
        return acl_sp.get();
    });

    return status;
}

la_status
la_acl_group_base::reset_acl_group_cfg(acl_group_rtf_conf_set_id_t rtf_conf_set_id)
{
    const la_acl_wptr_vec_t empty_acl_vec{};
    for (la_slice_id_t slice : m_device->get_used_slices()) {
        la_status status = config_eth_rtf_conf_set_mapping(slice, rtf_conf_set_id, empty_acl_vec);
        return_on_error(status);
        status = config_ipv4_rtf_conf_set_mapping(slice, rtf_conf_set_id, empty_acl_vec);
        return_on_error(status);
        status = config_ipv6_rtf_conf_set_mapping(slice, rtf_conf_set_id, empty_acl_vec);
        return_on_error(status);
        status = config_l2_rtf_conf_set(slice, rtf_conf_set_id);
        return_on_error(status);
        status = config_rtf_conf_set_to_post_fwd_stage(slice, rtf_conf_set_id);
        return_on_error(status);
        status = config_rtf_conf_set_to_og_pcl_configs(slice, rtf_conf_set_id);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::allocate_rtf_conf_set_id(acl_group_rtf_conf_set_id_t& out_rtf_conf_set_id)
{
    acl_group_info_t entry_value{};
    out_rtf_conf_set_id = RTF_CONF_SET_ID_INVALID;

    if (!m_real_ethernet_acls.empty()) {
        entry_value.ethernet_acls = m_real_ethernet_acls;
        entry_value.ethernet_acls_size = m_real_ethernet_acls.size();
    }
    if (!m_real_ipv4_acls.empty()) {
        entry_value.ipv4_acls = m_real_ipv4_acls;
        entry_value.ipv4_acls_size = m_real_ipv4_acls.size();
    }
    if (!m_real_ipv6_acls.empty()) {
        entry_value.ipv6_acls = m_real_ipv6_acls;
        entry_value.ipv6_acls_size = m_real_ipv6_acls.size();
    }
    bool clear_old_value = false;
    uint64_t old_id = 0;

    // Check if we are about to release the old rtf conf set. If so,
    // we need to clear it. The profile allocator will delay reallocating it.
    if (m_acl_group_profile && (m_acl_group_profile.use_count() == 1)) {
        clear_old_value = true;
        old_id = m_acl_group_profile->id();
    }

    la_status status = m_device->m_profile_allocators.acl_group_entries->reallocate(m_acl_group_profile, entry_value);
    return_on_error(status, HLD, ERROR, "Out of acl group profiles");

    if (clear_old_value && (old_id != m_acl_group_profile->id())) {
        status = reset_acl_group_cfg(old_id);
        return_on_error(status);
    }
    out_rtf_conf_set_id = m_acl_group_profile->id();

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::get_rtf_conf_set_id(acl_group_rtf_conf_set_id_t& out_rtf_conf_set_id) const
{
    if (m_acl_group_profile != nullptr) {
        out_rtf_conf_set_id = m_acl_group_profile->id();
    } else {
        out_rtf_conf_set_id = RTF_CONF_SET_ID_INVALID;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    for (auto acl : m_real_ethernet_acls) {
        m_device->remove_object_dependency(acl, this);
    }
    for (auto acl : m_real_ipv4_acls) {
        m_device->remove_object_dependency(acl, this);
    }
    for (auto acl : m_real_ipv6_acls) {
        m_device->remove_object_dependency(acl, this);
    }
    if (m_acl_group_profile.use_count() == 1) {
        acl_group_rtf_conf_set_id_t rtf_conf_set_id = m_acl_group_profile->id();
        la_status status = reset_acl_group_cfg(rtf_conf_set_id);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

// la_object API-s
la_object::object_type_e
la_acl_group_base::type() const
{
    return object_type_e::ACL_GROUP;
}

const la_device*
la_acl_group_base::get_device() const
{
    return m_device.get();
}

uint64_t
la_acl_group_base::oid() const
{
    return m_oid;
}

std::string
la_acl_group_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_acl_group_base(oid=" << m_oid << ")";
    return log_message.str();
}

npl_init_rtf_stage_and_type_e
la_acl_group_base::get_init_ip_rtf_stage(la_acl_packet_format_e packet_format, const la_acl_wptr_vec_t& acls) const
{
    if ((packet_format == la_acl_packet_format_e::IPV4) || (packet_format == la_acl_packet_format_e::IPV6)) {
        for (uint16_t acl_index = 0; acl_index < acls.size(); acl_index++) {
            if (acls[acl_index] != nullptr) {
                la_acl_packet_processing_stage_e stage;
                const auto& acl_impl = acls[acl_index].weak_ptr_static_cast<la_acl_impl>();
                bool is_og_acl = acl_impl->is_og_acl();
                if (is_og_acl) {
                    return NPL_INIT_RTF_OG;
                }
                la_status status = acl_impl->get_rtf_stage(stage);
                if (status != LA_STATUS_SUCCESS) {
                    return NPL_INIT_RTF_NONE;
                }
                const la_acl_key_profile* acl_key_profile;
                status = acl_impl->get_acl_key_profile(acl_key_profile);
                if (status != LA_STATUS_SUCCESS) {
                    return NPL_INIT_RTF_NONE;
                }
                la_acl_key_type_e acl_key_profile_key_type;
                status = acl_key_profile->get_key_type(acl_key_profile_key_type);
                if (status != LA_STATUS_SUCCESS) {
                    return NPL_INIT_RTF_NONE;
                }
                switch (stage) {
                case la_acl_packet_processing_stage_e::PRE_FORWARDING:
                    if (acl_key_profile_key_type == la_acl_key_type_e::ETHERNET)
                        return NPL_INIT_RTF_PRE_FWD_L2;
                    return NPL_INIT_RTF_PRE_FWD_L3;
                case la_acl_packet_processing_stage_e::POST_FORWARDING:
                    return NPL_INIT_RTF_NONE;
                case la_acl_packet_processing_stage_e::RX_DONE:
                    return NPL_INIT_RTF_NONE;
                default:
                    return NPL_INIT_RTF_NONE;
                }
            }
        }
    }

    return NPL_INIT_RTF_NONE;
}

la_status
la_acl_group_base::validate_acls(la_acl_packet_format_e packet_format, const la_acl_wptr_vec_t& acls) const
{
    la_status status;
    bool found_ingress_acl = false;
    bool found_egress_acl = false;

    uint32_t acls_num = 0;

    for (auto acl : acls) {
        if (acl != nullptr) {
            acls_num++;
        }
    }

    // check size
    if (acls_num > NUM_ACL_GROUP_ACLS) {
        log_err(HLD,
                "la_acl_group_base::%s number of acls for %s type (%d) exceeds maximum (%d)",
                __func__,
                silicon_one::to_string(packet_format).c_str(),
                acls_num,
                NUM_ACL_GROUP_ACLS);
        return LA_STATUS_EINVAL;
    }

    // check direction
    for (auto acl : acls) {
        if (acl == nullptr) {
            continue;
        }
        const la_acl_key_profile* acl_key_profile;
        status = acl->get_acl_key_profile(acl_key_profile);
        return_on_error(status);

        la_acl_direction_e dir = acl_key_profile->get_direction();
        if (dir == la_acl_direction_e::INGRESS) {
            found_ingress_acl = true;
        } else {
            found_egress_acl = true;
        }
        if (found_ingress_acl && found_egress_acl) {
            log_err(HLD, "la_acl_group_base::%s acls list can't include both ingress and egress acls", __func__);
            return LA_STATUS_EINVAL;
        }
    }

    // OG ACL can only be in first step in ACL group
    bool found_first_acl = false;
    for (auto acl : acls) {
        if (acl == nullptr) {
            continue;
        }
        auto acl_impl = acl.weak_ptr_static_cast<la_acl_impl>();
        if (found_first_acl && acl_impl->is_og_acl()) {
            log_err(HLD, "la_acl_group_base::%s OG ACL can be only first acl in acl group", __func__);
            return LA_STATUS_EINVAL;
        }
        if (!found_first_acl) {
            found_first_acl = true;
        }
    }

    if (packet_format == la_acl_packet_format_e::ETHERNET) {
        // for ethernet packet formats acls vectors can include ethernet key profiles only
        for (auto acl : acls) {
            if (acl == nullptr) {
                continue;
            }
            /// check acl key profile type
            const la_acl_key_profile* acl_key_profile;
            status = acl->get_acl_key_profile(acl_key_profile);
            return_on_error(status);

            la_acl_key_type_e key_type;
            status = acl_key_profile->get_key_type(key_type);
            return_on_error(status);

            if (key_type != la_acl_key_type_e::ETHERNET) {
                log_err(HLD, "la_acl_group_base::%s ethernet acls list can include only ethernet acls", __func__);
                return LA_STATUS_EINVAL;
            }
        }
    } else if (packet_format == la_acl_packet_format_e::IPV4) {
        // for ipv4 packet formats acls vectors can include ipv4 and ethernet key profiles
        for (auto acl : acls) {
            if (acl == nullptr) {
                continue;
            }
            /// check acl key profile type
            const la_acl_key_profile* acl_key_profile;
            status = acl->get_acl_key_profile(acl_key_profile);
            return_on_error(status);

            la_acl_key_type_e key_type;
            status = acl_key_profile->get_key_type(key_type);
            return_on_error(status);

            if ((key_type != la_acl_key_type_e::IPV4) && (key_type != la_acl_key_type_e::ETHERNET)) {
                log_err(HLD, "la_acl_group_base::%s ipv4 acls list can include only ipv4 and ethernet  acls", __func__);
                return LA_STATUS_EINVAL;
            }
        }
    } else if (packet_format == la_acl_packet_format_e::IPV6) {
        // for ipv6 packet formats acls vectors can include ipv6 and ethernet key profiles
        for (auto acl : acls) {
            if (acl == nullptr) {
                continue;
            }
            /// check acl key profile type
            const la_acl_key_profile* acl_key_profile;
            status = acl->get_acl_key_profile(acl_key_profile);
            return_on_error(status);

            la_acl_key_type_e key_type;
            status = acl_key_profile->get_key_type(key_type);
            return_on_error(status);

            if ((key_type != la_acl_key_type_e::IPV6) && (key_type != la_acl_key_type_e::ETHERNET)) {
                log_err(HLD, "la_acl_group_base::%s ipv6 acls list can include only ipv6 and ethernet  acls", __func__);
                return LA_STATUS_EINVAL;
            }
        }
    }

    // validate acls stages order.

    if (packet_format == la_acl_packet_format_e::ETHERNET) {
        npl_rtf_stage_and_type_e stage;
        std::vector<npl_rtf_stage_and_type_e> eth_stages = {};
        stage = get_init_eth_rtf_stage(packet_format, acls);
        eth_stages.push_back(stage);
        uint64_t acl_index = 0;
        for (auto acl : acls) {
            if (acl != nullptr) {
                stage = get_next_rtf_stage(packet_format, acls, acl_index);
                eth_stages.push_back(stage);
            }
            acl_index++;
        }
        if (eth_stages.size() > 1) {
            for (uint32_t i = 0; i < eth_stages.size() - 1; i++) {
                if ((eth_stages[i] == NPL_RTF_NONE) || (eth_stages[i + 1] == NPL_RTF_NONE)) {
                    continue;
                }
                if (eth_stages[i] > eth_stages[i + 1]) {
                    log_err(HLD, "la_acl_group_base::%s invalid ethernet acls stages order", __func__);
                    return LA_STATUS_EINVAL;
                }
            }
        }
    }

    if ((packet_format == la_acl_packet_format_e::IPV4) || (packet_format == la_acl_packet_format_e::IPV6)) {
        npl_init_rtf_stage_and_type_e init_stage;
        npl_rtf_stage_and_type_e stage;
        init_stage = get_init_ip_rtf_stage(packet_format, acls);
        std::vector<npl_rtf_stage_and_type_e> ip_stages = {};
        switch (init_stage) {
        case npl_init_rtf_stage_and_type_e::NPL_INIT_RTF_NONE:
            ip_stages.push_back(npl_rtf_stage_and_type_e::NPL_RTF_NONE);
            break;
        case npl_init_rtf_stage_and_type_e::NPL_INIT_RTF_OG:
            ip_stages.push_back(npl_rtf_stage_and_type_e::NPL_RTF_OG);
            break;
        case npl_init_rtf_stage_and_type_e::NPL_INIT_RTF_PRE_FWD_L2:
            ip_stages.push_back(npl_rtf_stage_and_type_e::NPL_RTF_PRE_FWD_L2);
            break;
        case npl_init_rtf_stage_and_type_e::NPL_INIT_RTF_PRE_FWD_L3:
            ip_stages.push_back(npl_rtf_stage_and_type_e::NPL_RTF_PRE_FWD_L3);
            break;
        }
        uint64_t acl_index = 0;
        for (auto acl : acls) {
            if (acl != nullptr) {
                stage = get_next_rtf_stage(packet_format, acls, acl_index);
                ip_stages.push_back(stage);
            }
            acl_index++;
        }
        if (ip_stages.size() > 1) {
            for (uint32_t i = 0; i < ip_stages.size() - 1; i++) {
                if ((ip_stages[i] == NPL_RTF_NONE) || (ip_stages[i + 1] == NPL_RTF_NONE)) {
                    continue;
                }
                if (ip_stages[i] > ip_stages[i + 1]) {
                    if ((ip_stages[i] == npl_rtf_stage_and_type_e::NPL_RTF_PRE_FWD_L3)
                        && (ip_stages[i + 1] == npl_rtf_stage_and_type_e::NPL_RTF_OG)) {
                        continue;
                    } else {
                        log_err(HLD, "la_acl_group_base::%s invalid ip acls stages order", __func__);
                        return LA_STATUS_EINVAL;
                    }
                }
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::config_eth_rtf_conf_set_mapping_entry(la_slice_id_t slice,
                                                         acl_group_rtf_conf_set_id_t rtf_conf_set_id,
                                                         uint64_t step,
                                                         la_acl_id_t acl_id,
                                                         npl_fwd0_table_index_e table_index,
                                                         npl_rtf_stage_and_type_e next_rtf_stage,
                                                         uint64_t stop_on_step) const
{
    npl_eth_rtf_conf_set_mapping_table_key_t k;
    npl_eth_rtf_conf_set_mapping_table_value_t v;
    npl_eth_rtf_conf_set_mapping_table_t::entry_pointer_type e = nullptr;
    const auto& table(m_device->m_tables.eth_rtf_conf_set_mapping_table[slice]);
    auto& rtf_iteration_prop = v.payloads.eth_rtf_iteration_prop;

    k.lp_rtf_conf_set.val = rtf_conf_set_id;
    k.rtf_step.val = step;

    rtf_iteration_prop.f0_rtf_prop.acl_id = acl_id;
    rtf_iteration_prop.f0_rtf_prop.table_index = static_cast<npl_eth_table_index_e>(table_index);
    rtf_iteration_prop.stop_on_step_and_next_stage_compressed_fields.next_rtf_stage = next_rtf_stage;
    rtf_iteration_prop.stop_on_step_and_next_stage_compressed_fields.stop_on_step = stop_on_step;

    la_status status = table->set(k, v, e);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::config_ipv4_rtf_conf_set_mapping_entry(la_slice_id_t slice,
                                                          acl_group_rtf_conf_set_id_t rtf_conf_set_id,
                                                          uint64_t step,
                                                          la_acl_id_t acl_id,
                                                          npl_fwd0_table_index_e table_index,
                                                          npl_rtf_stage_and_type_e next_rtf_stage,
                                                          uint64_t stop_on_step) const
{
    npl_ipv4_rtf_conf_set_mapping_table_key_t k;
    npl_ipv4_rtf_conf_set_mapping_table_value_t v;
    npl_ipv4_rtf_conf_set_mapping_table_t::entry_pointer_type e = nullptr;
    const auto& table(m_device->m_tables.ipv4_rtf_conf_set_mapping_table[slice]);
    auto& rtf_iteration_prop = v.payloads.ipv4_rtf_iteration_prop;

    k.lp_rtf_conf_set.val = rtf_conf_set_id;
    k.rtf_step.val = step;

    rtf_iteration_prop.f0_rtf_prop.ip_rtf.acl_id = acl_id;
    rtf_iteration_prop.f0_rtf_prop.ip_rtf.table_index = table_index;
    rtf_iteration_prop.stop_on_step_and_next_stage_compressed_fields.next_rtf_stage = next_rtf_stage;
    rtf_iteration_prop.stop_on_step_and_next_stage_compressed_fields.stop_on_step = stop_on_step;
    rtf_iteration_prop.use_fwd1_interface = 0;

    la_status status = table->set(k, v, e);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::config_ipv6_rtf_conf_set_mapping_entry(la_slice_id_t slice,
                                                          acl_group_rtf_conf_set_id_t rtf_conf_set_id,
                                                          uint64_t step,
                                                          la_acl_id_t acl_id,
                                                          npl_fwd0_table_index_e table_index,
                                                          npl_rtf_stage_and_type_e next_rtf_stage,
                                                          uint64_t stop_on_step) const
{
    npl_ipv6_rtf_conf_set_mapping_table_key_t k;
    npl_ipv6_rtf_conf_set_mapping_table_value_t v;
    npl_ipv6_rtf_conf_set_mapping_table_t::entry_pointer_type e = nullptr;
    const auto& table(m_device->m_tables.ipv6_rtf_conf_set_mapping_table[slice]);
    auto& rtf_iteration_prop = v.payloads.ipv6_rtf_iteration_prop;

    k.lp_rtf_conf_set.val = rtf_conf_set_id;
    k.rtf_step.val = step;

    rtf_iteration_prop.f0_rtf_prop.ip_rtf.acl_id = acl_id;
    rtf_iteration_prop.f0_rtf_prop.ip_rtf.table_index = table_index;
    rtf_iteration_prop.stop_on_step_and_next_stage_compressed_fields.next_rtf_stage = next_rtf_stage;
    rtf_iteration_prop.stop_on_step_and_next_stage_compressed_fields.stop_on_step = stop_on_step;
    rtf_iteration_prop.use_fwd1_interface = 0;

    la_status status = table->set(k, v, e);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::config_eth_rtf_conf_set_mapping(la_slice_id_t slice,
                                                   acl_group_rtf_conf_set_id_t rtf_conf_set_id,
                                                   const la_acl_wptr_vec_t& acls) const
{
    uint64_t step = 0;
    uint64_t acl_index = 0;
    la_status status;

    for (auto acl : acls) {
        if (acl != nullptr) {
            auto acl_delegate = get_delegate(acl);
            if (acl_delegate == nullptr) {
                return LA_STATUS_EUNKNOWN;
            }

            const la_acl_key_profile* acl_key_profile;
            status = acl->get_acl_key_profile(acl_key_profile);
            return_on_error(status);

            const la_acl_key_profile_base* acl_key_profile_impl = static_cast<const la_acl_key_profile_base*>(acl_key_profile);
            la_acl_id_t acl_id = la_device_impl::ACL_INVALID_ID;
            acl_delegate->get_id(slice / 2, acl_id);

            npl_fwd0_table_index_e table_index;
            status = acl_key_profile_impl->get_fwd0_table_index(table_index);
            return_on_error(status);
            npl_rtf_stage_and_type_e next_rtf_stage = get_next_rtf_stage(la_acl_packet_format_e::ETHERNET, acls, acl_index);

            status = config_eth_rtf_conf_set_mapping_entry(
                slice, rtf_conf_set_id, step, acl_id, table_index, next_rtf_stage, 0 /* stop_on_step */);
            return_on_error(status);
            step++;
        }
        acl_index++;
    }
    for (; step < NUM_ACL_GROUP_ACLS; step++) {
        status = config_eth_rtf_conf_set_mapping_entry(slice,
                                                       rtf_conf_set_id,
                                                       step,
                                                       la_device_impl::ACL_INVALID_ID,
                                                       NPL_RTF_DB1_160_FWD0_TABLE,
                                                       NPL_RTF_NONE /* next_rtf_stage */,
                                                       0 /* stop_on_step */);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::config_ipv4_rtf_conf_set_mapping(la_slice_id_t slice,
                                                    acl_group_rtf_conf_set_id_t rtf_conf_set_id,
                                                    const la_acl_wptr_vec_t& acls) const
{
    uint64_t step = 0;
    uint64_t acl_index = 0;
    la_status status;
    for (auto acl : acls) {
        if (acl != nullptr) {
            auto acl_delegate = get_delegate(acl);
            if (acl_delegate == nullptr) {
                return LA_STATUS_EUNKNOWN;
            }

            const la_acl_key_profile* acl_key_profile;
            status = acl->get_acl_key_profile(acl_key_profile);
            return_on_error(status);

            const la_acl_key_profile_base* acl_key_profile_impl = static_cast<const la_acl_key_profile_base*>(acl_key_profile);
            la_acl_id_t acl_id = la_device_impl::ACL_INVALID_ID;
            acl_delegate->get_id(slice / 2, acl_id);

            npl_fwd0_table_index_e table_index;
            status = acl_key_profile_impl->get_fwd0_table_index(table_index);
            return_on_error(status);
            npl_rtf_stage_and_type_e next_rtf_stage = get_next_rtf_stage(la_acl_packet_format_e::IPV4, acls, acl_index);

            status = config_ipv4_rtf_conf_set_mapping_entry(
                slice, rtf_conf_set_id, step, acl_id, table_index, next_rtf_stage, 0 /* stop_on_step */);
            return_on_error(status);
            step++;
        }
        acl_index++;
    }
    for (; step < NUM_ACL_GROUP_ACLS; step++) {
        status = config_ipv4_rtf_conf_set_mapping_entry(slice,
                                                        rtf_conf_set_id,
                                                        step,
                                                        la_device_impl::ACL_INVALID_ID,
                                                        NPL_RTF_DB1_160_FWD0_TABLE,
                                                        NPL_RTF_NONE /* next_rtf_stage */,
                                                        0 /* stop_on_step */);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::config_ipv6_rtf_conf_set_mapping(la_slice_id_t slice,
                                                    acl_group_rtf_conf_set_id_t rtf_conf_set_id,
                                                    const la_acl_wptr_vec_t& acls) const
{
    uint64_t step = 0;
    uint64_t acl_index = 0;
    la_status status;
    for (auto acl : acls) {
        if (acl != nullptr) {
            auto acl_delegate = get_delegate(acl);
            if (acl_delegate == nullptr) {
                return LA_STATUS_EUNKNOWN;
            }

            const la_acl_key_profile* acl_key_profile;
            status = acl->get_acl_key_profile(acl_key_profile);
            return_on_error(status);

            const la_acl_key_profile_base* acl_key_profile_impl = static_cast<const la_acl_key_profile_base*>(acl_key_profile);
            la_acl_id_t acl_id = la_device_impl::ACL_INVALID_ID;
            acl_delegate->get_id(slice / 2, acl_id);

            npl_fwd0_table_index_e table_index;
            status = acl_key_profile_impl->get_fwd0_table_index(table_index);
            return_on_error(status);
            npl_rtf_stage_and_type_e next_rtf_stage = get_next_rtf_stage(la_acl_packet_format_e::IPV6, acls, acl_index);

            status = config_ipv6_rtf_conf_set_mapping_entry(
                slice, rtf_conf_set_id, step, acl_id, table_index, next_rtf_stage, 0 /* stop_on_step */);
            return_on_error(status);
            step++;
        }
        acl_index++;
    }
    for (; step < NUM_ACL_GROUP_ACLS; step++) {
        status = config_ipv6_rtf_conf_set_mapping_entry(slice,
                                                        rtf_conf_set_id,
                                                        step,
                                                        la_device_impl::ACL_INVALID_ID,
                                                        NPL_RTF_DB1_160_FWD0_TABLE,
                                                        NPL_RTF_NONE /* next_rtf_stage */,
                                                        0 /* stop_on_step */);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::config_l2_rtf_conf_set_and_init_stages(la_slice_id_t slice, acl_group_rtf_conf_set_id_t rtf_conf_set_id)
{
    npl_get_l2_rtf_conf_set_and_init_stages_key_t k;
    npl_get_l2_rtf_conf_set_and_init_stages_value_t v;
    npl_get_l2_rtf_conf_set_and_init_stages_t::entry_pointer_type e = nullptr;
    const auto& table(m_device->m_tables.get_l2_rtf_conf_set_and_init_stages[slice]);
    auto& l2_rtf_conf_set_and_init_stages = v.payloads.l2_rtf_conf_set_and_init_stages;

    k.rtf_conf_set_ptr = rtf_conf_set_id;

    npl_init_rtf_stage_and_type_e npl_init_rtf_stage;
    npl_init_rtf_stage = get_init_ip_rtf_stage(la_acl_packet_format_e::IPV4, m_real_ipv4_acls);
    l2_rtf_conf_set_and_init_stages.rtf_conf_set_and_stages.ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage = npl_init_rtf_stage;

    npl_init_rtf_stage = get_init_ip_rtf_stage(la_acl_packet_format_e::IPV6, m_real_ipv6_acls);
    l2_rtf_conf_set_and_init_stages.rtf_conf_set_and_stages.ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage = npl_init_rtf_stage;
    l2_rtf_conf_set_and_init_stages.rtf_conf_set_and_stages.rtf_conf_set.val = rtf_conf_set_id;

    npl_rtf_stage_and_type_e npl_init_eth_rtf_stage
        = get_init_eth_rtf_stage(la_acl_packet_format_e::ETHERNET, m_real_ethernet_acls);
    l2_rtf_conf_set_and_init_stages.eth_rtf_stage = npl_init_eth_rtf_stage;

    la_status status = table->set(k, v, e);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::config_l2_rtf_conf_set(la_slice_id_t slice, acl_group_rtf_conf_set_id_t rtf_conf_set_id)
{
    la_status status = config_l2_rtf_conf_set_and_init_stages(slice, rtf_conf_set_id);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::config_rtf_conf_set_to_post_fwd_stage(la_slice_id_t slice, acl_group_rtf_conf_set_id_t rtf_conf_set_id)
{
    npl_rtf_stage_and_type_e post_fwd_rtf_stage;
    npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t k;
    npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t v;
    npl_rtf_conf_set_to_post_fwd_stage_mapping_table_t::entry_pointer_type e = nullptr;
    const auto& table(m_device->m_tables.rtf_conf_set_to_post_fwd_stage_mapping_table[slice]);
    auto& post_fwd_params = v.payloads.post_fwd_params;

    k.lp_rtf_conf_set.val = rtf_conf_set_id;
    k.ip_version = NPL_IP_VERSION_IPV4;

    post_fwd_params.use_metedata_table_per_packet_format.use_metadata_table_for_ip_packet.val = NPL_FALSE_VALUE;
    post_fwd_params.use_metedata_table_per_packet_format.use_metadata_table_for_non_ip_packet.val = NPL_FALSE_VALUE;
    for (auto acl : m_real_ipv4_acls) {
        const auto& acl_impl = acl.weak_ptr_static_cast<la_acl_impl>();
        if (acl_impl->is_class_id_enabled()) {
            post_fwd_params.use_metedata_table_per_packet_format.use_metadata_table_for_ip_packet.val = NPL_TRUE_VALUE;
            break;
        }
    }
    for (auto acl : m_real_ethernet_acls) {
        const auto& acl_impl = acl.weak_ptr_static_cast<la_acl_impl>();
        if (acl_impl->is_class_id_enabled()) {
            post_fwd_params.use_metedata_table_per_packet_format.use_metadata_table_for_non_ip_packet.val = NPL_TRUE_VALUE;
            break;
        }
    }

    post_fwd_params.ip_ver_and_post_fwd_stage.ip_ver = NPL_IP_VERSION_IPV4;
    la_status status = get_post_fwd_rtf_stage(la_acl_packet_format_e::IPV4, m_ipv4_acls, post_fwd_rtf_stage);
    return_on_error(status);
    post_fwd_params.ip_ver_and_post_fwd_stage.post_fwd_rtf_stage = post_fwd_rtf_stage;

    status = table->set(k, v, e);
    return_on_error(status);

    k.ip_version = NPL_IP_VERSION_IPV6;

    post_fwd_params.use_metedata_table_per_packet_format.use_metadata_table_for_ip_packet.val = NPL_FALSE_VALUE;
    for (auto acl : m_real_ipv6_acls) {
        const auto& acl_impl = acl.weak_ptr_static_cast<la_acl_impl>();
        if (acl_impl->is_class_id_enabled()) {
            post_fwd_params.use_metedata_table_per_packet_format.use_metadata_table_for_ip_packet.val = NPL_TRUE_VALUE;
            break;
        }
    }

    post_fwd_params.ip_ver_and_post_fwd_stage.ip_ver = NPL_IP_VERSION_IPV6;
    status = get_post_fwd_rtf_stage(la_acl_packet_format_e::IPV6, m_real_ipv6_acls, post_fwd_rtf_stage);
    return_on_error(status);
    post_fwd_params.ip_ver_and_post_fwd_stage.post_fwd_rtf_stage = post_fwd_rtf_stage;

    status = table->set(k, v, e);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_group_base::config_rtf_conf_set_to_og_pcl_configs(la_slice_id_t slice, acl_group_rtf_conf_set_id_t rtf_conf_set_id)
{
    npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t k1;
    npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t k2;
    npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t v1;
    npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t v2;
    npl_rtf_conf_set_to_og_pcl_ids_mapping_table_t::entry_pointer_type e1 = nullptr;
    npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_t::entry_pointer_type e2 = nullptr;
    const auto& table1(m_device->m_tables.rtf_conf_set_to_og_pcl_ids_mapping_table[slice]);
    const auto& table2(m_device->m_tables.rtf_conf_set_to_og_pcl_compress_bits_mapping_table[slice]);
    auto& per_rtf_step_og_pcl_ids = v1.payloads.per_rtf_step_og_pcl_ids;
    auto& per_rtf_step_og_pcl_compress_bits = v2.payloads.per_rtf_step_og_pcl_compress_bits;
    la_status status;
    la_pcl_gid_t pcl_gid;

    auto ipv4_size = m_real_ipv4_acls.size();
    auto ipv6_size = m_real_ipv6_acls.size();
    k1.lp_rtf_conf_set.val = rtf_conf_set_id;
    k2.lp_rtf_conf_set.val = rtf_conf_set_id;

    for (size_t rtf_step = 0; rtf_step < NUM_ACL_GROUP_ACLS; rtf_step++) {
        per_rtf_step_og_pcl_ids.ipv4_og_pcl_ids.src_pcl_id.val = 0;
        per_rtf_step_og_pcl_ids.ipv4_og_pcl_ids.dest_pcl_id.val = 0;
        per_rtf_step_og_pcl_compress_bits.ipv4_compress_bits.src_compress = 0;
        per_rtf_step_og_pcl_compress_bits.ipv4_compress_bits.dest_compress = 0;
        per_rtf_step_og_pcl_ids.ipv6_og_pcl_ids.src_pcl_id.val = 0;
        per_rtf_step_og_pcl_ids.ipv6_og_pcl_ids.dest_pcl_id.val = 0;
        per_rtf_step_og_pcl_compress_bits.ipv6_compress_bits.src_compress = 0;
        per_rtf_step_og_pcl_compress_bits.ipv6_compress_bits.dest_compress = 0;
        if (rtf_step < ipv4_size) {
            auto acl = m_real_ipv4_acls[rtf_step];
            const auto& acl_impl = acl.weak_ptr_static_cast<la_acl_impl>();
            if (acl_impl->is_og_acl()) {
                const auto& src_pcl = acl_impl->get_src_pcl();
                const auto& dst_pcl = acl_impl->get_dst_pcl();
                if (src_pcl) {
                    status = src_pcl->get_pcl_gid(pcl_gid);
                    return_on_error(status);
                    per_rtf_step_og_pcl_ids.ipv4_og_pcl_ids.src_pcl_id.val = pcl_gid;
                    per_rtf_step_og_pcl_compress_bits.ipv4_compress_bits.src_compress = 1;
                }
                if (dst_pcl) {
                    status = dst_pcl->get_pcl_gid(pcl_gid);
                    return_on_error(status);
                    per_rtf_step_og_pcl_ids.ipv4_og_pcl_ids.dest_pcl_id.val = pcl_gid;
                    per_rtf_step_og_pcl_compress_bits.ipv4_compress_bits.dest_compress = 1;
                }
            }
        }
        if (rtf_step < ipv6_size) {
            auto acl = m_real_ipv6_acls[rtf_step];
            const auto& acl_impl = acl.weak_ptr_static_cast<la_acl_impl>();
            if (acl_impl->is_og_acl()) {
                const auto& src_pcl = acl_impl->get_src_pcl();
                const auto& dst_pcl = acl_impl->get_dst_pcl();
                if (src_pcl) {
                    status = src_pcl->get_pcl_gid(pcl_gid);
                    return_on_error(status);
                    per_rtf_step_og_pcl_ids.ipv6_og_pcl_ids.src_pcl_id.val = pcl_gid;
                    per_rtf_step_og_pcl_compress_bits.ipv6_compress_bits.src_compress = 1;
                }
                if (dst_pcl) {
                    status = dst_pcl->get_pcl_gid(pcl_gid);
                    return_on_error(status);
                    per_rtf_step_og_pcl_ids.ipv6_og_pcl_ids.dest_pcl_id.val = pcl_gid;
                    per_rtf_step_og_pcl_compress_bits.ipv6_compress_bits.dest_compress = 1;
                }
            }
        }
        k1.rtf_step.val = rtf_step;
        status = table1->set(k1, v1, e1);
        return_on_error(status);
        k2.rtf_step.val = rtf_step;
        status = table2->set(k2, v2, e2);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

void
la_acl_group_base::notify_acl_group_change(la_acl_packet_format_e packet_format) const
{
    attribute_management_details amd;
    amd.op = attribute_management_op::ACL_GROUP_CHANGED;
    amd.packet_format = packet_format;
    la_amd_undo_callback_funct_t undo = [](attribute_management_details amd) { return amd; };

    la_status status = m_device->notify_attribute_changed(this, amd, undo);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD,
                "notify_acl_group_change failed to notify attribute acl group change in packet format %s (status = %s)",
                silicon_one::to_string(packet_format).c_str(),
                la_status2str(status).c_str());
    }
}

} // namespace silicon_one
