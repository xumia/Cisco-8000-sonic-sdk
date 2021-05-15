// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "la_acl_impl.h"
#include "api/npu/la_l2_destination.h"
#include "api/npu/la_l3_destination.h"
#include "la_acl_egress_sec_ipv4.h"
#include "la_acl_egress_sec_ipv6.h"
//#include "la_acl_egress_sec_mac_default.h"
#include "la_acl_generic.h"
#include "la_acl_security_group.h"
#include "nplapi/npl_types.h"
#include "system/la_device_impl.h"

#include "hld_utils.h"
#include "nplapi/npl_table_types.h"

#include "api_tracer.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_acl_impl::la_acl_impl(const la_device_impl_wptr& device)
    : m_device(device),
      m_delegate(nullptr),
      m_acl_key_profile(nullptr),
      m_acl_command_profile(nullptr),
      m_is_og_acl(false),
      m_is_class_id_enabled(false)
{
}

la_acl_impl::~la_acl_impl() = default;

la_status
la_acl_impl::initialize(la_object_id_t oid,
                        const la_acl_key_profile_base* acl_key_profile,
                        const la_acl_command_profile_base* acl_command_profile,
                        const la_pcl_wptr& src_pcl,
                        const la_pcl_wptr& dst_pcl)
{
    m_oid = oid;
    if (m_delegate != nullptr) {
        log_err(HLD, "Attempt to initialize already-initialized acl oid=%ld", m_oid);
    }

    const auto& acl_key_profile_sp = m_device->get_sptr(acl_key_profile);
    const auto& acl_command_profile_sp = m_device->get_sptr(acl_command_profile);

    m_acl_key_profile = acl_key_profile_sp;
    m_acl_command_profile = acl_command_profile_sp;
    la_acl_direction_e dir = acl_key_profile->get_direction();
    la_acl_key_type_e key_type;
    la_acl_key_profile_base::key_size_e key_size;

    key_size = acl_key_profile->get_key_size();

    la_status status = acl_key_profile->get_key_type(key_type);
    return_on_error(status);

    if (key_type == la_acl_key_type_e::SGACL) {
        m_delegate = std::make_shared<la_acl_security_group>(m_device, m_device->get_sptr(this));
    } else if (dir == la_acl_direction_e::EGRESS) {
        if (key_type == la_acl_key_type_e::ETHERNET) {
            // m_delegate = make_unique<la_acl_egress_sec_mac_default>(m_device, m_device->get_sptr(this));
        } else if (key_type == la_acl_key_type_e::IPV4) {
            m_delegate = make_unique<la_acl_egress_sec_ipv4>(m_device, m_device->get_sptr(this));
        } else if (key_type == la_acl_key_type_e::IPV6) {
            m_delegate = make_unique<la_acl_egress_sec_ipv6>(m_device, m_device->get_sptr(this));
        }
    } else {
        uint64_t udk_table_id = m_acl_key_profile->get_udk_table_id();
        if (key_type == la_acl_key_type_e::ETHERNET) {
            if (key_size == la_acl_key_profile_base::key_size_e::SIZE_160) {
                switch (udk_table_id) {
                case NPL_NETWORK_RX_ETH_RTF_MACRO_TABLE_ID_INGRESS_RTF_ETH_DB1_160_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_eth_db1_160_f0_trait> >(m_device,
                                                                                                         m_device->get_sptr(this));
                    break;
                case NPL_NETWORK_RX_ETH_RTF_MACRO_TABLE_ID_INGRESS_RTF_ETH_DB2_160_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_eth_db2_160_f0_trait> >(m_device,
                                                                                                         m_device->get_sptr(this));
                    break;
                }
            }
        } else if (key_type == la_acl_key_type_e::IPV4) {
            if (key_size == la_acl_key_profile_base::key_size_e::SIZE_160) {
                switch (udk_table_id) {
                case NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB1_160_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv4_db1_160_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                case NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB2_160_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv4_db2_160_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                case NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB3_160_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv4_db3_160_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                case NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB4_160_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv4_db4_160_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                }
            } else if (key_size == la_acl_key_profile_base::key_size_e::SIZE_320) {
                switch (udk_table_id) {
                case NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB1_320_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv4_db1_320_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                case NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB2_320_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv4_db2_320_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                case NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB3_320_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv4_db3_160_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                case NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB4_320_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv4_db4_320_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                }
            }
        } else if (key_type == la_acl_key_type_e::IPV6) {
            if (key_size == la_acl_key_profile_base::key_size_e::SIZE_160) {
                switch (udk_table_id) {
                case NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB1_160_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv6_db1_160_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                case NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB2_160_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv6_db2_160_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                case NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB3_160_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv6_db3_160_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                case NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB4_160_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv6_db4_160_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                }
            } else if (key_size == la_acl_key_profile_base::key_size_e::SIZE_320) {
                switch (udk_table_id) {
                case NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB1_320_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv6_db1_320_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                case NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB2_320_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv6_db2_320_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                case NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB3_320_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv6_db3_320_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                case NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB4_320_F0_TABLE:
                    m_delegate = std::make_shared<la_acl_generic<acl_ingress_rtf_ipv6_db4_320_f0_trait> >(m_device,
                                                                                                          m_device->get_sptr(this));
                    break;
                }
            }
        }
    }

    if (m_delegate == nullptr) {
        return LA_STATUS_EINVAL;
    }

    status = m_delegate->initialize(m_acl_key_profile, m_acl_command_profile);
    if (status != LA_STATUS_SUCCESS) {
        m_delegate.reset();
        return status;
    }

    status = m_delegate->initialize_pcls(src_pcl, dst_pcl);
    if (status != LA_STATUS_SUCCESS) {
        m_delegate.reset();
        return status;
    }

    m_device->add_object_dependency(acl_key_profile_sp, this);
    m_device->add_object_dependency(acl_command_profile_sp, this);

    if (src_pcl != nullptr) {
        m_device->add_object_dependency(src_pcl, this);
    }
    if (dst_pcl != nullptr) {
        m_device->add_object_dependency(dst_pcl, this);
    }

    if (dir == la_acl_direction_e::INGRESS) {
        if ((key_type == la_acl_key_type_e::IPV4) || (key_type == la_acl_key_type_e::IPV6)) {
            la_acl_key_def_vec_t key_def;
            m_acl_key_profile->get_key_definition(key_def);
            for (auto acl_field_def : key_def) {
                switch (acl_field_def.type) {
                case la_acl_field_type_e::SRC_PCL_BINCODE:
                case la_acl_field_type_e::DST_PCL_BINCODE:
                    m_is_og_acl = true;
                    break;
                default:
                    break;
                }
            }
        }

        la_acl_key_def_vec_t key_def;
        m_acl_key_profile->get_key_definition(key_def);
        for (auto acl_field_def : key_def) {
            switch (acl_field_def.type) {
            case la_acl_field_type_e::CLASS_ID:
                m_is_class_id_enabled = true;
                break;
            default:
                break;
            }
        }
    }

    return status;
}

la_status
la_acl_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    const auto& src_pcl = get_src_pcl();
    if (src_pcl != nullptr) {
        m_device->remove_object_dependency(src_pcl, this);
    }

    const auto& dst_pcl = get_dst_pcl();
    if (dst_pcl != nullptr) {
        m_device->remove_object_dependency(dst_pcl, this);
    }

    const la_acl_key_profile* acl_key_profile;
    la_status status = get_acl_key_profile(acl_key_profile);
    if (status == LA_STATUS_SUCCESS) {
        m_device->remove_object_dependency(acl_key_profile, this);
    }

    const la_acl_command_profile* acl_command_profile;
    status = get_acl_command_profile(acl_command_profile);
    if (status == LA_STATUS_SUCCESS) {
        m_device->remove_object_dependency(acl_command_profile, this);
    }
    if (m_delegate) {
        m_delegate->destroy();
    }

    return LA_STATUS_SUCCESS;
}

// la_object API-s
la_object::object_type_e
la_acl_impl::type() const
{
    return object_type_e::ACL;
}

std::string
la_acl_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_acl_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_acl_impl::oid() const
{
    return m_oid;
}

const la_device*
la_acl_impl::get_device() const
{
    return m_device.get();
}

// la_acl API-s
const la_acl_delegate_wptr
la_acl_impl::get_delegate() const
{
    return m_delegate;
}

la_status
la_acl_impl::get_type(type_e& out_type) const
{
    return m_delegate->get_type(out_type);
}

const la_pcl_wcptr
la_acl_impl::get_src_pcl() const
{
    return m_delegate->get_src_pcl();
}

const la_pcl_wcptr
la_acl_impl::get_dst_pcl() const
{
    return m_delegate->get_dst_pcl();
}

la_status
la_acl_impl::get_acl_key_profile(const la_acl_key_profile*& out_acl_key_profile) const
{
    out_acl_key_profile = m_acl_key_profile.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_acl_impl::get_acl_command_profile(const la_acl_command_profile*& out_acl_command_profile) const
{
    out_acl_command_profile = m_acl_command_profile.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_acl_impl::get_count(size_t& out_count) const
{
    return m_delegate->get_count(out_count);
}

la_status
la_acl_impl::append(const la_acl_key& key_val, const la_acl_command_actions& cmd)
{
    // TBD: Check if fields provided are part of the ACL key being used.
    start_api_call("key_val=", key_val, "cmd=", cmd);
    return m_delegate->append(key_val, cmd);
}

la_status
la_acl_impl::insert(size_t position, const la_acl_key& key_val, const la_acl_command_actions& cmd)
{
    // TBD: Check if fields provided are part of the ACL key being used.
    start_api_call("position=", position, "key_val=", key_val, "cmd=", cmd);
    return m_delegate->insert(position, key_val, cmd);
}

la_status
la_acl_impl::set(size_t position, const la_acl_key& key_val, const la_acl_command_actions& cmd)
{
    start_api_call("position=", position, "key_val=", key_val, "cmd=", cmd);
    return m_delegate->set(position, key_val, cmd);
}

la_status
la_acl_impl::erase(size_t position)
{
    start_api_call("position=", position);
    return m_delegate->erase(position);
}

la_status
la_acl_impl::clear()
{
    start_api_call("");
    return m_delegate->clear();
}

la_status
la_acl_impl::get(size_t position, acl_entry_desc& out_acl_entry_desc) const
{
    return m_delegate->get(position, out_acl_entry_desc);
}

la_status
la_acl_impl::reserve()
{
    return m_delegate->reserve();
}

la_status
la_acl_impl::get_max_available_space(size_t& out_available_space) const
{
    return m_delegate->get_tcam_max_available_space(out_available_space);
}

la_status
la_acl_impl::get_rtf_stage(la_acl_packet_processing_stage_e& out_stage) const
{
    la_acl_packet_processing_stage_e stage = la_acl_packet_processing_stage_e::PRE_FORWARDING;

    la_acl_key_def_vec_t acl_key_def;
    la_acl_command_def_vec_t acl_command_def;

    m_acl_key_profile->get_key_definition(acl_key_def);
    m_acl_command_profile->get_command_definition(acl_command_def);

    for (const auto field : acl_key_def) {
        switch (field.type) {
        case la_acl_field_type_e::CLASS_ID:
            stage = la_acl_packet_processing_stage_e::POST_FORWARDING;
            break;
        default:
            break;
        }
    }

#if 0
    ///  TBD Yaniv
    ///  Currently all acl action types can be executed in PRE_FORWARDING stage.
    ///  If a new acl action should be executed in stage other than PRE_FORWARDING
    ///  enable this code
    if (stage != la_acl_packet_processing_stage_e::RX_DONE) {
        for (const auto action : acl_command_def) {
            switch (action.type) {
            case la_acl_action_type_e::<<< new acl action type 1>>>:
                stage = la_acl_packet_processing_stage_e::POST_FORWARDING:;
                break;
            case la_acl_action_type_e::<<< new acl action type 2>>>:
                stage = la_acl_packet_processing_stage_e::RX_DONE;
                break;
            default:
                break;
            }
            if (stage == la_acl_packet_processing_stage_e::RX_DONE) {
                break;
            }
        }
    }
#endif
    out_stage = stage;

    return LA_STATUS_SUCCESS;
}

bool
la_acl_impl::is_og_acl() const
{
    return m_is_og_acl;
}

bool
la_acl_impl::is_class_id_enabled() const
{
    return m_is_class_id_enabled;
}

} // namespace silicon_one
