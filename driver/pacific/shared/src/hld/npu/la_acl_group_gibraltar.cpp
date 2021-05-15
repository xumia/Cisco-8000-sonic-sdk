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

#include "npu/la_acl_group_gibraltar.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

la_acl_group_gibraltar::la_acl_group_gibraltar(const la_device_impl_wptr& device) : la_acl_group_base(device)
{
}

la_acl_group_gibraltar::~la_acl_group_gibraltar()
{
}

npl_rtf_stage_and_type_e
la_acl_group_gibraltar::get_next_rtf_stage(la_acl_packet_format_e packet_format,
                                           const la_acl_wptr_vec_t& acls,
                                           uint16_t acl_index) const
{
    if (packet_format == la_acl_packet_format_e::ETHERNET) {
        for (uint16_t next_acl_index = acl_index + 1; next_acl_index < acls.size(); next_acl_index++) {
            if (acls[next_acl_index] != nullptr) {
                la_acl_packet_processing_stage_e next_stage;
                const auto& acl_impl = acls[next_acl_index].weak_ptr_static_cast<la_acl_impl>();
                la_status status = acl_impl->get_rtf_stage(next_stage);
                if (status != LA_STATUS_SUCCESS) {
                    return NPL_RTF_NONE;
                }
                switch (next_stage) {
                case la_acl_packet_processing_stage_e::PRE_FORWARDING:
                    return NPL_RTF_PRE_FWD_L2;
                case la_acl_packet_processing_stage_e::POST_FORWARDING:
                    return NPL_RTF_POST_FWD_L2;
                case la_acl_packet_processing_stage_e::RX_DONE:
                    return NPL_RTF_RX_DONE_L2;
                default:
                    return NPL_RTF_NONE;
                }
            }
        }
    } else if ((packet_format == la_acl_packet_format_e::IPV4) || (packet_format == la_acl_packet_format_e::IPV6)) {
        for (uint16_t next_acl_index = acl_index + 1; next_acl_index < acls.size(); next_acl_index++) {
            if (acls[next_acl_index] != nullptr) {
                la_acl_packet_processing_stage_e next_stage;
                const auto& acl_impl = acls[next_acl_index].weak_ptr_static_cast<la_acl_impl>();
                bool is_og_acl = acl_impl->is_og_acl();
                if (is_og_acl) {
                    return NPL_RTF_OG;
                }
                la_status status = acl_impl->get_rtf_stage(next_stage);
                if (status != LA_STATUS_SUCCESS) {
                    return NPL_RTF_NONE;
                }
                const la_acl_key_profile* acl_key_profile;
                status = acl_impl->get_acl_key_profile(acl_key_profile);
                if (status != LA_STATUS_SUCCESS) {
                    return NPL_RTF_NONE;
                }
                la_acl_key_type_e acl_key_profile_key_type;
                status = acl_key_profile->get_key_type(acl_key_profile_key_type);
                if (status != LA_STATUS_SUCCESS) {
                    return NPL_RTF_NONE;
                }
                switch (next_stage) {
                case la_acl_packet_processing_stage_e::PRE_FORWARDING:
                    if (acl_key_profile_key_type == la_acl_key_type_e::ETHERNET)
                        return NPL_RTF_PRE_FWD_L2;
                    return NPL_RTF_PRE_FWD_L3;
                case la_acl_packet_processing_stage_e::POST_FORWARDING:
                    return NPL_RTF_POST_FWD_L3;
                case la_acl_packet_processing_stage_e::RX_DONE:
                    return NPL_RTF_RX_DONE_L3;
                default:
                    return NPL_RTF_NONE;
                }
            }
        }
    }

    return NPL_RTF_NONE;
}

npl_rtf_stage_and_type_e
la_acl_group_gibraltar::get_init_eth_rtf_stage(la_acl_packet_format_e packet_format, const la_acl_wptr_vec_t& acls) const
{
    if (packet_format == la_acl_packet_format_e::ETHERNET) {
        for (uint16_t acl_index = 0; acl_index < acls.size(); acl_index++) {
            if (acls[acl_index] != nullptr) {
                la_acl_packet_processing_stage_e stage;
                const auto& acl_impl = acls[acl_index].weak_ptr_static_cast<la_acl_impl>();
                la_status status = acl_impl->get_rtf_stage(stage);
                if (status != LA_STATUS_SUCCESS) {
                    return NPL_RTF_NONE;
                }
                const la_acl_key_profile* acl_key_profile;
                status = acl_impl->get_acl_key_profile(acl_key_profile);
                if (status != LA_STATUS_SUCCESS) {
                    return NPL_RTF_NONE;
                }
                la_acl_key_type_e acl_key_profile_key_type;
                status = acl_key_profile->get_key_type(acl_key_profile_key_type);
                if (status != LA_STATUS_SUCCESS) {
                    return NPL_RTF_NONE;
                }
                switch (stage) {
                case la_acl_packet_processing_stage_e::PRE_FORWARDING:
                    if (acl_key_profile_key_type == la_acl_key_type_e::ETHERNET)
                        return NPL_RTF_PRE_FWD_L2;
                    return NPL_RTF_PRE_FWD_L2;
                case la_acl_packet_processing_stage_e::POST_FORWARDING:
                    return NPL_RTF_POST_FWD_L2;
                case la_acl_packet_processing_stage_e::RX_DONE:
                    return NPL_RTF_RX_DONE_L2;
                default:
                    return NPL_RTF_NONE;
                }
            }
        }
    }

    return NPL_RTF_NONE;
}

la_status
la_acl_group_gibraltar::get_post_fwd_rtf_stage(la_acl_packet_format_e packet_format,
                                               const la_acl_wptr_vec_t& acls,
                                               npl_rtf_stage_and_type_e& post_fwd_rtf_stage) const
{
    if (packet_format == la_acl_packet_format_e::ETHERNET) {
        for (auto acl : acls) {
            if (acl != nullptr) {
                la_acl_packet_processing_stage_e stage;
                const auto& acl_impl = acl.weak_ptr_static_cast<la_acl_impl>();
                la_status status = acl_impl->get_rtf_stage(stage);
                return_on_error(status);
                switch (stage) {
                case la_acl_packet_processing_stage_e::PRE_FORWARDING:
                    break;
                case la_acl_packet_processing_stage_e::POST_FORWARDING:
                    post_fwd_rtf_stage = NPL_RTF_POST_FWD_L2;
                    return LA_STATUS_SUCCESS;
                case la_acl_packet_processing_stage_e::RX_DONE:
                    post_fwd_rtf_stage = NPL_RTF_RX_DONE_L2;
                    return LA_STATUS_SUCCESS;
                default:
                    break;
                }
            }
        }
    } else if ((packet_format == la_acl_packet_format_e::IPV4) || (packet_format == la_acl_packet_format_e::IPV6)) {
        for (auto acl : acls) {
            if (acl != nullptr) {
                la_acl_packet_processing_stage_e stage;
                const auto& acl_impl = acl.weak_ptr_static_cast<la_acl_impl>();
                la_status status = acl_impl->get_rtf_stage(stage);
                return_on_error(status);
                switch (stage) {
                case la_acl_packet_processing_stage_e::PRE_FORWARDING:
                    break;
                case la_acl_packet_processing_stage_e::POST_FORWARDING:
                    post_fwd_rtf_stage = npl_rtf_stage_and_type_e::NPL_RTF_POST_FWD_L3;
                    return LA_STATUS_SUCCESS;
                case la_acl_packet_processing_stage_e::RX_DONE:
                    post_fwd_rtf_stage = npl_rtf_stage_and_type_e::NPL_RTF_RX_DONE_L3;
                    return LA_STATUS_SUCCESS;
                default:
                    break;
                }
            }
        }
    }
    post_fwd_rtf_stage = npl_rtf_stage_and_type_e::NPL_RTF_NONE;

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
