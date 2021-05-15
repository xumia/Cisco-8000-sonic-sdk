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

#ifndef __LA_AC_PROFILE_IMPL_H__
#define __LA_AC_PROFILE_IMPL_H__

#include "api/npu/la_ac_profile.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"

#include <map>
#include <stdint.h>
#include <vector>

namespace silicon_one
{

class la_ac_profile_impl : public la_ac_profile
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_ac_profile_impl() = default;
    //////////////////////////////
public:
    explicit la_ac_profile_impl(const la_device_impl_wptr& device);
    ~la_ac_profile_impl() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, uint64_t ac_profile_index);
    la_status destroy();

    // la_ac_profile API-s
    la_status get_key_selector_per_format(la_packet_vlan_format_t tag_format, key_selector_e& out_key_selector) override;
    la_status set_key_selector_per_format(la_packet_vlan_format_t tag_format, key_selector_e key_selector) override;
    la_status set_default_vid_per_format_enabled(la_packet_vlan_format_t tag_format, bool enabled) override;
    la_status get_qos_mode_per_format(la_packet_vlan_format_t tag_format, qos_mode_e& out_qos_mode) override;
    la_status set_qos_mode_per_format(la_packet_vlan_format_t tag_format, qos_mode_e qos_mode) override;
    la_status get_default_pcpdei_per_format_enabled(la_packet_vlan_format_t tag_format, bool& out_enabled) override;
    la_status set_default_pcpdei_per_format_enabled(la_packet_vlan_format_t tag_format, bool enabled) override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    /// @brief Get profile ID.
    ///
    /// @return Profile ID in hardware.
    uint64_t get_id() const;

    /// @brief Check if the profile includes format that maps to VLAN-with-fallback.
    bool need_fallback();

    /// @brief Create PWE key selector
    la_status set_pwe_key_selector();

private:
    /// @brief  Set key selector with the 'is-pwe' additional parameter.
    la_status set_key_selector_per_format_with_pwe(la_packet_vlan_format_t tag_format, key_selector_e key_selector, bool is_pwe);

    /// @brief Lookup Vlan format table for a given la_packet_vlan_format_t and get entry location and value.
    ///
    /// @param[in]   tag_format         la_packet_vlan_format_t to lookup for.
    /// @param[out]  entry_location     Entry location.
    /// @param[out]  entry_value        Entry value.
    la_status lookup_vlan_format_table(la_packet_vlan_format_t tag_format,
                                       size_t& entry_location,
                                       npl_vlan_format_table_t::value_type& entry_value) const;

    /// @brief Create a VLAN format table's Key, Mask, Value from a given la_packet_vlan_format_t.
    ///
    /// @param[in]  tag_format      Object to translate.
    /// @param[in]  key             Key to update.
    /// @param[in]  mask            Mask to update.
    /// @param[in]  value           Value to update
    la_status build_kmv(la_packet_vlan_format_t tag_format,
                        key_selector_e selector,
                        npl_vlan_format_table_t::key_type& key,
                        npl_vlan_format_table_t::key_type& mask,
                        npl_vlan_format_table_t::value_type& value,
                        bool is_pwe) const;

    /// @brief Compare VLAN format table keys.
    ///
    /// @return True if equal, false otherwise.
    bool vlan_format_table_key_equal(const npl_vlan_format_table_t::key_type& key1,
                                     const npl_vlan_format_table_t::key_type& key2) const;

    /// @brief Calculate number of TPID-s for given VLAN format table key.
    ///
    /// @return Number of TPID-s.
    size_t num_tags(const npl_vlan_format_table_t::key_type& key) const;

    /// Device this AC profle belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    /// Profile index
    uint64_t m_index;

    /// Profile includes format that maps to VLAN-with-fallback
    bool m_need_fallback;

    /// Profile includes private vlan selector
    bool m_selector_type_pvlan_enabled;
};
}

#endif
