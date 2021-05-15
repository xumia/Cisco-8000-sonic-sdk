// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LEABA_LPM_DUMMY_DISTRIBUTOR_H__
#define __LEABA_LPM_DUMMY_DISTRIBUTOR_H__

#include "lpm_distributor.h"

namespace silicon_one
{

// Dummy distributor class to handle case when there is no distributor in device.
class lpm_dummy_distributor : public lpm_distributor
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Construct a LPM distributor object.
    ///
    /// @param[in]     name                 Name of distibutor.
    /// @param[in]     distributor_size     Number of distributor rows.
    /// @param[in]     max_key_width        Max supported key width.
    lpm_dummy_distributor(std::string name, size_t distributor_size, size_t max_key_width);

    // lpm_distributor API-s
    la_status insert(const lpm_key_t& key, lpm_payload_t payload, hardware_instruction_vec& out_instructions) override;
    la_status remove(const lpm_key_t& key, hardware_instruction_vec& out_instructions) override;
    la_status update(const lpm_implementation_desc_vec& updates, hardware_instruction_vec& out_instructions) override;
    la_status lookup_tcam_tree(const lpm_key_t& key,
                               lpm_key_t& out_hit_key,
                               lpm_payload_t& out_hit_payload,
                               distributor_cell_location& out_hit_location) const override;
    la_status lookup_tcam_table(const lpm_key_t& key,
                                lpm_key_t& out_hit_key,
                                lpm_payload_t& out_hit_payload,
                                distributor_cell_location& out_hit_location) const override;
    const lpm_logical_tcam_tree_node* find(const lpm_key_t& key) const override;
    const lpm_logical_tcam_tree_node* get_root_node(bool is_ipv6) const override;
    la_status get_payload_of_node(const lpm_logical_tcam_tree_node* node, lpm_payload_t& out_payload) const override;
    la_status get_entry(distributor_cell_location location, lpm_key_payload& out_key_payload) const override;
    vector_alloc<lpm_key_payload_location> get_entries() const override;
    void commit() override;
    void withdraw() override;
    json_t* save_state() const override;
    void load_state(json_t* json_distributor, hardware_instruction_vec& out_instructions) override;

protected:
    lpm_dummy_distributor() = default; // For serialization purposes only

    // lpm_distributor virtual functions
    la_status make_space_for_logical_tcam(bool is_ipv6, lpm_logical_tcam::logical_instruction_vec& out_instructions) override;
    distributor_cell_location translate_logical_row_to_cell_location(size_t logical_row, bool is_ipv6) const override;

}; // class lpm_dummy_distributor

} // namespace silicon_one

#endif // __LEABA_LPM_DUMMY_DISTRIBUTOR_H__
