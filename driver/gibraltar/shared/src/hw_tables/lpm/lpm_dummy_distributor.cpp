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

#include "lpm_dummy_distributor.h"
#include "common/logger.h"
#include "common/transaction.h"

#include <jansson.h>

namespace silicon_one
{

lpm_dummy_distributor::lpm_dummy_distributor(std::string name, size_t distributor_size, size_t max_key_width)
    : lpm_distributor(name, distributor_size, max_key_width, distributor_size / 2, distributor_size / 4)
{
}

la_status
lpm_dummy_distributor::insert(const lpm_key_t& key, lpm_payload_t payload, hardware_instruction_vec& out_instructions)
{
    log_err(TABLES,
            "%s: %s: Dummy insert in distributor key=0x%s/%zu  payload=%u",
            m_name.c_str(),
            __func__,
            key.to_string().c_str(),
            key.get_width(),
            payload);

    return LA_STATUS_SUCCESS;
}

la_status
lpm_dummy_distributor::remove(const lpm_key_t& key, hardware_instruction_vec& out_instructions)
{
    log_err(TABLES,
            "%s: %s: Dummy remove key in distributor key=0x%s/%zu",
            m_name.c_str(),
            __func__,
            key.to_string().c_str(),
            key.get_width());
    return LA_STATUS_SUCCESS;
}

la_status
lpm_dummy_distributor::update(const lpm_implementation_desc_vec& updates, hardware_instruction_vec& out_instructions)
{
    log_err(TABLES, "%s: %s Dummy update distributor", m_name.c_str(), __func__);
    return LA_STATUS_SUCCESS;
}

la_status
lpm_dummy_distributor::lookup_tcam_tree(const lpm_key_t& key,
                                        lpm_key_t& out_hit_key,
                                        lpm_payload_t& out_hit_payload,
                                        distributor_cell_location& out_hit_location) const
{
    log_err(TABLES,
            "%s: %s:  Dummy lookup in distributor key=0x%s/%zu",
            m_name.c_str(),
            __func__,
            key.to_string().c_str(),
            key.get_width());
    out_hit_key = key;
    out_hit_payload = 0;
    out_hit_location = distributor_cell_location{};
    return LA_STATUS_SUCCESS;
}

la_status
lpm_dummy_distributor::lookup_tcam_table(const lpm_key_t& key,
                                         lpm_key_t& out_hit_key,
                                         lpm_payload_t& out_hit_payload,
                                         distributor_cell_location& out_hit_location) const
{
    log_err(TABLES,
            "%s: %s: Dummy lookup in distributor key=0x%s/%zu",
            m_name.c_str(),
            __func__,
            key.to_string().c_str(),
            key.get_width());
    out_hit_key = key;
    out_hit_payload = 0;
    out_hit_location = distributor_cell_location{};
    return LA_STATUS_SUCCESS;
}

const lpm_logical_tcam_tree_node*
lpm_dummy_distributor::find(const lpm_key_t& key) const
{
    log_err(TABLES,
            "%s: %s: Dummy find in distributor key=0x%s/%zu",
            m_name.c_str(),
            __func__,
            key.to_string().c_str(),
            key.get_width());
    return nullptr;
}

const lpm_logical_tcam_tree_node*
lpm_dummy_distributor::get_root_node(bool is_ipv6) const
{
    log_err(TABLES, "%s: %s: Dummy get root node in distributor", m_name.c_str(), __func__);
    return nullptr;
}

la_status
lpm_dummy_distributor::get_payload_of_node(const lpm_logical_tcam_tree_node* node, lpm_payload_t& out_payload) const
{
    log_err(TABLES, "%s: %s: Dummy payload of node in distributor", m_name.c_str(), __func__);
    out_payload = 0;
    return LA_STATUS_SUCCESS;
}

vector_alloc<lpm_key_payload_location>
lpm_dummy_distributor::get_entries() const
{
    log_err(TABLES, "%s: %s: Dummy entries in distributor", m_name.c_str(), __func__);
    vector_alloc<lpm_key_payload_location> entries;
    return entries;
}

la_status
lpm_dummy_distributor::get_entry(distributor_cell_location location, lpm_key_payload& out_key_payload) const
{
    log_err(TABLES, "%s: %s: Dummy entry in distributor: location=%s", m_name.c_str(), __func__, location.to_string().c_str());
    out_key_payload = {.key = lpm_key_t(), .payload = 0};
    return LA_STATUS_SUCCESS;
}

json_t*
lpm_dummy_distributor::save_state() const
{
    log_err(TABLES, "%s: %s: Dummy state of distributor", m_name.c_str(), __func__);
    json_t* json_distributor = json_object();
    return json_distributor;
}

void
lpm_dummy_distributor::load_state(json_t* json_distributor, hardware_instruction_vec& out_instructions)
{
    log_err(TABLES, "%s: %s: Dummy load state of distributor", m_name.c_str(), __func__);
}

void
lpm_dummy_distributor::commit()
{
    log_err(TABLES, "%s: %s: Dummy commit in distributor", m_name.c_str(), __func__);
}

void
lpm_dummy_distributor::withdraw()
{
    log_err(TABLES, "%s: %s: Dummy withdraw in distributor", m_name.c_str(), __func__);
}

la_status
lpm_dummy_distributor::make_space_for_logical_tcam(bool is_ipv6, lpm_logical_tcam::logical_instruction_vec& out_instructions)
{
    log_err(TABLES, "%s: %s: Dummy make space in distributor", m_name.c_str(), __func__);
    return LA_STATUS_SUCCESS;
}

distributor_cell_location
lpm_dummy_distributor::translate_logical_row_to_cell_location(size_t logical_row, bool is_ipv6) const
{
    log_err(TABLES, "%s: %s: Dummy translation row to location in distributor", m_name.c_str(), __func__);
    distributor_cell_location location{};
    return location;
}

} // namespace silicon_one
