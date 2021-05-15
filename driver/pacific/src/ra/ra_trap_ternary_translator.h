// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

//

#ifndef __RA_TRAP_TERNARY_TRANSLATOR_H__
#define __RA_TRAP_TERNARY_TRANSLATOR_H__

#include "nplapi/npl_ternary_table_translator_base.h"
#include "nplapi_translator/npl_table_entry_translation.h"

#include "common/defines.h"
#include "ra/ra_types_fwd.h"
#include "special_tables/trap_tcam.h"

namespace silicon_one
{

/// @brief npl_ternary_translator interface implementation for Trap tables.
///
/// The underlying resource is split into two segments and is shared between two translators
/// to dynamically manage shared resource.
/// Upper table is placed straight on the resource - table grows from the top (first line) to bottom.
/// Lower table is placed reversed on the resource - table grows from the bottom (last line) to top.
///
/// The line translation may return multiple (or 0) lines, hence the translator must keep
/// track of content lines, occupied by each ternary table line.
///
/// As a result of dynamic resource allocation and multi-line translation, the actual table capacity is unknown.
/// Therefore, the following semantics are applied to avoid false "lack of resource" failures.
/// 1. max_size() returns the maximal size of the logical table, defined by table trait.
/// 2. erase() will act like pop(), deleting all physical lines and shifting the bottom of the table up.
///
/// Terms:
/// - table line (line)    - logical table line, NPL table line.
/// - entry line (content) - result of line translation. One table line is translated into multiple entry lines.
/// - resource line        - actual TCAM line the data is written to.
///
/// Template parameters:
/// _Trait      Corresponding NPL table trait.
///
template <class _Trait>
class ra_trap_ternary_translator : public npl_ternary_table_translator_base<_Trait>
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    typedef typename _Trait::key_type key_type;
    typedef typename _Trait::value_type value_type;
    typedef typename npl_ternary_table_translator_base<_Trait>::npl_translator_entry_desc npl_translator_entry_desc;

    ra_trap_ternary_translator(const ll_device_sptr& ll_dev,
                               npl_context_e context,
                               size_t replication_idx,
                               trap_tcam_sptr tcam,
                               bool is_reversed);

    virtual la_status initialize();
    virtual la_status set_entry_value(size_t line, const key_type& key, const key_type& mask, const value_type& value);
    virtual la_status insert(size_t line, const key_type& key, const key_type& mask, const value_type& value);
    virtual la_status insert_bulk(size_t first_line, size_t bulk_size, const vector_alloc<npl_translator_entry_desc>& entries);
    virtual la_status push(size_t line, size_t free_slot, const key_type& key, const key_type& mask, const value_type& value);
    virtual la_status erase(size_t line);
    virtual la_status move(size_t dst_line, size_t src_line, size_t count);
    virtual la_status pop(size_t line);
    virtual size_t max_size() const;
    virtual la_status get_max_available_space(size_t& out_available_space) const;
    virtual la_status set_trans_info(void* trans_info);
    virtual la_status get_physical_usage(size_t& out_physical_usage) const;

    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(m_ll_device);
        ar(m_context_id);
        ar(m_replication_idx);
        ar(m_tcam);
        ar(m_is_reversed);
        ar(m_entry_lines);
        ar(m_total_resource_size);
        ar(m_npu_features);
    }

private:
    ra_trap_ternary_translator() = default; // For serialization purposes only.

    // line translator results
    typedef std::vector<ternary_table_generic_entry_t> lt_result_vec_t;

    // forbid copy
    ra_trap_ternary_translator(const ra_trap_ternary_translator&);
    ra_trap_ternary_translator& operator=(const ra_trap_ternary_translator&);

    // Translate entry line to actual resource (HW) line.
    size_t entry_line_to_resource_line(size_t entry_line) const;

    // Return the first entry line, allocated for given table line.
    size_t get_first_entry_line(size_t line) const;
    // Return the number of entry lines, allocated for given table line.
    size_t get_entry_lines_num(size_t line) const;

    // Append empty line to the mapping, if beyond current mapping size.
    la_status append_line_if_needed(size_t line);
    // Insert empty line to the mapping.
    la_status insert_line(size_t line);
    // Remove empty line from the mapping.
    la_status remove_line(size_t line);

    // Increase table section of the resource, if need to grow beyond the limit.
    la_status resize_resource_if_needed(size_t delta);

    // Push the table content down by shift (content width).
    // Allocating space for given line.
    la_status push_lines(size_t line, size_t shift);
    // Pull the table content up by the content width of the given line.
    // Deallocating space for given line.
    la_status pull_lines(size_t line);

    // Write content to the resource, mapped to the table line.
    // Assuming that resource is available (resource lines are empty).
    la_status write_content(size_t line, const lt_result_vec_t& entry_lines);
    // Erase content from the resource, mapped to the table line.
    la_status erase_content(size_t line);

private:
    // Low-level device
    ll_device_sptr m_ll_device;

    // Context of the replication.
    npl_context_e m_context_id;

    // Index of the current replication within the same context.
    size_t m_replication_idx;

    // Physical resource access
    trap_tcam_sptr m_tcam;

    // Whether the table is reversed on the resource
    bool m_is_reversed;

    // Mapping of table lines to entry lines.
    // Per table line, stores the next line after last entry line.
    // For both straight and reversed tables, keeps straight values.
    // The translation to reversed is done only on actual HW write.
    std::vector<size_t> m_entry_lines;

    // Total size of both straight and reversed sections.
    size_t m_total_resource_size;

    npu_features_t m_npu_features;
};

template <class _Trait>
ra_trap_ternary_translator<_Trait>::ra_trap_ternary_translator(const ll_device_sptr& ll_dev,
                                                               npl_context_e context,
                                                               size_t replication_idx,
                                                               trap_tcam_sptr tcam,
                                                               bool is_reversed)
    : m_ll_device(ll_dev),
      m_context_id(context),
      m_replication_idx(replication_idx),
      m_tcam(tcam),
      m_is_reversed(is_reversed),
      m_entry_lines(),
      m_npu_features()
{
    dassert_crit(tcam);
    m_total_resource_size = tcam->size();
    m_entry_lines.reserve(_Trait::table_size);

    bool alternate_next_engine_bits = (m_ll_device->get_device_revision() == la_device_revision_e::PACIFIC_A0);
    m_npu_features.alternate_next_engine_bits = alternate_next_engine_bits;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::initialize()
{
    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::set_entry_value(size_t line, const key_type& key, const key_type& mask, const value_type& value)
{
    log_debug(RA,
              "ra_trap_ternary_translator(%d, %zd)::set_entry_value(%s, %zd, %s, %s, %s)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              line,
              key.pack().to_string().c_str(),
              mask.pack().to_string().c_str(),
              value.pack().to_string().c_str());

    lt_result_vec_t lt_res_vec;
    nplapi_table_entry_translation::translate_ternary_entry(
        m_context_id, m_replication_idx, key, mask, value, lt_res_vec, &m_npu_features);

    if (lt_res_vec.empty()) {
        // Line translation gave nothing for this context/replication idx. No error should be issued.
        return LA_STATUS_SUCCESS;
    }

    size_t entry_lines_num = get_entry_lines_num(line);

    // Make sure at least entry takes the same ammount of lines.
    // Otherwise, update does not make sense.
    if (entry_lines_num != lt_res_vec.size()) {
        return LA_STATUS_EINVAL;
    }

    la_status status = erase_content(line);
    return_on_error(status);

    status = write_content(line, lt_res_vec);

    return status;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::insert(size_t line, const key_type& key, const key_type& mask, const value_type& value)
{
    // Due to multi-line, insert into middle of table looks more like push:
    // - move the separator between tables if needed (resize)
    // - push content below, expanding current line
    // - write entry lines

    log_debug(RA,
              "ra_trap_ternary_translator(%d, %zd)::insert(%s, %zd, %s, %s, %s)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              line,
              key.pack().to_string().c_str(),
              mask.pack().to_string().c_str(),
              value.pack().to_string().c_str());

    // update if the new line is beyond current map bounds.
    append_line_if_needed(line);

    // Make sure the line is empty.
    if (get_entry_lines_num(line) != 0) {
        return LA_STATUS_EINVAL;
    }

    lt_result_vec_t lt_res_vec;
    nplapi_table_entry_translation::translate_ternary_entry(
        m_context_id, m_replication_idx, key, mask, value, lt_res_vec, &m_npu_features);

    if (lt_res_vec.empty()) {
        // Line translation gave nothing for this context/replication idx. No error should be issued.
        return LA_STATUS_SUCCESS;
    }

    size_t entry_lines_num = lt_res_vec.size();

    la_status status = resize_resource_if_needed(entry_lines_num);
    return_on_error(status);

    status = push_lines(line, entry_lines_num);
    return_on_error(status);

    status = write_content(line, lt_res_vec);

    return status;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::insert_bulk(size_t first_line,
                                                size_t bulk_size,
                                                const vector_alloc<npl_translator_entry_desc>& entries)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::push(size_t line,
                                         size_t free_slot,
                                         const key_type& key,
                                         const key_type& mask,
                                         const value_type& value)
{
    // Due to multi-line, push looks like insert into middle of table:
    // - move the separator between tables if needed (resize).
    // - push ALL content below, including current line, making room
    // - write entry lines.

    log_debug(RA,
              "ra_trap_ternary_translator(%d, %zd)::push(%s, %zd, %zd, %s, %s, %s)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              line,
              free_slot,
              key.pack().to_string().c_str(),
              mask.pack().to_string().c_str(),
              value.pack().to_string().c_str());

    // update if the new line is beyond current map bounds.
    append_line_if_needed(free_slot);

    // Since the index change is done up to the free slot,
    // but the shift is done to the end, it's easier to change indices by removing/inserting
    remove_line(free_slot);
    insert_line(line);

    lt_result_vec_t lt_res_vec;
    nplapi_table_entry_translation::translate_ternary_entry(
        m_context_id, m_replication_idx, key, mask, value, lt_res_vec, &m_npu_features);

    if (lt_res_vec.empty()) {
        // Line translation gave nothing for this context/replication idx. No error should be issued.
        return LA_STATUS_SUCCESS;
    }

    size_t entry_lines_num = lt_res_vec.size();

    la_status status = resize_resource_if_needed(entry_lines_num);
    return_on_error(status);

    status = push_lines(line, entry_lines_num);
    return_on_error(status);

    status = write_content(line, lt_res_vec);

    return status;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::erase(size_t line)
{
    // Due to multi-line, delete from middle of table looks more like pop:
    // - delete entry lines
    // - pull everything below

    log_debug(RA,
              "ra_trap_ternary_translator(%d, %zd)::erase(%s, %zd)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              line);

    la_status status = erase_content(line);
    return_on_error(status);

    status = pull_lines(line);

    return status;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::move(size_t dst_line, size_t src_line, size_t count)
{
    log_debug(RA,
              "ra_trap_ternary_translator(%d, %zd)::move(%s, dst_line:%zd, src_line:%zd, count:%zd)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              dst_line,
              src_line,
              count);

    dassert_crit((dst_line < m_entry_lines.size()) && (src_line < m_entry_lines.size())
                 && ((dst_line + count) < m_entry_lines.size()));

    if (!count) {
        return LA_STATUS_SUCCESS;
    }

    // update mapping
    for (uint32_t i = 0; i < count; i++) {
        m_entry_lines[dst_line + i] = m_entry_lines[src_line + i];
    }

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::pop(size_t line)
{
    log_debug(RA,
              "ra_trap_ternary_translator(%d, %zd)::pop(%s, %zd)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              line);

    if (line >= m_entry_lines.size()) {
        // If the line is beyond the current map, there is nothing to do to pop it.
        return LA_STATUS_SUCCESS;
    }

    la_status status = erase_content(line);
    return_on_error(status);

    status = pull_lines(line);
    return_on_error(status);

    status = remove_line(line);

    return status;
}

template <class _Trait>
size_t
ra_trap_ternary_translator<_Trait>::max_size() const
{
    return _Trait::table_size;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::get_max_available_space(size_t& out_available_space) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::get_physical_usage(size_t& out_physical_usage) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

template <class _Trait>
size_t
ra_trap_ternary_translator<_Trait>::entry_line_to_resource_line(size_t line) const
{
    return (m_is_reversed) ? m_total_resource_size - line - 1 : line;
}

template <class _Trait>
size_t
ra_trap_ternary_translator<_Trait>::get_first_entry_line(size_t line) const
{
    dassert_crit(line < m_entry_lines.size());
    return (line == 0) ? 0 : m_entry_lines[line - 1];
}

template <class _Trait>
size_t
ra_trap_ternary_translator<_Trait>::get_entry_lines_num(size_t line) const
{
    return (line < m_entry_lines.size()) ? m_entry_lines[line] - get_first_entry_line(line) : 0;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::append_line_if_needed(size_t line)
{
    if (line < m_entry_lines.size()) {
        return LA_STATUS_SUCCESS;
    }

    size_t last_entry_line = (m_entry_lines.empty()) ? 0 : m_entry_lines.back();
    m_entry_lines.resize(line + 1, last_entry_line);

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::insert_line(size_t line)
{
    if (line >= m_entry_lines.size()) {
        // wierd case, where one pushes line beyond current table size
        return append_line_if_needed(line);
    }

    size_t entry_line = (line == 0) ? 0 : m_entry_lines[line - 1];
    m_entry_lines.insert(m_entry_lines.begin() + line, entry_line);

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::remove_line(size_t line)
{
    // to remove, line should be empty
    dassert_crit(get_entry_lines_num(line) == 0);
    m_entry_lines.erase(m_entry_lines.begin() + line);

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::resize_resource_if_needed(size_t delta)
{
    la_status status = LA_STATUS_SUCCESS;
    size_t curr_max_size = m_tcam->get_resource_size(m_is_reversed);
    size_t curr_size = m_entry_lines.back();

    if (curr_size + delta > curr_max_size) {
        status = m_tcam->resize_resource(curr_size + delta, m_is_reversed);
    }

    return status;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::push_lines(size_t start_table_line, size_t shift)
{
    dassert_crit(start_table_line < m_entry_lines.size());
    dassert_crit(get_entry_lines_num(start_table_line) == 0);

    if (!shift) {
        return LA_STATUS_SUCCESS;
    }

    log_debug(RA,
              "ra_trap_ternary_translator(%d, %zd)::push_lines(start: %zd, shift: %zd)",
              m_context_id,
              m_replication_idx,
              get_first_entry_line(start_table_line),
              shift);

    // push content
    size_t start_entry_line = get_first_entry_line(start_table_line);
    for (size_t idx = m_entry_lines.back(); idx > start_entry_line; --idx) {
        size_t src_line = entry_line_to_resource_line(idx - 1);
        size_t dest_line = entry_line_to_resource_line(idx - 1 + shift);

        la_status status = m_tcam->move(src_line, dest_line);
        return_on_error(status);
    }

    // update mapping
    for (size_t idx = start_table_line; idx < m_entry_lines.size(); ++idx) {
        m_entry_lines[idx] += shift;
    }

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::pull_lines(size_t start_table_line)
{
    size_t shift = get_entry_lines_num(start_table_line);
    if (!shift) {
        return LA_STATUS_SUCCESS;
    }

    log_debug(RA,
              "ra_trap_ternary_translator(%d, %zd)::pull_lines(start: %zd, shift: %zd)",
              m_context_id,
              m_replication_idx,
              get_first_entry_line(start_table_line),
              shift);

    // pull content
    size_t next_entry_line = get_first_entry_line(start_table_line) + shift;
    for (size_t idx = next_entry_line; idx < m_entry_lines.back(); ++idx) {
        size_t dest_line = entry_line_to_resource_line(idx - shift);
        size_t src_line = entry_line_to_resource_line(idx);

        la_status status = m_tcam->move(src_line, dest_line);
        return_on_error(status);
    }

    // update mapping
    for (size_t idx = start_table_line; idx < m_entry_lines.size(); ++idx) {
        m_entry_lines[idx] -= shift;
    }

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::write_content(size_t line, const ra_trap_ternary_translator::lt_result_vec_t& entry_lines)
{
    dassert_crit(get_entry_lines_num(line) == entry_lines.size());
    size_t start_line = get_first_entry_line(line);

    log_debug(RA,
              "ra_trap_ternary_translator(%d, %zd)::write_line(line: %zd, entries: %zd)",
              m_context_id,
              m_replication_idx,
              start_line,
              entry_lines.size());

    for (size_t idx = 0; idx < entry_lines.size(); ++idx) {
        const ternary_table_generic_entry_t& curr = entry_lines[idx];
        size_t resource_line = entry_line_to_resource_line(start_line + idx);

        la_status status = m_tcam->write(resource_line, curr.key, curr.mask, curr.payload);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::erase_content(size_t line)
{
    size_t entry_lines_num = get_entry_lines_num(line);
    if (!entry_lines_num) {
        return LA_STATUS_SUCCESS;
    }
    size_t start_line = get_first_entry_line(line);

    log_debug(RA,
              "ra_trap_ternary_translator(%d, %zd)::erase_line(line: %zd, entries: %zd)",
              m_context_id,
              m_replication_idx,
              start_line,
              entry_lines_num);

    for (size_t idx = 0; idx < entry_lines_num; ++idx) {
        size_t resource_line = entry_line_to_resource_line(start_line + idx);

        la_status status = m_tcam->invalidate(resource_line);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_trap_ternary_translator<_Trait>::set_trans_info(void* trans_info)
{
    return LA_STATUS_SUCCESS;
}

}; // namespace silicon_one

#endif // __RA_TERNARY_TRANSLATOR_H__
