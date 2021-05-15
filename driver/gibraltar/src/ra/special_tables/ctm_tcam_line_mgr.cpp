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

#include "ctm_tcam_line_mgr.h"
#include "common/logger.h"
#include "ctm/ctm_common.h"

#include "common/dassert.h"

namespace silicon_one
{

ctm_tcam_line_mgr::ctm_tcam_line_mgr() : m_size(ctm::BANK_SIZE), m_occupied_lines(0, m_size), m_number_of_free_lines(m_size)
{
}

ctm_tcam_line_mgr::ctm_tcam_line_mgr(size_t size) : m_size(size), m_occupied_lines(0, m_size), m_number_of_free_lines(m_size)
{
}

size_t
ctm_tcam_line_mgr::get_first_free_line_in_range(const size_t start_line, const size_t end_line)
{
    dassert_crit(start_line <= end_line);
    dassert_crit(end_line <= m_size);

    size_t ret_val = start_line;

    while (ret_val < end_line && m_occupied_lines.bit(ret_val) == 1) {
        ++ret_val;
    }

    if (ret_val >= end_line) {
        ret_val = m_size;
    }

    return ret_val;
}

size_t
ctm_tcam_line_mgr::get_next_free_line(const size_t line)
{
    size_t ret_val = m_size;

    if (line < m_size) {
        ret_val = get_first_free_line_in_range(line + 1, m_size);
    }

    return ret_val;
}
void
ctm_tcam_line_mgr::allocate_line(size_t line)
{
    dassert_crit(line < m_size);
    dassert_crit(m_number_of_free_lines > 0);
    dassert_crit(m_number_of_free_lines <= m_size);

    if (m_occupied_lines.bit(line) == 0) {
        m_occupied_lines.set_bit(line, 1);
        --m_number_of_free_lines;
    } else {
        log_warning(RA, "%s, trying to allocate already allocated line.", __FUNCTION__);
    }
}

void
ctm_tcam_line_mgr::release_line(size_t line)
{
    dassert_crit(line < m_size);
    dassert_crit(m_number_of_free_lines < m_size);

    if (m_occupied_lines.bit(line) == 1) {
        m_occupied_lines.set_bit(line, 0);
        ++m_number_of_free_lines;
    } else {
        log_warning(RA, "%s, trying to release a free line.", __FUNCTION__);
    }
}

void
ctm_tcam_line_mgr::allocate_all_lines()
{
    for (size_t i = 0; i < m_size; i++) {
        m_occupied_lines.set_bit(i, 1);
    }
    m_number_of_free_lines = 0;
}

void
ctm_tcam_line_mgr::release_all_lines()
{
    for (size_t i = 0; i < m_size; i++) {
        m_occupied_lines.set_bit(i, 0);
    }
    m_number_of_free_lines = m_size;
}

size_t
ctm_tcam_line_mgr::get_num_alloc_lines() const
{
    return m_size - m_number_of_free_lines;
}
size_t
ctm_tcam_line_mgr::get_num_free_lines() const
{
    return m_number_of_free_lines;
}

size_t
ctm_tcam_line_mgr::get_size() const
{
    return m_size;
}
bool
ctm_tcam_line_mgr::is_occupied(const size_t line) const
{
    return m_occupied_lines.bit(line) == 1;
}

} // namespace silicon_one
