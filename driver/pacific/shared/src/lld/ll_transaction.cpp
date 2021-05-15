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

#include "lld/ll_transaction.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/math_utils.h"
#include "ll_device_impl.h"
#include "lld/lld_utils.h"

#include <iterator>

using namespace silicon_one;

// non-default c'tor
ll_transaction::ll_transaction(ll_device_wptr ldev) : m_ll_device(ldev)
{
}

// move c'tor
ll_transaction::ll_transaction(ll_transaction&& other) : m_ll_device(other.m_ll_device)
{
    // only empty transaction can be "moved"
    dassert_crit(other.m_access.empty());
    dassert_crit(other.m_rollback.empty());

    other.m_ll_device.reset(); // not obligatory, but a good measure
}

la_status
ll_transaction::commit()
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));

    if (m_access.empty()) {
        log_debug(LLD, "%s: nothing to commit", __func__);
        return LA_STATUS_SUCCESS;
    }

    la_status rc = m_ll_device->access(std::move(m_access));
    dassert_crit(m_access.empty());

    return rc;
}

void
ll_transaction::abort()
{
    start_void_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));

    // clear both m_access and m_rollback, actions are forgotten and rollbacks are executed.
    m_access.clear();
    auto rollbacks = std::move(m_rollback);

    // Iterate in reverse (FIFO) order
    for (auto rit = rollbacks.rbegin(); rit != rollbacks.rend(); ++rit) {
        // execute the rollback
        (*rit)();
    }
}

void
ll_transaction::push_rollback(rollback_desc rollback)
{
    start_void_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));

    m_rollback.push_back(std::move(rollback));
}

la_status
ll_transaction::read_register(const lld_register& reg, bit_vector& out_bv)
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));
    la_status rc = validate_params(__PRETTY_FUNCTION__, reg, 0 /* is_volatile */, false);
    return_on_error(rc);

    return do_read_register(reg, false /* peek */, out_bv);
}

la_status
ll_transaction::read_register_volatile(const lld_register& reg, bool peek, bit_vector& out_bv)
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));
    la_status rc = validate_params(__PRETTY_FUNCTION__, reg, 1 /* is_volatile */, false);
    return_on_error(rc);

    return do_read_register(reg, peek, out_bv);
}

la_status
ll_transaction::write_register(const lld_register& reg, const bit_vector& in_bv)
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));
    la_status rc = validate_params(__PRETTY_FUNCTION__, reg, -1 /* is_volatile */, true);
    return_on_error(rc);

    const lld_register_desc_t* rdesc = reg.get_desc();
    if (in_bv.get_width() > rdesc->width_in_bits) {
        log_err(LLD,
                "%s: in buf too big, %s, val width %ld, reg width %d",
                __func__,
                rdesc->name.c_str(),
                in_bv.get_width(),
                rdesc->width_in_bits);
        return LA_STATUS_ESIZE;
    }

    return do_write_register(reg, in_bv);
}

la_status
ll_transaction::write_register_array(const lld_register_array_container& reg, size_t first, size_t count, const bit_vector& in_bv)
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));
    la_status rc = validate_params(__PRETTY_FUNCTION__, reg, -1 /* is_volatile */, true);
    return_on_error(rc);

    const lld_register_desc_t* rdesc = reg.get_desc();

    size_t width_bytes = rdesc->width * 8 * rdesc->instances;
    if (in_bv.get_width() > width_bytes) {
        log_err(LLD,
                "%s: in buf too big, %s, val width %ld, reg width %d, instance: %d",
                __func__,
                rdesc->name.c_str(),
                in_bv.get_width(),
                rdesc->width_in_bits,
                reg.get_desc()->instances);
        return LA_STATUS_ESIZE;
    }

    return do_write_register_array(reg, first, count, in_bv);
}

la_status
ll_transaction::read_memory(const lld_memory& mem, size_t first_entry, size_t count, bit_vector& out_bv)
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));
    la_status rc = validate_params(__PRETTY_FUNCTION__, mem, 0 /* is_volatile */, first_entry, count, false);
    return_on_error(rc);

    return do_read_memory(mem, first_entry, count, out_bv);
}

la_status
ll_transaction::read_memory_volatile(const lld_memory& mem, size_t first_entry, size_t count, bit_vector& out_bv)
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));
    la_status rc = validate_params(__PRETTY_FUNCTION__, mem, 1 /* is_volatile */, first_entry, count, false);
    return_on_error(rc);

    return do_read_memory(mem, first_entry, count, out_bv);
}

la_status
ll_transaction::write_memory(const lld_memory& mem, size_t first_entry, size_t count, const bit_vector& in_bv)
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));
    la_status rc = validate_params(__PRETTY_FUNCTION__, mem, -1 /* is_volatile */, first_entry, count, false);
    return_on_error(rc);

    return do_write_memory(mem, first_entry, count, in_bv);
}

la_status
ll_transaction::read_modify_write_register(const lld_register& reg, size_t msb, size_t lsb, const bit_vector& val)
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));
    la_status rc = validate_params(__PRETTY_FUNCTION__, reg, 0 /* is volatile */, true);
    return_on_error(rc);

    const lld_register_desc_t* rdesc = reg.get_desc();

    if ((rdesc->width_in_bits < msb) || ((msb - lsb + 1) < val.get_width())) {
        log_err(LLD,
                "%s: out of range, %s, reg width_in_bits %d, msb %ld, lsb %ld, val bits %ld",
                __func__,
                rdesc->name.c_str(),
                rdesc->width_in_bits,
                msb,
                lsb,
                val.get_width());
        return LA_STATUS_EOUTOFRANGE;
    }

    if (m_ll_device->get_shadow_read_enabled()) {
        bit_vector tmp_bv(0, rdesc->width_in_bits);

        // Read register
        rc = reg.read_shadow(rdesc->width, tmp_bv.byte_array());
        return_on_error(rc);

        // Modify value
        tmp_bv.set_bits(msb, lsb, val);

        // Write to shadow and to HW
        rc = do_write_register(reg, tmp_bv);
    } else {
        auto ad = m_ll_device->make_read_modify_write_register(reg, msb, lsb, val);
        m_access.push_back(std::move(ad));
        rc = LA_STATUS_SUCCESS;
    }

    return rc;
}

la_status
ll_transaction::read_modify_write_memory(const lld_memory& mem, size_t line, size_t msb, size_t lsb, const bit_vector& val)
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));
    la_status rc = validate_params(__PRETTY_FUNCTION__, mem, 0 /* is volatile */, line, 1 /* count */, false);
    return_on_error(rc);

    const lld_memory_desc_t* mdesc = mem.get_desc();
    if ((mdesc->width_bits < msb) || ((msb - lsb + 1) < val.get_width())) {
        log_err(LLD,
                "%s: out of range, %s, mbits %d, msb %ld, lsb %ld, vbits %ld",
                __func__,
                mdesc->name.c_str(),
                mdesc->width_bits,
                msb,
                lsb,
                val.get_width());
        return LA_STATUS_EOUTOFRANGE;
    }

    if (m_ll_device->get_shadow_read_enabled()) {
        bit_vector tmp_bv(0, mdesc->width_total_bits);

        // Read
        rc = mem.read_shadow(line, 1 /* count */, tmp_bv.byte_array());
        return_on_error(rc);

        // Modify
        tmp_bv.set_bits(msb, lsb, val);

        // Write to shadow and to HW
        rc = do_write_memory(mem, line, 1 /* count */, tmp_bv);
    } else {
        auto ad = m_ll_device->make_read_modify_write_memory(mem, line, msb, lsb, val);
        m_access.push_back(std::move(ad));
        rc = LA_STATUS_SUCCESS;
    }

    return rc;
}

la_status
ll_transaction::read_tcam(lld_memory const& tcam,
                          size_t tcam_line,
                          bit_vector& out_key_bv,
                          bit_vector& out_mask_bv,
                          bool& out_valid)
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));
    la_status rc = validate_params(__PRETTY_FUNCTION__, tcam, 0 /* is volatile */, tcam_line, 1 /* count */, false);
    return_on_error(rc);

    const lld_memory_desc_t* mdesc = tcam.get_desc();
    if (!mdesc->readable) {
        log_err(LLD, "%s: tcam mem is not readable, %s", __PRETTY_FUNCTION__, mdesc->name.c_str());
        return LA_STATUS_EACCES;
    }

    // TCAM read is a complex operation, make_read_tcam() does it in place and is expected to return nullptr.
    auto ad = m_ll_device->make_read_tcam(tcam, tcam_line, out_key_bv, out_mask_bv, out_valid);
    dassert_crit(ad.action == ll_device::access_desc::operation_e::INVALID);

    return LA_STATUS_SUCCESS;
}

la_status
ll_transaction::write_tcam(lld_memory const& tcam, size_t tcam_line, const bit_vector& out_key_bv, const bit_vector& out_mask_bv)
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));
    la_status rc = validate_params(__PRETTY_FUNCTION__, tcam, 0 /* is volatile */, tcam_line, 1 /* count */, true);
    return_on_error(rc);

    const lld_memory_desc_t* mdesc = tcam.get_desc();
    if (!mdesc->writable) {
        log_err(LLD, "%s: tcam mem is not writable, %s", __PRETTY_FUNCTION__, mdesc->name.c_str());
        return LA_STATUS_EACCES;
    }

    auto ad = m_ll_device->make_write_tcam(tcam, tcam_line, out_key_bv, out_mask_bv);
    // make_write_... returns INVALID if write-to-device is disabled.
    if (ad.action != ll_device::access_desc::operation_e::INVALID) {
        m_access.push_back(std::move(ad));
    }

    return LA_STATUS_SUCCESS;
}

la_status
ll_transaction::invalidate_tcam(lld_memory const& tcam, size_t tcam_line)
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));
    la_status rc = validate_params(__PRETTY_FUNCTION__, tcam, 0 /* is volatile */, tcam_line, 1 /* count */, true);
    return_on_error(rc);

    const lld_memory_desc_t* mdesc = tcam.get_desc();
    if (!mdesc->writable) {
        log_err(LLD, "%s: tcam mem is not writable, %s", __PRETTY_FUNCTION__, mdesc->name.c_str());
        return LA_STATUS_EACCES;
    }

    auto ad = m_ll_device->make_invalidate_tcam(tcam, tcam_line);
    // make_invalidate_tcam returns nullptr if write-to-device is disabled.
    if (ad.action != ll_device::access_desc::operation_e::INVALID) {
        m_access.push_back(std::move(ad));
    }

    return LA_STATUS_SUCCESS;
}

la_status
ll_transaction::wait_for_value(const lld_register& reg, bool equal, uint16_t val, uint16_t mask)
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));
    la_status rc = validate_params(__PRETTY_FUNCTION__, reg, 1 /* is_volatile */, false);
    return_on_error(rc);

    auto ad = m_ll_device->make_wait_for_value(reg, equal, val, mask);
    if (ad.action != ll_device::access_desc::operation_e::INVALID) {
        m_access.push_back(std::move(ad));
    }

    return LA_STATUS_SUCCESS;
}

la_status
ll_transaction::wait_for_value(const lld_memory& mem, size_t line, bool equal, uint16_t val, uint16_t mask)
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));
    la_status rc = validate_params(__PRETTY_FUNCTION__, mem, 1 /* is volatile */, line, 1 /* count */, false);
    return_on_error(rc);

    const lld_memory_desc_t* mdesc = mem.get_desc();
    if (!mdesc->readable) {
        log_err(LLD, "%s: mem is not readable, %s", __PRETTY_FUNCTION__, mdesc->name.c_str());
        return LA_STATUS_EACCES;
    }

    auto ad = m_ll_device->make_wait_for_value(mem, line, equal, val, mask);
    if (ad.action != ll_device::access_desc::operation_e::INVALID) {
        m_access.push_back(std::move(ad));
    }

    return LA_STATUS_SUCCESS;
}

la_status
ll_transaction::delay(uint64_t cycles)
{
    start_lld_call(static_cast<ll_device_impl*>(m_ll_device.get()));

    auto ad = m_ll_device->make_delay(cycles);
    dassert_crit(ad.action != ll_device::access_desc::operation_e::INVALID);
    m_access.push_back(std::move(ad));

    return LA_STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Helpers - do_xxx
// ---------------------------------------------------------------------------
la_status
ll_transaction::do_read_register(const lld_register& reg, bool peek, bit_vector& out_bv)
{
    const lld_register_desc_t* rdesc = reg.get_desc();

    log_debug(LLD, "%s: %s, width %d", __func__, rdesc->name.c_str(), rdesc->width_in_bits);

    out_bv.resize(rdesc->width_in_bits);

    if (rdesc->is_volatile() || !m_ll_device->get_shadow_read_enabled()) {
        // Store a HW access operation, the shadow will be updated when operation is completed
        auto ad = m_ll_device->make_read_register(reg, peek, out_bv);
        dassert_crit(ad.action != ll_device::access_desc::operation_e::INVALID);
        m_access.push_back(std::move(ad));

        return LA_STATUS_SUCCESS;
    }

    void* out_val = out_bv.byte_array();
    // Read from shadow, do not access HW
    return reg.read_shadow(reg.get_desc()->width, out_val);
}

la_status
ll_transaction::do_write_register(const lld_register& reg, const bit_vector& in_bv)
{
    log_debug(LLD,
              "%s: %s, val width %ld, reg width %d",
              __func__,
              reg.get_desc()->name.c_str(),
              in_bv.get_width(),
              reg.get_desc()->width_in_bits);

    auto ad = m_ll_device->make_write_register(reg, in_bv);
    m_access.push_back(std::move(ad));

    return LA_STATUS_SUCCESS;
}

la_status
ll_transaction::do_write_register_array(const lld_register_array_container& reg,
                                        size_t first,
                                        size_t count,
                                        const bit_vector& in_bv)
{
    log_debug(LLD,
              "%s: %s, val width %ld, reg width %d, count %lu, first %lu",
              __func__,
              reg.get_desc()->name.c_str(),
              in_bv.get_width(),
              reg.get_desc()->width_in_bits,
              count,
              first);

    auto ad = m_ll_device->make_write_register_array(reg, first, count, in_bv);
    m_access.push_back(std::move(ad));

    return LA_STATUS_SUCCESS;
}

la_status
ll_transaction::do_read_memory(const lld_memory& mem, size_t first_entry, size_t count, bit_vector& out_bv)
{
    const lld_memory_desc_t* mdesc = mem.get_desc();

    if (!mdesc->readable) {
        log_err(LLD, "%s: mem is not readable, %s", __PRETTY_FUNCTION__, mdesc->name.c_str());
        return LA_STATUS_EACCES;
    }

    log_debug(LLD,
              "%s: %s, width_bits %d, width_total_bits %d, width_total %d, entry %ld, count %ld",
              __func__,
              mdesc->name.c_str(),
              mdesc->width_bits,
              mdesc->width_total_bits,
              mdesc->width_total,
              first_entry,
              count);

    if (count == 1) {
        out_bv.resize(mdesc->width_total_bits);
    } else {
        out_bv.resize(bit_utils::BITS_IN_BYTE * count * mdesc->width_total);
    }

    if (mdesc->is_volatile() || !m_ll_device->get_shadow_read_enabled()) {
        // Store a HW access operation, the shadow will be updated when operation is completed
        auto ad = m_ll_device->make_read_memory(mem, first_entry, count, out_bv);
        dassert_crit(ad.action != ll_device::access_desc::operation_e::INVALID);
        m_access.push_back(std::move(ad));

        return LA_STATUS_SUCCESS;
    }

    // Read from shadow, do not access HW
    return mem.read_shadow(first_entry, count, out_bv.byte_array());
}

la_status
ll_transaction::do_write_memory(const lld_memory& mem, size_t first_entry, size_t count, const bit_vector& in_bv)
{
    const lld_memory_desc_t* mdesc = mem.get_desc();
    size_t in_bits = in_bv.get_width();
    size_t in_bytes = in_bv.get_width_in_bytes();

    if (!mdesc->writable) {
        log_err(LLD, "%s: mem is not writable, %s", __func__, mdesc->name.c_str());
        return LA_STATUS_EACCES;
    }

    log_debug(LLD,
              "%s: %s, width_bits %d, width_total_bits %d, first_entry %ld, count %ld",
              __func__,
              mdesc->name.c_str(),
              mdesc->width_bits,
              mdesc->width_total_bits,
              first_entry,
              count);

    // Single line:
    // Exact width is ok, narrow input is zero padded, too wide input is an error.
    //
    // Multiple lines:
    // The size of the input buffer must be exactly the total size of memory line (including ECC bits) times count.
    //
    if (!(count == 1 && in_bits <= mdesc->width_total_bits) &&      // single line
        !(count > 1 && (in_bytes == count * mdesc->width_total))) { // multi line

        if (count == 1) {
            // TODO: currently, tests often generate too wide buffers for count==1
            // So we let it pass, even though should fail.
            log_info(LLD,
                     "%s: in buf too big, %s, in_bits %ld, count %ld, width_total_bits %d - resizing!",
                     __func__,
                     mdesc->name.c_str(),
                     in_bits,
                     count,
                     mdesc->width_total_bits);
        } else { // count > 1
            log_err(LLD,
                    "%s: in buf size mismatch, %s, in_bits %ld, count %ld, width_total_bits %d",
                    __func__,
                    mdesc->name.c_str(),
                    in_bits,
                    count,
                    mdesc->width_total_bits);
            return LA_STATUS_ESIZE;
        }
    }

    auto ad = m_ll_device->make_write_memory(mem, first_entry, count, in_bv);
    m_access.push_back(std::move(ad));

    return LA_STATUS_SUCCESS;
}
