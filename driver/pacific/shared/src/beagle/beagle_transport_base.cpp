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

#include "beagle/beagle_transport_base.h"
#include "beagle/beagle_transport_asic3.h"
#include "lld/ll_device.h"

namespace silicon_one
{

beagle_transport_base::beagle_transport_base(apb* apb, uint32_t apb_select, bool is_simulated, la_device_id_t dev_id)
{
    m_apb_handler = apb;
    m_apb_select = apb_select;
    m_is_simulated = is_simulated;
    m_dev_id = dev_id;
}

beagle::beagle_status_t
beagle_transport_base::read(uint32_t beagle_db_addr, uint32_t& out_val32)
{
    bit_vector bv;
    la_status re = m_apb_handler->read(m_apb_select, beagle_db_addr, bv);
    out_val32 = (uint32_t)(bv.get_value());
    return la_stat2beagle_stat(re);
}

beagle::beagle_status_t
beagle_transport_base::write(uint32_t beagle_db_addr, uint32_t in_val)
{
    bit_vector bv;
    bv.set_bits(31, 0, in_val);
    la_status wr = m_apb_handler->write(m_apb_select, beagle_db_addr, bv);
    return la_stat2beagle_stat(wr);
}

bool
beagle_transport_base::is_simulated_device() const
{
    return m_is_simulated;
}

beagle::beagle_status_t
beagle_transport_base::la_stat2beagle_stat(la_status stat)
{
    beagle::beagle_status_t status;

    if (stat == LA_STATUS_SUCCESS) {
        status = beagle::BGL_SUCCESS;
    } else if (stat == LA_STATUS_EINVAL) {
        status = beagle::BGL_EINVAL;
    } else {
        status = beagle::BGL_UNKNOWN;
    }

    return status;
}

beagle::chip_id_t
beagle_transport_base::get_chip_id() const
{
    return (beagle::chip_id_t)m_dev_id;
}
};
