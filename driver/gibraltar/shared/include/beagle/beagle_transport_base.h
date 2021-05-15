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

#ifndef __LEABA_BEAGLE_TRANSPORT_BASE_H__
#define __LEABA_BEAGLE_TRANSPORT_BASE_H__

#include "apb/apb.h"
#include "beagle_api/beagle_transport.h"
#include "common/bit_vector.h"
#include "common/la_status.h"

namespace silicon_one
{

class beagle_transport_base : public beagle::beagle_transport
{

public:
    beagle_transport_base(apb* apb, uint32_t apb_select, bool is_simulated, la_device_id_t dev_id);
    virtual ~beagle_transport_base() = default;
    beagle::beagle_status_t read(uint32_t beagle_db_addr, uint32_t& out_val32) override;
    beagle::beagle_status_t write(uint32_t beagle_db_addr, uint32_t in_val) override;
    bool is_simulated_device() const override;
    beagle::chip_id_t get_chip_id() const override;

protected:
    apb* m_apb_handler;
    uint32_t m_apb_select = 0;
    bool m_is_simulated = false;
    la_device_id_t m_dev_id;

    beagle::beagle_status_t la_stat2beagle_stat(la_status stat);
};
}

#endif
