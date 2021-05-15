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

#ifndef __ETP_H__
#define __ETP_H__

#include "apb/apb.h"
#include "common/bit_vector.h"
#include "common/la_status.h"
#include "common/logger.h"
#include "etp/etp_serdes_address.h"

extern "C" {
#include "etp_sh3_def.h"
#include "etp_sh3_platform.h"
}

namespace silicon_one
{

class etp
{
public:
    etp();
    static la_status get_etp_module(etp_serdes_addressing_component_e component,
                                    etp_serdes_address& serdes_addr,
                                    etp_sh3_module_t& out_mod);
    static la_status set_apb_handler(apb* apb);
    static la_status clear_apb_handler(apb* apb);
    static ETP_STATUS etp_reg_write(etp_sh3_module_t* etp_mod, uint32 addr, uint32 val);
    static ETP_STATUS etp_reg_read(etp_sh3_module_t* etp_mod, uint32 addr, uint32* val);

private:
    static std::map<la_device_id_t, apb*> apb_serdes_handlers;
};
}

#endif // __ETP_H__
