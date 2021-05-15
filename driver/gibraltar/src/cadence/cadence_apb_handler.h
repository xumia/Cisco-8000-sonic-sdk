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

#ifndef __CADENCE_APB_HANDLER_H__
#define __CADENCE_APB_HANDLER_H__

// Cadence
#include "apb_handler.h"

// Leaba SDK
#include "apb/apb.h"

/// @file: APB handler for Cadence PCIe PHY
namespace silicon_one
{

class cadence_apb_handler : public apb_handler
{
public:
    cadence_apb_handler() = delete;
    cadence_apb_handler(apb* apb_pcie);
    virtual ~cadence_apb_handler() = default;

    int read(int address, int& out_val) override;
    int write(int address, int in_val) override;

private:
    apb* m_apb_pcie;
};
}

#endif
