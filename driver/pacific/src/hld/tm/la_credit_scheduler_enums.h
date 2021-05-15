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

#ifndef __LA_CREDIT_SCHEDULER_ENUMS_H__
#define __LA_CREDIT_SCHEDULER_ENUMS_H__

namespace silicon_one
{

enum {
    CREDIT_SCHEDULER_MANTISSA_SIZE = 5, ///< Mantissa size in bits
};

// SCH fields
enum {
    IFSE_EIR_SHAPE_MODE_BASE = 124, // Base of field IfseEirShaperMode of register IfseGeneralConfiguration

    TPSE_MAP_LOGICAL_PORT_BASE = 1,      // Base bit of TpseMapLogicalPort field
    TPSE_PRIORITY_PROPAGATION_BASE = 21, // Base bit of TpsePriorityPropagation field
};

} // namespace silicon_one

#endif // __LA_CREDIT_SCHEDULER_ENUMS_H__
