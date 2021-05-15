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

/// SWIG interface file for Leaba INFO

%module info_phycli
%{
#include "api/types/la_common_types.h"
#include "api/system/la_info_phy_brick_handler.h"
#include "api/system/la_info_phy_handler.h"
%}

%include "stdint.i"
%include std_string.i
%include std_vector.i
%include "api/types/la_common_types.h"
%include "common/common_swig_typemaps.i"
%include "lld/swig_typemaps.i"

OUTARG_OWNED_PTR_TYPEMAPS(silicon_one::la_info_phy_handler*, owned_info)
OUTARG_PTR_TYPEMAPS(silicon_one::la_info_phy_brick_handler*, out_info_brick)

OUTARG_STRUCT_TYPEMAPS(silicon_one::la_info_phy_brick_handler::info_link_counters, out_info_link_counters)
OUTARG_ENUM_TYPEMAPS(size_t, out_link)
OUTARG_ENUM_TYPEMAPS(size_t, out_lane)
OUTARG_ENUM_TYPEMAPS(size_t, out_val)
OUTARG_ENUM_TYPEMAPS(size_t, out_data)
OUTARG_BOOL_TYPEMAPS(out_lock)
OUTARG_BOOL_TYPEMAPS(out_done)

%inline %{
    la_status
    info_create(silicon_one::ll_device_sptr ll_device, silicon_one::la_info_phy_handler*& owned_info)
    {
        owned_info = silicon_one::la_info_phy_handler::create(ll_device.get());

        return owned_info ? LA_STATUS_SUCCESS : LA_STATUS_EUNKNOWN;
    }
%}

%include "api/system/la_info_phy_brick_handler.h"
%include "api/system/la_info_phy_handler.h"

