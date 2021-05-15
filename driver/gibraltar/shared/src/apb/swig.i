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

/// SWIG interface file for Leaba APB

%module apbcli
%{
#include "apb/apb.h"
%}

%include "stdint.i"
%include std_string.i
%include std_vector.i
%include "common/common_swig_typemaps.i"
%include "lld/swig_typemaps.i"

OUTARG_OWNED_PTR_TYPEMAPS(silicon_one::apb*, owned_apb)
OUTARG_ENUM_TYPEMAPS(silicon_one::apb*, apb_select)

%inline %{
    la_status
    apb_create(silicon_one::ll_device_sptr ll_device, silicon_one::apb_interface_type_e type, silicon_one::apb*& owned_apb)
    {
        owned_apb = silicon_one::apb::create(ll_device, type);

        return owned_apb ? LA_STATUS_SUCCESS : LA_STATUS_EUNKNOWN;
    }
%}

%inline %{
    la_status
    encode_apb_select(silicon_one::ll_device_sptr ll_device, uint slice, uint ifg, uint sd_package, uint32_t& apb_select)
    {
        return silicon_one::apb::encode_apb_select(ll_device, slice, ifg, sd_package, apb_select);
    }
%}

%include "common/bit_vector.i"
BITVECTOR_TYPEMAPS(bit_vector)

%include "api/types/la_common_types.h"
%include "apb/apb_types.h"
%include "apb/apb.h"

