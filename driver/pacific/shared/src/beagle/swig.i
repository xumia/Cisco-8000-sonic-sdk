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

%module beaglecli
%{
#include "beagle/beagle_transport_creator.h"
#include "lld/ll_device.h"
using namespace beagle;
using namespace silicon_one;
%}

%include <stdint.i>
%include <std_shared_ptr.i>
%shared_ptr(beagle::beagle_transport)
%shared_ptr(silicon_one::beagle_transport_impl)

%include "common/common_swig_typemaps.i"

OUTARG_ENUM_TYPEMAPS_VOID(uint32_t, out_val32)
OUTARG_ENUM_TYPEMAPS_VOID(uint32_t, apb_select)

%inline %{
    la_status
    encode_apb_select(silicon_one::ll_device_sptr ll_device, int slice, int ifg, int serdes_package, uint32_t& apb_select)
    {
        return apb::encode_apb_select(ll_device, slice, ifg, serdes_package, apb_select);
    }
%}

%inline %{
    std::shared_ptr<beagle::beagle_transport>
    create_beagle_transport(silicon_one::ll_device_sptr ll_device, silicon_one::apb* apb, int slice, int ifg, int beagle)
    {
        uint32_t apb_select;

        la_status stat = apb::encode_apb_select(ll_device, slice, ifg, beagle, apb_select);

        if(stat != LA_STATUS_SUCCESS) {
            return nullptr;
        }

        return beagle_transport_creator::create(ll_device, apb, apb_select);
    }
%}

%inline %{
    std::shared_ptr<beagle::beagle_transport>
    create_beagle_transport_asic3(silicon_one::ll_device_sptr ll_device, silicon_one::apb* apb, int slice, int ifg, int beagle)
    {
        return create_beagle_transport(ll_device, apb, slice, ifg, beagle);
    }
%}

%include "beagle_status.h"
%include "chip_id_beagle_id.h"
%include "apb/apb.h"
%include "beagle_transport.h"
%include "beagle/beagle_transport_creator.h"
%include "lld/swig_typemaps.i"
