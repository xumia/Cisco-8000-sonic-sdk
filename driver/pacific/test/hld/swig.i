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

/// SWIG interface file for testing Leaba's high-level driver.

%module test_hldcli

%include std_string.i
%include std_map.i
%include "stdint.i"
%include "common/la_status.h"
%include "system/counter_manager.h"

%{
#include "nplapi/translator_creator.h"
#include "system/la_device_impl.h"
#include "system/counter_manager.h"
#include "nsim_provider/nsim_flow.h"

using namespace silicon_one;

%}

%inline %{

const silicon_one::resource_manager* la_device_get_resource_manager(silicon_one::la_device* dev)
{
    la_device_impl* dev_impl = static_cast<la_device_impl*>(dev);

    return dev_impl->get_resource_manager().get();
}

%}

%inline %{

const silicon_one::counter_manager* la_device_get_counter_bank_manager(silicon_one::la_device* dev)
{
    la_device_impl* dev_impl = static_cast<la_device_impl*>(dev);

    return dev_impl->get_counter_bank_manager().get();
}

%}


%pythoncode %{

import nplapicli as nplapi
try:
    import test_nsim_providercli as nsim
except BaseException:
    import test_packet_provider as nsim
import test_racli as ra

%}

