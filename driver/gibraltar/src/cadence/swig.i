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

/// SWIG interface file for Cadence CLI

%module cadencecli
%{

// Cadence PCI API
#include "apb_handler.h"

#include "torrent_api.h"
// Leaba SDK
#include "apb/apb.h"
#include "cadence_apb_handler.h"

%}

%include "stdint.i"
%include std_string.i
%include std_vector.i
%include "common/common_swig_typemaps.i"

OUTARG_ENUM_TYPEMAPS(int, out_CMN_Rdy)
OUTARG_ENUM_TYPEMAPS(int, out_EQE_eval)
OUTARG_ENUM_TYPEMAPS(int, out_FS)
OUTARG_ENUM_TYPEMAPS(int, out_LF)
OUTARG_ENUM_TYPEMAPS(int, out_LFPS_Detect)
OUTARG_ENUM_TYPEMAPS(int, out_Mac_Sus_ACK)
OUTARG_ENUM_TYPEMAPS(int, out_PLL_CLK_en_ACK)
OUTARG_ENUM_TYPEMAPS(int, out_PLL_Lock)
OUTARG_ENUM_TYPEMAPS(int, out_PLL_Rdy)
OUTARG_ENUM_TYPEMAPS(int, out_PLL_disable)
OUTARG_ENUM_TYPEMAPS(int, out_Refclk_active)
OUTARG_ENUM_TYPEMAPS(int, out_VGA)
OUTARG_ENUM_TYPEMAPS(int, out_atten)
OUTARG_ENUM_TYPEMAPS(int, out_error)
OUTARG_ENUM_TYPEMAPS(int, out_offset)
OUTARG_ENUM_TYPEMAPS(int, out_peak_amp)
OUTARG_ENUM_TYPEMAPS(int, out_pwrstate)
OUTARG_ENUM_TYPEMAPS(int, out_rx_det)
OUTARG_ENUM_TYPEMAPS(int, out_sigdet)
OUTARG_ENUM_TYPEMAPS(int, out_sync)
OUTARG_ENUM_TYPEMAPS(int, out_tap1)
OUTARG_ENUM_TYPEMAPS(int, out_tap2)
OUTARG_ENUM_TYPEMAPS(int, out_tap3)
OUTARG_ENUM_TYPEMAPS(int, out_val)

// Cadence PCI API
%include "torrent_api.h"

// Leaba SDK
%include "common/bit_vector.i"
%include "apb/apb_types.h"
%include "apb/apb.h"
%include "cadence_apb_handler.h"

