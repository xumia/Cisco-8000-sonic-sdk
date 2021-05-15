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

/// SWIG interface file for SRM CLI

%module srmcli
%{
#include "srm_api.h"
#include "platform/ip_types.h"
#include "platform/ip_rtos.h"
#include "srm_rules.h"
#include "srm/srm_serdes_address.h"
#include "srm/srm.h"
#include "apb/apb.h"
#include "common/gen_utils.h"
%}

%include "typemaps.i"
%include "stdint.i"
%include "std_vector.i"

%template(vector_uint32) std::vector<uint32_t>;
%template(vector_int16) std::vector<int16_t>;


%feature("autodoc", "1");

%include "common/common_swig_typemaps.i"
ARRAY_HANDLER(short, PyLong_AsLongLong, PyLong_FromLongLong)
ARRAY_HANDLER(unsigned short, PyLong_AsLongLong, PyLong_FromLongLong)
ARRAY_HANDLER(int, PyLong_AsLongLong, PyLong_FromLongLong)
ARRAY_HANDLER(unsigned int, PyLong_AsLongLong, PyLong_FromLongLong)

%include "common/bit_vector.i"
BITVECTOR_TYPEMAPS(bit_vector)

// SRM
%include "srm_api.h"
%include "platform/ip_types.h"
%include "srm_rules.h"
%include "apb/apb_types.h"
%include "apb/apb.h"
%include "srm/srm_serdes_address.h"
%include "srm/srm.h"
%include "api/types/la_common_types.h"

%inline {
    e_srm_fw_mode
    srm_mcu_fw_mode_query(uint32_t die) {
        e_srm_fw_mode out;
        srm_mcu_fw_mode_query(die, &out);
        return out;
    }

    std::string srm_version() {
        char buf[256];
        srm_version(buf, sizeof(buf));
        return std::string(buf);
    }

    std::string srm_version_firmware(uint32_t die) {
        char buf[256];
        srm_version_firmware(die, buf, sizeof(buf));
        return std::string(buf);
    }

    struct ffe_taps_t {
        int16_t data[SRM_FFE_TAP_COUNT];
    };

    ip_status_t
    srm_rx_dsp_ffe_taps_query(uint32_t die, uint32_t channel, uint16_t ffe_sub_channel, ffe_taps_t* out_ffe_taps) {
        return srm_rx_dsp_ffe_taps_query(die, channel, ffe_sub_channel, out_ffe_taps->data);
    }

    ip_status_t
    srm_rx_dsp_ffe_taps_print(uint32_t die, uint32_t channel, uint16_t ffe_sub_channel, const ffe_taps_t* ffe_taps) {
        return srm_rx_dsp_ffe_taps_print(die, channel, ffe_sub_channel, (int16_t*)ffe_taps->data);
    }

    struct hist_data_t {
        uint32_t data[160];
    };

    ip_status_t
    srm_rx_dsp_get_histogram(uint32_t die, uint32_t channel, e_srm_rx_error_gen errgen_id, hist_data_t* out_hist) {
        return srm_rx_dsp_get_histogram(die, channel, errgen_id, out_hist->data);
    }

    ip_status_t
    srm_rx_dsp_get_histogram_bypass(uint32_t die, uint32_t channel, e_srm_rx_error_gen errgen_id, hist_data_t* out_hist) {
        return srm_rx_dsp_get_histogram(die, channel, errgen_id, out_hist->data);
    }

    ip_status_t
    srm_mcu_msg_rx_hist_request(uint32_t die, uint32_t channel, e_srm_rx_error_gen errgen_id, hist_data_t* out_hist) {
        return srm_mcu_msg_rx_hist_request(die, channel, errgen_id, out_hist->data);
    }

    ip_status_t
    srm_rx_dsp_hist_ascii_plot(uint32_t die, uint32_t channel, const hist_data_t* in_hist) {
        return srm_rx_dsp_hist_ascii_plot(die, channel, (uint32_t*)in_hist->data);
    }

    struct srm_mcu_buffer_address_t {
        uint32_t buffer_address;
        uint16_t buff_32b_size;
    };

    int32_t
    srm_diags_temperature_query(uint32_t die){
        int32_t temperature;
        srm_diags_temperature_query(die, &temperature);
        return temperature;
    }


    ip_status_t
    srm_mcu_get_buffer_address(uint32_t die, uint32_t buffer_type, srm_mcu_buffer_address_t* out) {
        return srm_mcu_get_buffer_address(die, buffer_type, &out->buffer_address, &out->buff_32b_size);
    }

    struct srm_prbs_ber_t {
        double ber;
        double ber_lsb;
    };

    ip_status_t
    srm_prbs_chk_ber(srm_prbs_chk_status_t *chk_status, srm_prbs_ber_t* out) {
        return srm_prbs_chk_ber(chk_status, &out->ber, &out->ber_lsb);
    }

    ip_status_t
    srm_tx_equalization_set(uint32_t die, uint32_t channel, std::vector<int16_t> fir_tap_in) {
        if (fir_tap_in.size() != 7) {
            printf("%s: fir_tap_in.size()==%ld, should be 7\n", __func__, fir_tap_in.size());
            return IP_ERROR;
        }
        return srm_tx_equalization_set(die, channel, (int16_t*)fir_tap_in.data());
    }

    ip_status_t
    srm_mcu_pif_write(uint32_t die, uint32_t addr, const std::vector<uint32_t> pif_data) {
        return srm_mcu_pif_write(die, addr, (const uint32_t *)pif_data.data(), pif_data.size());
    }

    std::vector<uint32_t>
    srm_mcu_pif_read(uint32_t die, uint32_t addr, uint32_t num_words) {
        std::vector<uint32_t> pif_data;
        pif_data.resize(num_words, 0);
        ip_status_t rc = srm_mcu_pif_read(die, addr, (uint32_t *)pif_data.data(), pif_data.size());
        if (rc) {
            printf("srm_mcu_pif_read: error, %d\n", rc);
            pif_data.resize(0);
        }
        return pif_data;
    }
}

// Struct that contains an array of structs. In SWIG, the array member is read-only.
%extend srm_anlt_bundle_t {
    srm_channel_t* lt_followers_item(size_t i) {
        if (i >= silicon_one::array_size($self->lt_followers)) {
            return nullptr;
        }
        return &$self->lt_followers[i];
    }

    size_t lt_followers_items_n() {
        return silicon_one::array_size($self->lt_followers);
    }
}

// Struct that contains an array of integers. In SWIG, the array member is read-only. We define a setter here.
%extend srm_tx_fir_t {
    ip_status_t set_fir_tap(std::vector<int16_t> val) {
        if (val.size() != silicon_one::array_size($self->fir_tap)) {
            printf("%s: bad size=%ld, should be %ld\n", __func__, val.size(), silicon_one::array_size($self->fir_tap));
            return IP_ERROR;
        }
        memcpy($self->fir_tap, val.data(), sizeof($self->fir_tap));
        return IP_OK;
    }
}

%inline {
    uint32_t
    get_serdes_addr(silicon_one::srm_serdes_addressing_mode_e addressing_mode,
                    uint32_t dev_id,
                    uint32_t slice,
                    uint32_t ifg,
                    uint32_t serdes_package,
                    uint32_t serdes_index) {
        silicon_one::srm_serdes_address addr = {
            .fields = {
                .serdes_index = serdes_index,
                .serdes_package = serdes_package,
                .ifg = ifg,
                .slice = slice,
                .device_id = dev_id,
                .reserved = 0,
                .addressing_mode = (uint32_t)addressing_mode
            }
        };

        return addr.u32;
    }
}
