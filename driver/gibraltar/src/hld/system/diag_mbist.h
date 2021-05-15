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

#ifndef __DIAG_MBIST_H__
#define __DIAG_MBIST_H__

#include "cpu2jtag/cpu2jtag.h"
#include "la_device_impl.h"

namespace silicon_one
{

class mbist
{
public:
    mbist(la_device_impl* dev);
    virtual ~mbist();
    const la_device* get_device() const;

    enum class bist_type_e {
        BIST = 0,          // The initial Built-in Self Test. If "repair" is not enabled this is the only step that runs.
        BIRA,              // Built-in Redundancy Analysis, runs after BIST, if "repair" is enabled.
        BISR,              // Built-in Self Repair, runs after BIRA, if "repair" is enabled.
        BIST_AFTER_REPAIR, // The final BIST step, runs after BISR if "repair" is enabled.
        LAST,
    };
    struct result {
        struct bist_type {
            uint32_t num_failed_processors;        // Num of failed processors in this BIST type
            std::vector<std::string> failed_rings; // Vector of failed rings in this BIST type
        } bist_types[(size_t)bist_type_e::LAST];
    };

    la_status run(bool repair, result& out_mbist_result);

private:
    la_device_impl* m_device;
    cpu2jtag* m_cpu2jtag;
    result m_result;

    void clear_result();
    la_status run_ring_mbist(std::string ring, bool repair);
    la_status select_sms(std::string ring);

    enum bist_instruction_e {
        BIRA_RUN = 0x12,
        BISR_RUN = 0x13,
        BIST_RUN = 0x11,
        BYPASS = 0x0,
        DIAGS_SEL = 0xb,
        INBR_RST = 0x17,
        RSCR_SEL = 0x18,
        STATUS_SEL = 0x9,
    };
    la_status shift_same_instruction_to_all_processors(bist_instruction_e instruction,
                                                       uint32_t num_of_processors,
                                                       uint32_t wait_milliseconds);
    la_status check_ring_results(std::string ring, uint32_t num_of_processors, bist_type_e type, bool& out_error);
    bool check_processor_result(std::string ring, uint32_t processor, bit_vector processor_tdo, bist_type_e type);
};
}
#endif
