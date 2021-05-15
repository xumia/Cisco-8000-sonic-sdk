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

#include "nsim_provider/nsim_test_flow.h"
#include "common/logger.h"
#include "device_simulator/dsim/device_simulator.h"

#include <map>

using namespace std;

//************************************
// Factory functions
//************************************

silicon_one::nsim_provider*
create_and_run_simulator_server(const char* host, size_t port, const char* device_path)
{
    std::string source_path = "../../npl/cisco_router";
    std::string leaba_defined_path = "../../npl/pacific/leaba_defined";
    std::string revision;
    const char* asic_env = getenv("ASIC");
    if (asic_env) {
        revision = asic_env;
        if (revision == "GIBRALTAR_A0" || revision == "GIBRALTAR_A1" || revision == "GIBRALTAR_A2") {
            leaba_defined_path = "../../npl/gibraltar/leaba_defined";
        } else if (revision == "ASIC3_A0") {
            leaba_defined_path = "../../devices/akpg/asic3/leaba_defined";
        } else if (revision == "ASIC4_A0") {
            leaba_defined_path = "../../devices/akpg/asic4/leaba_defined";
        } else if (revision == "ASIC5_A0") {
            leaba_defined_path = "../../devices/akpg/asic5/leaba_defined";
        }
    }

    // TODO: need to call activate() instead of reset(), after creating mac port to bring the port up. And even then,
    // there is a slight latency before the Rx of the port is enabled. The default "check_port_up_mode" for NSIM is to
    // "drop" the packets in case of port down, so untill this is fixed, just print a warning and continue test execution.
    map<string, string> additional_params = {{"revision", revision}, {"check_port_up_mode", "warn"}};

    silicon_one::nsim_provider* provider = new silicon_one::nsim_provider(
        device_path ? device_path : "", source_path, leaba_defined_path, additional_params, host ? host : "localhost", port);
    return provider;
}

//************************************
// Debug utilities
//************************************

void
set_nsim_flow_debug(bool val)
{
    silicon_one::logger& linst = silicon_one::logger::instance();

    silicon_one::la_logger_level_e severity = silicon_one::la_logger_level_e::INFO;
    if (val) {
        severity = silicon_one::la_logger_level_e::DEBUG;
    }

    linst.set_logging_level(silicon_one::logger::NO_DEVICE, silicon_one::la_logger_component_e::SIM, severity);
}

