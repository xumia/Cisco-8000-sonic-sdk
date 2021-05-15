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

/// @file
/// @brief Stand-alone device TM example.
///
/// @example tm1.cpp
///
/// Configure traffic management for standalone device (system with a single device),
/// with two destination system ports on the same interface group.
///
/// Higher-numbered queues (OQ7) get higher priority.
///
/// TM configuration
/// 1. Credit scheduler\n
///    a. SP1 (8 SerDes, 400G) gets 80% of the bandwidth, SP2 (2 SerDes, 100G) gets 20% of the bandwidth.\n
///    b. Each port has 8 queues assigned to it.
///       * Port 1: round robin for CIR, weights for EIR. Rates and weights are exponential.
///       * Port 2: strict priority between all queues
///    c. All similar ingress VOQ-s (same DSP, same priority) get credits in a round-robin fashion.\n
///
/// @dot
/// digraph tm1_credit_scheduler {
///     node[shape = record, style="bold, rounded", fontname = "Helvetica:bold", fontsize = 10];
///     edge [tailport="s", headport="n"];
///     cs   [label = "IFG CS"];
///     tp1  [label = "TM port 1\n(DSP1)"];
///     tp2  [label = "TM port 2\n(DSP2)"];
///     oq10 [label = "OQ0"];
///     oq17 [label = "OQ7"];
///     oq20 [label = "OQ0"];
///     oq27 [label = "OQ7"];
///     cs->tp1 [label = "80%"];
///     cs->tp2 [label = "20%"];
///     tp1->{oq10 oq17};
///     tp2->{oq20 oq27};
/// }
/// @enddot
///
/// 2. Transmit scheduler\n
///    a. SP1 gets 80% of the bandwidth, SP2 gets 20% of the bandwidth.\n
///    b. Each port has 8 queues assigned to it.
///       * Port 1: round robin for CIR, weights for EIR. Rates and weights are exponential.
///       * Port 2: strict priority between all queues
///    c. For the high-priority queue, UC traffic gets 90% of the bandwidth and MC traffic gets 10%.\n
///       For the other queues, UC traffic gets 70% of the bandwidth and MC traffic gets 30%.\n
///
/// @dot
/// digraph tm1_transmit_scheduler {
///     node[shape = box, style="bold, rounded", fontname = "Helvetica:bold", fontsize = 10];
///     edge [tailport="s", headport="n"];
///     ts   [label = "Transmit CS"];
///     tp1  [label = "TM port 1\n(DSP1)"];
///     tp2  [label = "TM port 2\n(DSP2)"];
///     oq10 [label = "OQ0"];
///     oq17 [label = "OQ7"];
///     oq20 [label = "OQ0"];
///     oq27 [label = "OQ7"];
///     oq10uc [label = "UC"];
///     oq10mc [label = "MC"];
///     oq17uc [label = "UC"];
///     oq17mc [label = "MC"];
///     oq20uc [label = "UC"];
///     oq20mc [label = "MC"];
///     oq27uc [label = "UC"];
///     oq27mc [label = "MC"];
///     ts->tp1 [label = "80%"];
///     ts->tp2 [label = "20%"];
///     tp1->{oq10 oq17};
///     tp2->{oq20 oq27};
///     oq10->oq10uc [label = "70%"];
///     oq10->oq10mc [label = "30%"];
///     oq17->oq17uc [label = "90%"];
///     oq17->oq17mc [label = "10%"];
///     oq20->oq20uc [label = "70%"];
///     oq20->oq20mc [label = "30%"];
///     oq27->oq27uc [label = "90%"];
///     oq27->oq27mc [label = "10%"];
/// }
/// @enddot
#include "example_system.h"

#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_switch.h"
#include "api/system/la_system_port.h"
#include "api/tm/la_ifg_scheduler.h"
#include "api/tm/la_interface_scheduler.h"
#include "api/tm/la_logical_port_scheduler.h"
#include "api/tm/la_output_queue_scheduler.h"
#include "api/tm/la_system_port_scheduler.h"
#include "api/tm/la_voq_set.h"
#include "api/types/la_common_types.h"
#include "api/types/la_tm_types.h"

using namespace silicon_one;

static la_slice_id_t dest_slice_id = 1;
static la_device_id_t device_id = 0;

void
tm1_init_slices(example_system_t* es)
{
    for (la_slice_id_t sid = 0; sid < 6; sid++) {
        es->xdevice->set_slice_mode(sid, la_slice_mode_e::NETWORK);
    }
}

void
tm1_configure_credit_scheduler(example_system_t* es)
{
    // Credit scheduler configuration
    // 1. IFG level: 80%-20% split between SP1 and SP2 traffic
    // 2. TM port level: port 1 RR/WFQ, port 2 SP
    // 3. OQ level: single round-robin group for VSC-s
    la_wfq_weight_t sp1_weight = 80;
    la_wfq_weight_t sp2_weight = 20;

    la_ifg_scheduler* ifg_sch = nullptr;
    es->xdevice->get_ifg_scheduler(dest_slice_id, 0 /* ifg */, ifg_sch);

    // 1. IFG-level settings

    // 2. Interface level settings
    la_interface_scheduler* ifc_sch1 = es->mac_ports[0]->get_scheduler();
    ;
    la_interface_scheduler* ifc_sch2 = es->mac_ports[1]->get_scheduler();
    ;
    ifc_sch1->set_cir_weight(sp1_weight);
    ifc_sch1->set_eir_weight(sp1_weight);

    ifc_sch2->set_cir_weight(sp2_weight);
    ifc_sch2->set_eir_weight(sp2_weight);

    // 3. System port-level settings
    la_system_port_scheduler* sp_sch1 = es->system_ports[0]->get_scheduler();
    ;
    la_system_port_scheduler* sp_sch2 = es->system_ports[1]->get_scheduler();
    ;

    // a. Port 1: RR for CIR, WFQ for EIR
    sp_sch1->set_oq_priority_group(7 /* queue */, la_system_port_scheduler::priority_group_e::SP8);
    sp_sch1->set_oq_priority_group(6 /* queue */, la_system_port_scheduler::priority_group_e::SP6);
    sp_sch1->set_oq_priority_group(5 /* queue */, la_system_port_scheduler::priority_group_e::SP4);
    sp_sch1->set_oq_priority_group(4 /* queue */, la_system_port_scheduler::priority_group_e::SP2);
    sp_sch1->set_oq_priority_group(3 /* queue */, la_system_port_scheduler::priority_group_e::SINGLE3);
    sp_sch1->set_oq_priority_group(2 /* queue */, la_system_port_scheduler::priority_group_e::SINGLE2);
    sp_sch1->set_oq_priority_group(1 /* queue */, la_system_port_scheduler::priority_group_e::SINGLE1);
    sp_sch1->set_oq_priority_group(0 /* queue */, la_system_port_scheduler::priority_group_e::SINGLE0);

    // CIR limit = 1G*2^priority
    // EIR weight = 1 + priority
    la_rate_t rate_1g = 1000000; // Basic rate is 1M credits/second

    sp_sch1->set_priority_group_credit_cir(la_system_port_scheduler::priority_group_e::SP8, rate_1g * 128);
    sp_sch1->set_priority_group_credit_cir(la_system_port_scheduler::priority_group_e::SP6, rate_1g * 64);
    sp_sch1->set_priority_group_credit_cir(la_system_port_scheduler::priority_group_e::SP4, rate_1g * 32);
    sp_sch1->set_priority_group_credit_cir(la_system_port_scheduler::priority_group_e::SP2, rate_1g * 16);
    sp_sch1->set_priority_group_credit_cir(la_system_port_scheduler::priority_group_e::SINGLE3, rate_1g * 8);
    sp_sch1->set_priority_group_credit_cir(la_system_port_scheduler::priority_group_e::SINGLE2, rate_1g * 4);
    sp_sch1->set_priority_group_credit_cir(la_system_port_scheduler::priority_group_e::SINGLE1, rate_1g * 2);
    sp_sch1->set_priority_group_credit_cir(la_system_port_scheduler::priority_group_e::SINGLE0, rate_1g * 1);

    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SP8, 8);
    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SP6, 7);
    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SP4, 6);
    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SP2, 5);
    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SINGLE3, 4);
    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SINGLE2, 3);
    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SINGLE1, 2);
    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SINGLE0, 1);

    // b. Port 2: strict priority between queues
    sp_sch2->set_oq_priority_group(7 /* queue */, la_system_port_scheduler::priority_group_e::SP8);
    sp_sch2->set_oq_priority_group(6 /* queue */, la_system_port_scheduler::priority_group_e::SP8);
    sp_sch2->set_oq_priority_group(5 /* queue */, la_system_port_scheduler::priority_group_e::SP8);
    sp_sch2->set_oq_priority_group(4 /* queue */, la_system_port_scheduler::priority_group_e::SP8);
    sp_sch2->set_oq_priority_group(3 /* queue */, la_system_port_scheduler::priority_group_e::SP8);
    sp_sch2->set_oq_priority_group(2 /* queue */, la_system_port_scheduler::priority_group_e::SP8);
    sp_sch2->set_oq_priority_group(1 /* queue */, la_system_port_scheduler::priority_group_e::SP8);
    sp_sch2->set_oq_priority_group(0 /* queue */, la_system_port_scheduler::priority_group_e::SP8);

    // OQ-level settings
    la_voq_set* voq_set_1 = es->system_ports[0]->get_voq_set();
    ;
    la_voq_set* voq_set_2 = es->system_ports[1]->get_voq_set();
    ;
    la_voq_gid_t dsp1_base_voq = voq_set_1->get_base_voq_id();
    la_voq_gid_t dsp2_base_voq = voq_set_2->get_base_voq_id();

    for (la_oq_id_t oid = 0; oid <= 7; oid++) {
        la_output_queue_scheduler* oq_sch1 = nullptr;
        la_output_queue_scheduler* oq_sch2 = nullptr;
        sp_sch1->get_output_queue_scheduler(oid, oq_sch1);
        sp_sch1->get_output_queue_scheduler(oid, oq_sch2);

        oq_sch1->set_scheduling_mode(la_output_queue_scheduler::scheduling_mode_e::DIRECT_4SP);
        oq_sch2->set_scheduling_mode(la_output_queue_scheduler::scheduling_mode_e::DIRECT_4SP);

        for (la_slice_id_t sid = 0; sid < 6; sid++) {
            la_vsc_gid_t dsp1_slice_base_vsc;
            la_vsc_gid_t dsp2_slice_base_vsc;
            voq_set_1->get_base_vsc(sid, dsp1_slice_base_vsc);
            voq_set_2->get_base_vsc(sid, dsp2_slice_base_vsc);

            dsp1_slice_base_vsc += oid + 8 * sid;
            dsp2_slice_base_vsc += oid + 8 * sid;

            oq_sch1->attach_vsc(dsp1_slice_base_vsc + oid, la_oq_vsc_mapping_e::RR0, device_id, sid, dsp1_base_voq + oid);
            oq_sch2->attach_vsc(dsp2_slice_base_vsc + oid, la_oq_vsc_mapping_e::RR0, device_id, sid, dsp2_base_voq + oid);
        }
    }
}

void
tm1_configure_transmit_scheduler(example_system_t* es)
{
    // Transmit scheduler configuration
    // 1. IFG level: 70-30 split between SP1 and SP2 traffic
    // 2. TM port level
    //    a. Port 1 RR/WFQ, port 2 SP
    //    b. 80-20 split between UC/MC traffic for priority queue, 70-30 for regular queue
    la_wfq_weight_t sp1_weight = 70;
    la_wfq_weight_t sp2_weight = 30;
    la_wfq_weight_t priority_uc_weight = 80, priority_mc_weight = 20;
    la_wfq_weight_t regular_uc_weight = 70, regular_mc_weight = 30;

    // 1. IFG-level settings

    // 2. Interface level settings
    la_interface_scheduler* ifc_sch1 = es->mac_ports[0]->get_scheduler();
    ;
    la_interface_scheduler* ifc_sch2 = es->mac_ports[1]->get_scheduler();
    ;
    ifc_sch1->set_cir_weight(sp1_weight);
    ifc_sch1->set_eir_weight(sp1_weight);

    ifc_sch2->set_cir_weight(sp2_weight);
    ifc_sch2->set_eir_weight(sp2_weight);

    // 3. System port-level settings
    la_system_port_scheduler* sp_sch1 = es->system_ports[0]->get_scheduler();
    ;
    la_system_port_scheduler* sp_sch2 = es->system_ports[1]->get_scheduler();
    ;

    // CIR limit = 1G*2^priority
    // EIR weight = 1 + priority
    la_rate_t rate_1g = 1000000; // Basic rate is 1M credits/second

    sp_sch1->set_priority_group_transmit_cir(la_system_port_scheduler::priority_group_e::SP8, rate_1g * 128);
    sp_sch1->set_priority_group_transmit_cir(la_system_port_scheduler::priority_group_e::SP6, rate_1g * 64);
    sp_sch1->set_priority_group_transmit_cir(la_system_port_scheduler::priority_group_e::SP4, rate_1g * 32);
    sp_sch1->set_priority_group_transmit_cir(la_system_port_scheduler::priority_group_e::SP2, rate_1g * 16);
    sp_sch1->set_priority_group_transmit_cir(la_system_port_scheduler::priority_group_e::SINGLE3, rate_1g * 8);
    sp_sch1->set_priority_group_transmit_cir(la_system_port_scheduler::priority_group_e::SINGLE2, rate_1g * 4);
    sp_sch1->set_priority_group_transmit_cir(la_system_port_scheduler::priority_group_e::SINGLE1, rate_1g * 2);
    sp_sch1->set_priority_group_transmit_cir(la_system_port_scheduler::priority_group_e::SINGLE0, rate_1g * 1);

    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SP8, 8);
    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SP6, 7);
    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SP4, 6);
    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SP2, 5);
    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SINGLE3, 4);
    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SINGLE2, 3);
    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SINGLE1, 2);
    sp_sch1->set_priority_group_eir_weight(la_system_port_scheduler::priority_group_e::SINGLE0, 1);

    // b. Port 2: strict priority between queues
    sp_sch2->set_oq_priority_group(7 /* queue */, la_system_port_scheduler::priority_group_e::SP8);
    sp_sch2->set_oq_priority_group(6 /* queue */, la_system_port_scheduler::priority_group_e::SP8);
    sp_sch2->set_oq_priority_group(5 /* queue */, la_system_port_scheduler::priority_group_e::SP8);
    sp_sch2->set_oq_priority_group(4 /* queue */, la_system_port_scheduler::priority_group_e::SP8);
    sp_sch2->set_oq_priority_group(3 /* queue */, la_system_port_scheduler::priority_group_e::SP8);
    sp_sch2->set_oq_priority_group(2 /* queue */, la_system_port_scheduler::priority_group_e::SP8);
    sp_sch2->set_oq_priority_group(1 /* queue */, la_system_port_scheduler::priority_group_e::SP8);
    sp_sch2->set_oq_priority_group(0 /* queue */, la_system_port_scheduler::priority_group_e::SP8);

    //    b. 80-20 split between UC/MC traffic
    // OQ-level settings
    for (la_oq_id_t oid = 0; oid <= 7; oid++) {
        la_output_queue_scheduler* oq_sch1 = nullptr;
        la_output_queue_scheduler* oq_sch2 = nullptr;
        sp_sch1->get_output_queue_scheduler(oid, oq_sch1);
        sp_sch1->get_output_queue_scheduler(oid, oq_sch2);

        if (oid == 7) {
            oq_sch1->set_transmit_uc_mc_weight(priority_uc_weight, priority_mc_weight);
            oq_sch2->set_transmit_uc_mc_weight(priority_uc_weight, priority_mc_weight);
        } else {
            oq_sch1->set_transmit_uc_mc_weight(regular_uc_weight, regular_mc_weight);
            oq_sch2->set_transmit_uc_mc_weight(regular_uc_weight, regular_mc_weight);
        }
    }
}

int
main()
{
    example_system_t es;
    example_system_init(&es);

    tm1_init_slices(&es);
    tm1_configure_credit_scheduler(&es);
    tm1_configure_transmit_scheduler(&es);
}
