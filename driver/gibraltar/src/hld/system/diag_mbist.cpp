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

#include "la_device_impl.h"

#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"

#include "diag_mbist.h"

#include "system/device_model_types.h"

#include <chrono>
#include <map>
#include <sstream>
#include <thread>
#include <vector>

using namespace std;

namespace silicon_one
{

static const char* MBIST_VERSION = "MBIST version 29/7/2019";

struct ring_number_and_type {
    uint32_t number;
    string type;
};

// clang-format off
static map<string, ring_number_and_type> ring_dict{
        { "dmc_css",       { .number =  1, .type = "dmc_css" }},
        { "dmc_non_css",   { .number =  2, .type = "dmc_non_css" }},
        { "mmu",           { .number =  3, .type = "mmu" }},
        { "ing_post_voq",  { .number =  4, .type = "ing_post_voq" }},
        { "sch",           { .number =  5, .type = "sch" }},
        { "egr",           { .number =  6, .type = "egr" }},
        { "pdoq",          { .number =  7, .type = "pdoq" }},
        { "pdvoq",         { .number =  8, .type = "pdvoq" }},
        { "txpp2",         { .number =  9, .type = "txpp" }},
        { "rxpp_fwd2",     { .number = 10, .type = "rxpp_fwd" }},
        { "rxpp_term2",    { .number = 11, .type = "rxpp_term" }},
        { "ifg_core4",     { .number = 12, .type = "ifg_core16" }},
        { "ifg_core5",     { .number = 13, .type = "ifg_core24" }},
        { "cdb_core0",     { .number = 14, .type = "cdb_core" }},
        { "cdb_core1",     { .number = 15, .type = "cdb_core" }},
        { "cdb_core2",     { .number = 16, .type = "cdb_core" }},
        { "cdb_core3",     { .number = 17, .type = "cdb_core" }},
        { "sms_quad0",     { .number = 18, .type = "sms_quad" }},
        { "sms_quad1",     { .number = 19, .type = "sms_quad" }},
        { "ing_pre_voq",   { .number = 20, .type = "ing_pre_voq" }},
        { "reorder",       { .number = 21, .type = "reorder" }},
        { "ing_start",     { .number = 22, .type = "ing_start" }},
        { "cdb_logic_top", { .number = 23, .type = "cdb_logic_top" }},
        { "idb1",          { .number = 24, .type = "idb" }},
        { "txpp3",         { .number = 25, .type = "txpp" }},
        { "rxpp_fwd3",     { .number = 26, .type = "rxpp_fwd" }},
        { "rxpp_term3",    { .number = 27, .type = "rxpp_term" }},
        { "ifg_core7",     { .number = 28, .type = "ifg_core16" }},
        { "ifg_core6",     { .number = 29, .type = "ifg_core24" }},
        { "cdb_core6",     { .number = 30, .type = "cdb_core" }},
        { "cdb_core5",     { .number = 31, .type = "cdb_core" }},
        { "cdb_core4",     { .number = 32, .type = "cdb_core" }},
        { "cdb_core7",     { .number = 33, .type = "cdb_core" }},
        { "sms_quad2",     { .number = 34, .type = "sms_quad" }},
        { "sms_quad3",     { .number = 35, .type = "sms_quad" }},
        { "fdll",          { .number = 36, .type = "fdll" }},
        { "dram_control",  { .number = 37, .type = "dram_control" }},
        { "counters",      { .number = 38, .type = "counters" }},
        { "sms_center",    { .number = 39, .type = "sms_center" }},
        { "ifg_core0",     { .number = 40, .type = "ifg_core24" }},
        { "rxpp_term0",    { .number = 41, .type = "rxpp_term" }},
        { "rxpp_fwd0",     { .number = 42, .type = "rxpp_fwd" }},
        { "txpp0",         { .number = 43, .type = "txpp" }},
        { "ifg_core1",     { .number = 44, .type = "ifg_core24" }},
        { "ifg_core2",     { .number = 45, .type = "ifg_core24" }},
        { "txpp1",         { .number = 46, .type = "txpp" }},
        { "rxpp_fwd1",     { .number = 47, .type = "rxpp_fwd" }},
        { "rxpp_term1",    { .number = 48, .type = "rxpp_term" }},
        { "ifg_core3",     { .number = 49, .type = "ifg_core16" }},
        { "idb0",          { .number = 50, .type = "idb" }},
        { "hbmhi",         { .number = 51, .type = "hbm" }},
        { "fllb",          { .number = 52, .type = "fllb" }},
        { "ifg_coreb",     { .number = 53, .type = "ifg_core24" }},
        { "rxpp_term5",    { .number = 54, .type = "rxpp_term" }},
        { "rxpp_fwd5",     { .number = 55, .type = "rxpp_fwd" }},
        { "txpp5",         { .number = 56, .type = "txpp" }},
        { "ifg_corea",     { .number = 57, .type = "ifg_core24" }},
        { "ifg_core9",     { .number = 58, .type = "ifg_core24" }},
        { "txpp4",         { .number = 59, .type = "txpp" }},
        { "rxpp_fwd4",     { .number = 60, .type = "rxpp_fwd" }},
        { "rxpp_term4",    { .number = 61, .type = "rxpp_term" }},
        { "ifg_core8",     { .number = 62, .type = "ifg_core16" }},
        { "idb2",          { .number = 63, .type = "idb" }},
        { "hbmlo",         { .number = 64, .type = "hbm" }},
    };

static set<string> matilda_32A_disabled_rings {
    "ifg_core6", "ifg_core7", "ifg_core8", "ifg_core9", "ifg_corea", "ifg_coreb",
    "rxpp_fwd3", "rxpp_term3", "rxpp_fwd4", "rxpp_term4", "rxpp_fwd5", "rxpp_term5",
    "txpp3", "txpp4", "txpp5",
    "idb2"
};

static set<string> matilda_32B_disabled_rings {
    "ifg_core0", "ifg_core1", "ifg_core2", "ifg_core3", "ifg_core4", "ifg_core5",
    "rxpp_fwd0", "rxpp_term0", "rxpp_fwd1", "rxpp_term1", "rxpp_fwd2", "rxpp_term2",
    "txpp0", "txpp1", "txpp2",
    "idb0"
};

static set<string> matilda_8T_A_disabled_rings {
    "ifg_corea", "ifg_coreb", "rxpp_fwd5", "rxpp_term5","txpp5"
};

static set<string> matilda_8T_B_disabled_rings {
    "ifg_core8", "ifg_core9", "rxpp_fwd4", "rxpp_term4","txpp4"
};

struct processor_name_and_num {
    string name;
    uint32_t num_of_processors;
};

struct ring_type_desc {
    vector<processor_name_and_num> processors;
};

static map<string, ring_type_desc> ring_type_dict{
        { "cdb_core",      { .processors = {{"cdb_core_processor",                       1}}}},
        { "cdb_logic_top", { .processors = {{"cdb_logic_top_processor",                  1},
                                            {"cem_mng_top_processor",                    1}}}},
        { "counters",      { .processors = {{"counters_collection_processor",            8},
                                            {"counters_processor",                       1}}}},
        { "dmc_css",       { .processors = {{"css_arc_cpu_processor",                    1},
                                            {"css_mem_processor",                        2},
                                            {"pcie_processor",                           1},
                                            {"css_processor",                            1},
                                            {"sbif_processor",                           1}}}},
        { "dmc_non_css",   { .processors = {{"csms_processor",                           1},
                                            {"frm_processor",                            1},
                                            {"mrb_processor",                            1},
                                            {"npu_host_processor",                       1},
                                            {"npe_macro_processor",                      1},
                                            {"pier_processor",                           1}}}},
        { "dram_control",  { .processors = {{"dram_control_processor",                   1}}}},
        { "egr",           { .processors = {{"egr_slice_processor",                      6}}}},
        { "fdll",          { .processors = {{"fdll_processor",                           1},
                                            {"fdll_empd_abstract_processor",             8}}}},
        { "fllb",          { .processors = {{"fllb_processor",                           1}}}},
        { "hbm",           { .processors = {{"hbm_macro0_processor",                     1},
                                            {"hbm_macro1_processor",                     1}}}},
        { "idb",           { .processors = {{"resolution_top_processor",                 1},
                                            {"idb_encdb_processor",                      1},
                                            {"idb_macdb_processor",                      1}}}},
        { "ifg_core16",    { .processors = {{"ifgb_24p_processor",                       1},
                                            {"mac_pool8_processor",                      2}}}},
        { "ifg_core24",    { .processors = {{"ifgb_24p_processor",                       1},
                                            {"mac_pool8_processor",                      3}}}},
        { "ing_post_voq",  { .processors = {{"ing_post_slice_processor",                 6},
                                            {"ing_post_voq_processor",                   1}}}},
        { "ing_pre_voq",   { .processors = {{"rx_pdr_2_slices_processor",                3},
                                            {"ing_pre_voq_processor",                    1}}}},
        { "ing_start",     { .processors = {{"ing_start_processor",                      1}}}},
        { "mmu",           { .processors = {{"mmu_processor",                            1},
                                            {"mmu_buff_processor",                       1},
                                            {"hbm_chnl_4x_tall_cfg0_processor",          8}}}},
        { "pdoq",          { .processors = {{"pdoq_slice_processor",                     6},
                                            {"pdoq_processor",                           1},
                                            {"pdoq_dual_empd_processor",                 8}}}},
        { "pdvoq",         { .processors = {{"pdvoq_slice_processor",                    6},
                                            {"pdvoq_dual_empd_processor",                8},
                                            {"pdvoq_core_processor",                     1}}}},
        { "reorder",       { .processors = {{"reorder_nw_reorder_block_processor",       6},
                                            {"reorder_processor",                        1},
                                            {"reorder_pp_reorder_slice_processor",       3}}}},
        { "rxpp_fwd",      { .processors = {{"npe_macro_processor",                      3},
                                            {"rxpp_fwd_processor",                       1}}}},
        { "rxpp_term",     { .processors = {{"rxpp_fi_stage_processor",                  1},
                                            {"npe_macro_processor",                      3},
                                            {"rxpp_term_processor",                      1},
                                            {"flc_db_processor",                         1}}}},
        { "sch",           { .processors = {{"sch_processor",                            12}}}},
        { "sms_center",    { .processors = {{"sms_main_processor",                       1}}}},
        { "sms_quad",      { .processors = {{"sms_quad_processor",                       1},
                                            {"sms_quad_bank_flat_processor",             63}}}},
        { "txpp",          { .processors = {{"npe_macro_processor",                      2},
                                            {"enc_stage_engine_cluster_no_ft_processor", 2},
                                            {"txpp_processor",                           1}}}},
    };

struct name_value_pair {
    string name;
    uint32_t value;
};

struct processor_chain_and_wrappers {
    vector<name_value_pair> chain_lengths;
    vector<name_value_pair> vwrappers;
};

static map<string, processor_chain_and_wrappers> processor_dict{
        { "cdb_core_processor",                       { .chain_lengths = {{"DIAGS",                                                          245},
                                                                          {"RSCR",                                                           729}},
                                                        .vwrappers =     {{"SACULS0G4U2P896X72M4B2W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SADCLS0G4L1P3584X163M4B4W0C1P0D0R1RM3SDRW00_2i_3101_vwrapper",   2},
                                                                          {"SADULS0G4L1P7168X26M16B2W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",   2},
                                                                          {"SADULS0G4S1P1024X39M4B1W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    24},
                                                                          {"SADULS0G4L1P2048X110M4B2W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",   56},
                                                                          {"SACRLS0G4S1P512X164M2B1W0C1P0D0R1RM3SDRW00_2i_3101_vwrapper",    2},
                                                                          {"SADULS0G4S1P1024X26M4B1W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    2}}}},

        { "cdb_logic_top_processor",                  { .chain_lengths = {{"DIAGS",                                                          235},
                                                                          {"RSCR",                                                           701}},
                                                        .vwrappers =     {{"SACULS0G4U2P64X166M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       4},
                                                                          {"SACULS0G4U2P40X166M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SADCLS0G4L1P2752X229M4B4W0C1P0D0R1RM3SDRW00_6i_3101_vwrapper",   1},
                                                                          {"SACULS0G4U2P256X170M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      12},
                                                                          {"SACULS0G4U2P256X164M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      12},
                                                                          {"SADULS0G4L1P9216X26M16B4W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",   1},
                                                                          {"SACULS0G4U2P64X164M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       8},
                                                                          {"SACRLS0G4S1P256X40M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SACULS0G4U2P256X74M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       6},
                                                                          {"SACULS0G4U2P128X84M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       12},
                                                                          {"SACULS0G4U2P256X166M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      12},
                                                                          {"SACULS0G4U2P64X92M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        4},
                                                                          {"SACULS0G4U2P40X92M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        2},
                                                                          {"SACRLS0G4S1P128X40M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SACULS0G4U2P256X76M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       6},
                                                                          {"SACULS0G4U2P40X164M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       2}}}},
        { "cem_mng_top_processor",                    { .chain_lengths = {{"DIAGS",                                                          52},
                                                                          {"RSCR",                                                           14}},
                                                        .vwrappers =     {{"SACRLS0G4S1P512X32M2B1W1C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SADULS0G4S1P4096X33M8B2W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",    1}}}},
        { "counters_collection_processor",            { .chain_lengths = {{"DIAGS",                                                          96},
                                                                          {"RSCR",                                                           181}},
                                                        .vwrappers =     {{"SACULS0G4L2P256X40M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       12},
                                                                          {"SADCLS0G4L1P4096X137M4B4W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",   12}}}},
        { "counters_processor",                       { .chain_lengths = {{"DIAGS",                                                          110},
                                                                          {"RSCR",                                                           224}},
                                                        .vwrappers =     {{"SACRLS0G4S1P112X86M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SADULS0G4S1P1024X30M4B1W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    6},
                                                                          {"SACULS0G4L2P192X40M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       12},
                                                                          {"SADCLS0G4L1P3072X137M4B4W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",   12}}}},
        { "csms_processor",                           { .chain_lengths = {{"DIAGS",                                                          143},
                                                                          {"RSCR",                                                           296}},
                                                        .vwrappers =     {{"SASULS0G4U2P1824X32M8B1W0C1P0D0R1RM3SDRW00_9i_3101_vwrapper",    3},
                                                                          {"SACULS0G4L2P768X32M4B2W0C0P0D0R1RM3RW00_3i_3101_vwrapper",       1},
                                                                          {"SADULS0G4L1P8192X14M16B2W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",   3},
                                                                          {"SADULS0G4L1P8192X12M16B2W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",   1},
                                                                          {"SADULS0G4L1P4096X21M8B2W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    4},
                                                                          {"SADULS0G4L1P8192X21M16B2W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",   4}}}},
        { "css_arc_cpu_processor",                    { .chain_lengths = {{"DIAGS",                                                          128},
                                                                          {"RSCR",                                                           257}},
                                                        .vwrappers =     {{"SADULS0G4S1P4096X32M8B2W1C1P0D0R1RM3SDRW01_1i_3101_vwrapper",    8},
                                                                          {"SACRLS0G4S1P512X20M4B1W1C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     8},
                                                                          {"SADULS0G4S1P2048X32M4B2W1C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    8},
                                                                          {"SADULS0G4S1P4096X32M8B2W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",    8},
                                                                          {"SACRLS0G4S1P512X19M4B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     8}}}},
        { "css_mem_processor",                        { .chain_lengths = {{"DIAGS",                                                          187},
                                                                          {"RSCR",                                                           577}},
                                                        .vwrappers =     {{"SADCLS0G4L1P16384X39M16B4W0C1P0D0R1RM3SDRW00_32i_3101_vwrapper", 2}}}},
        { "css_processor",                            { .chain_lengths = {{"DIAGS",                                                          79},
                                                                          {"RSCR",                                                           91}},
                                                        .vwrappers =     {{"SADRLS0G4L2P128X40M1B2W0C0P0D0RM3SDRW00_1i_3101_vwrapper",       18}}}},
        { "dram_control_processor",                   { .chain_lengths = {{"DIAGS",                                                          467},
                                                                          {"RSCR",                                                           1318}},
                                                        .vwrappers =     {{"SACULS0G4L2P64X72M2B1W0C0P0D0R1RM3RW00_2i_3101_vwrapper",        2},
                                                                          {"SACULS0G4L2P1024X29M4B2W0C0P0D0R1RM3RW00_8i_3101_vwrapper",      2},
                                                                          {"SACRLS0G4S1P256X72M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SACRLS0G4S1P64X72M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",      1},
                                                                          {"SACULS0G4U2P128X80M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4L2P1024X21M4B2W0C0P0D0R1RM3RW00_8i_3101_vwrapper",      1},
                                                                          {"SACULS0G4L2P128X40M2B1W0C0P0D0R1RM3RW00_3i_3101_vwrapper",       2},
                                                                          {"SACULS0G4L2P64X72M2B1W0C0P0D0R1RM3RW00_3i_3101_vwrapper",        4},
                                                                          {"SACULS0G4L2P1024X49M4B2W0C1P0D0R1RM3RW00_8i_3101_vwrapper",      1},
                                                                          {"SASULS0G4L2P2048X10M16B1W0C0P0D0R1RM3SDRW00_4i_3101_vwrapper",   1},
                                                                          {"SACRLS0G4S1P512X40M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SADULS0G4L1P4096X55M8B2W0C1P0D0R1RM3SDRW01_2i_3101_vwrapper",    1},
                                                                          {"SACULS0G4L2P1024X26M4B2W0C0P0D0R1RM3RW00_4i_3101_vwrapper",      3},
                                                                          {"SADRLS0G4S2P256X192M1B4W0C1P0D0RM3SDRW00_2i_3101_vwrapper",      1},
                                                                          {"SACRLS0G4S1P32X184M2B1W0C1P0D0R1RM3SDRW00_3i_3101_vwrapper",     1},
                                                                          {"SASSLS0G4L1P16384X46M16B4W0C1P0D0R1RM3SDRW00_4i_3101_vwrapper",  8},
                                                                          {"SADULS0G4L1P11008X44M16B4W0C1P0D0R1RM3SDRW01_6i_3101_vwrapper",  8},
                                                                          {"SACULS0G4U2P832X76M4B2W0C1P0D0R1RM3RW00_5i_3101_vwrapper",       1},
                                                                          {"SACULS0G4U2P1024X39M4B2W0C0P0D0R1RM3RW00_4i_3101_vwrapper",      1}}}},
        { "egr_slice_processor",                      { .chain_lengths = {{"DIAGS",                                                          139},
                                                                          {"RSCR",                                                           234}},
                                                        .vwrappers =     {{"SACULS0G4L2P896X30M4B2W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       3},
                                                                          {"SACULS0G4L2P992X30M4B2W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SASULS0G4U2P1184X30M8B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    1},
                                                                          {"SACULS0G4L2P896X64M4B2W0C1P0D0R1RM3RW00_2i_3101_vwrapper",       3},
                                                                          {"SACULS0G4L2P992X64M4B2W0C1P0D0R1RM3RW00_2i_3101_vwrapper",       2},
                                                                          {"SACULS0G4L2P400X128M2B2W0C1P0D0R1RM3RW00_3i_3101_vwrapper",      1},
                                                                          {"SADRLS0G4S2P16X148M1B1W0C1P0D0RM3SDRW00_4i_3101_vwrapper",       1},
                                                                          {"SADRLS0G4S2P16X228M1B1W0C1P0D0RM3SDRW00_2i_3101_vwrapper",       1},
                                                                          {"SACRLS0G4S1P216X14M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SADULS0G4L1P5504X51M8B4W0C1P0D0R1RM3SDRW01_3i_3101_vwrapper",    1},
                                                                          {"SACULS0G4U2P96X82M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        1},
                                                                          {"SACULS0G4L2P128X126M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      1},
                                                                          {"SACULS0G4U2P1024X36M4B2W0C0P0D0R1RM3RW00_1i_3101_vwrapper",      1},
                                                                          {"SACULS0G4L2P1024X50M4B2W0C1P0D0R1RM3RW00_2i_3101_vwrapper",      1}}}},
        { "enc_stage_engine_cluster_no_ft_processor", { .chain_lengths = {{"DIAGS",                                                          92},
                                                                          {"RSCR",                                                           169}},
                                                        .vwrappers =     {{"SACRLS0G4S1P256X138M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    12},
                                                                          {"SACRLS0G4S1P256X54M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     12}}}},
        { "fdll_empd_abstract_processor",             { .chain_lengths = {{"DIAGS",                                                          102},
                                                                          {"RSCR",                                                           185}},
                                                        .vwrappers =     {{"SACRLS0G4L1P1024X222M2B2W1C1P0D0R1RM3SDRW00_1i_3101_vwrapper",   7},
                                                                          {"SACULS0G4U2P288X138M2B2W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      1},
                                                                          {"SADULS0G4L1P12288X25M16B4W0C1P0D0R1RM3SDRW01_3i_3101_vwrapper",  1},
                                                                          {"SASULS0G4U2P3072X20M16B1W0C1P0D0R1RM3SDRW00_12i_3101_vwrapper",  1}}}},
        { "fdll_processor",                           { .chain_lengths = {{"DIAGS",                                                          85},
                                                                          {"RSCR",                                                           120}},
                                                        .vwrappers =     {{"SACULS0G4L2P128X46M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       7},
                                                                          {"SACULS0G4L2P128X28M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       7},
                                                                          {"SACULS0G4L2P128X54M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       7}}}},
        { "flc_db_processor",                         { .chain_lengths = {{"DIAGS",                                                          176},
                                                                          {"RSCR",                                                           347}},
                                                        .vwrappers =     {{"SACULS0G4L2P96X138M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SADULS0G4L1P12288X22M16B4W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",  1},
                                                                          {"SACULS0G4U2P1024X68M4B2W0C1P0D0R1RM3RW00_2i_3101_vwrapper",      18},
                                                                          {"SADRLS0G4S2P40X224M1B1W0C1P0D0RM3SDRW00_6i_3101_vwrapper",       1}}}},
        { "fllb_processor",                           { .chain_lengths = {{"DIAGS",                                                          537},
                                                                          {"RSCR",                                                           1457}},
                                                        .vwrappers =     {{"SACULS0G4L2P512X90M2B2W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       6},
                                                                          {"SADCLS0G4L1P8192X82M8B4W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    12},
                                                                          {"SADULS0G4L1P8192X21M16B2W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",   12},
                                                                          {"SACULS0G4L2P1024X4M4B2W1C0P0D0R1RM3RW00_1i_3101_vwrapper",       84},
                                                                          {"SADULS0G4S1P1024X92M4B1W1C1P0D0R1RM3SDRW01_1i_3101_vwrapper",    84},
                                                                          {"SACULS0G4L2P128X72M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       12},
                                                                          {"SACULS0G4U2P512X43M4B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       5},
                                                                          {"SACRLS0G4S1P512X74M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     5},
                                                                          {"SACULS0G4U2P48X156M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       6},
                                                                          {"SADRLS0G4S2P16X152M1B1W0C1P0D0RM3SDRW00_2i_3101_vwrapper",       6}}}},
        { "frm_processor",                            { .chain_lengths = {{"DIAGS",                                                          73},
                                                                          {"RSCR",                                                           64}},
                                                        .vwrappers =     {{"SACULS0G4L2P512X116M2B2W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      1},
                                                                          {"SADULS0G4L1P6144X43M8B4W0C1P0D0R1RM3SDRW01_3i_3101_vwrapper",    1},
                                                                          {"SACULS0G4U2P112X134M2B1W0C1P0D0R1RM3RW00_2i_3101_vwrapper",      2}}}},
        { "hbm_chnl_4x_tall_cfg0_processor",          { .chain_lengths = {{"DIAGS",                                                          127},
                                                                          {"RSCR",                                                           241}},
                                                        .vwrappers =     {{"SACULS0G4L2P64X82M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",        2},
                                                                          {"SACRLS0G4L1P448X50M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     2},
                                                                          {"SACRLS0G4L1P512X184M2B1W0C1P0D0R1RM3SDRW00_3i_3101_vwrapper",    4},
                                                                          {"SACULS0G4U2P288X22M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SACRLS0G4L1P192X42M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     2},
                                                                          {"SACRLS0G4L1P256X188M2B1W0C1P0D0R1RM3SDRW00_3i_3101_vwrapper",    4}}}},
        { "hbm_macro0_processor",                     { .chain_lengths = {{"DIAGS",                                                          94},
                                                                          {"RSCR",                                                           161}},
                                                        .vwrappers =     {{"SACRLS0G4L1P256X182M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    1},
                                                                          {"SADRLS0G4L2P128X36M1B2W0C0P0D0RM3SDRW00_1i_3101_vwrapper",       8},
                                                                          {"SADRLS0G4U2P128X144M1B2W0C0P0D0RM3SDRW00_1i_3101_vwrapper",      16}}}},
        { "hbm_macro1_processor",                     { .chain_lengths = {{"DIAGS",                                                          91},
                                                                          {"RSCR",                                                           153}},
                                                        .vwrappers =     {{"SADRLS0G4L2P128X36M1B2W0C0P0D0RM3SDRW00_1i_3101_vwrapper",       8},
                                                                          {"SADRLS0G4U2P128X144M1B2W0C0P0D0RM3SDRW00_1i_3101_vwrapper",      16}}}},
        { "idb_encdb_processor",                      { .chain_lengths = {{"DIAGS",                                                          443},
                                                                          {"RSCR",                                                           1409}},
                                                        .vwrappers =     {{"SADULS0G4S1P2048X87M4B2W0C1P0D0R1RM3SDRW01_10i_3101_vwrapper",   4},
                                                                          {"SADULS0G4S1P2048X92M4B2W0C1P0D0R1RM3SDRW01_10i_3101_vwrapper",   12},
                                                                          {"SACRLS0G4S1P512X138M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    2},
                                                                          {"SADULS0G4L1P3072X85M4B4W0C1P0D0R1RM3SDRW01_4i_3101_vwrapper",    2},
                                                                          {"SADULS0G4S1P2048X85M4B2W0C1P0D0R1RM3SDRW01_2i_3101_vwrapper",    2},
                                                                          {"SACRLS0G4S1P1024X170M2B2W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",   2}}}},
        { "idb_macdb_processor",                      { .chain_lengths = {{"DIAGS",                                                          410},
                                                                          {"RSCR",                                                           1257}},
                                                        .vwrappers =     {{"SADULS0G4S1P2048X88M4B2W0C1P0D0R1RM3SDRW01_7i_3101_vwrapper",    1},
                                                                          {"SADULS0G4S1P2048X88M4B2W0C1P0D0R1RM3SDRW01_2i_3101_vwrapper",    2},
                                                                          {"SADULS0G4L1P4096X57M8B2W0C1P0D0R1RM3SDRW01_51i_3101_vwrapper",   1},
                                                                          {"SADULS0G4L1P2048X100M4B2W0C1P0D0R1RM3SDRW01_2i_3101_vwrapper",   8},
                                                                          {"SADULS0G4L1P1024X126M4B1W0C1P0D0R1RM3SDRW01_9i_3101_vwrapper",   8},
                                                                          {"SADULS0G4S1P1024X89M4B1W0C1P0D0R1RM3SDRW01_5i_3101_vwrapper",    1},
                                                                          {"SADULS0G4L1P4096X39M8B2W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",    2}}}},
        { "ifgb_24p_processor",                       { .chain_lengths = {{"DIAGS",                                                          710},
                                                                          {"RSCR",                                                           1967}},
                                                        .vwrappers =     {{"SACULS0G4U2P64X100M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SACRLS0G4S1P240X120M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",    1},
                                                                          {"SACULS0G4U2P704X67M4B2W0C1P0D0R1RM3RW00_4i_3101_vwrapper",       6},
                                                                          {"SACULS0G4U2P704X75M4B2W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4U2P32X110M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       24},
                                                                          {"SACULS0G4U2P864X72M4B2W0C1P0D0R1RM3RW00_3i_3101_vwrapper",       16},
                                                                          {"SACULS0G4U2P800X72M4B2W0C1P0D0R1RM3RW00_2i_3101_vwrapper",       16},
                                                                          {"SACRLS0G4S1P64X218M2B1W0C1P0D0R1RM3SDRW00_5i_3101_vwrapper",     1},
                                                                          {"SASULS0G4U2P1280X56M8B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    3},
                                                                          {"SACULS0G4L2P320X56M2B2W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4L2P128X128M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      9},
                                                                          {"SACULS0G4U2P128X138M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      3},
                                                                          {"SACULS0G4U2P48X88M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        24},
                                                                          {"SACULS0G4U2P864X72M4B2W0C1P0D0R1RM3RW00_2i_3101_vwrapper",       32},
                                                                          {"SACRLS0G4S1P64X214M2B1W0C1P0D0R1RM3SDRW00_5i_3101_vwrapper",     1},
                                                                          {"SACULS0G4L2P704X30M4B2W0C0P0D0R1RM3RW00_3i_3101_vwrapper",       3},
                                                                          {"SACULS0G4L2P432X30M4B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1}}}},
        { "ing_post_slice_processor",                 { .chain_lengths = {{"DIAGS",                                                          323},
                                                                          {"RSCR",                                                           751}},
                                                        .vwrappers =     {{"SACULS0G4U2P512X72M2B2W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4L2P512X38M4B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4L2P512X15M4B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SACULS0G4L2P512X25M4B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SASULS0G4U2P2304X18M16B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",   1},
                                                                          {"SACULS0G4L2P1024X30M4B2W0C0P0D0R1RM3RW00_2i_3101_vwrapper",      1},
                                                                          {"SACRLS0G4S1P512X72M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SADULS0G4L1P11008X32M16B4W0C1P0D0R1RM3SDRW01_6i_3101_vwrapper",  1},
                                                                          {"SACULS0G4L2P64X72M2B1W0C0P0D0R1RM3RW00_3i_3101_vwrapper",        7},
                                                                          {"SACULS0G4L2P1024X22M4B2W0C0P0D0R1RM3RW00_4i_3101_vwrapper",      1},
                                                                          {"SACULS0G4L2P1024X29M4B2W0C0P0D0R1RM3RW00_8i_3101_vwrapper",      2},
                                                                          {"SACULS0G4U2P128X144M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      6},
                                                                          {"SACULS0G4L2P128X32M2B1W1C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4L2P128X76M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4L2P64X128M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4L2P1024X22M4B2W0C0P0D0R1RM3RW00_8i_3101_vwrapper",      1},
                                                                          {"SACULS0G4L2P256X26M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4L2P64X144M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4U2P128X146M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      2},
                                                                          {"SACULS0G4L2P1024X29M4B2W0C0P0D0R1RM3RW00_4i_3101_vwrapper",      2},
                                                                          {"SACULS0G4L2P1024X18M4B2W0C0P0D0R1RM3RW00_12i_3101_vwrapper",     1},
                                                                          {"SASULS0G4L2P2048X8M16B1W0C0P0D0R1RM3SDRW00_6i_3101_vwrapper",    1},
                                                                          {"SASULS0G4L2P2048X10M16B1W0C0P0D0R1RM3SDRW00_2i_3101_vwrapper",   1},
                                                                          {"SACULS0G4L2P1024X21M4B2W0C0P0D0R1RM3RW00_4i_3101_vwrapper",      1},
                                                                          {"SACULS0G4L2P256X34M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SADULS0G4S1P4096X10M16B1W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",   1},
                                                                          {"SACULS0G4L2P512X18M4B1W0C0P0D0R1RM3RW00_2i_3101_vwrapper",       1},
                                                                          {"SASULS0G4U2P2304X15M16B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",   1},
                                                                          {"SACULS0G4U2P128X130M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      1}}}},
        { "ing_post_voq_processor",                   { .chain_lengths = {{"DIAGS",                                                          219},
                                                                          {"RSCR",                                                           440}},
                                                        .vwrappers =     {{"SACULS0G4L2P64X72M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        1},
                                                                          {"SACULS0G4L2P1024X26M4B2W0C0P0D0R1RM3RW00_4i_3101_vwrapper",      6},
                                                                          {"SACULS0G4L2P1024X26M4B2W0C0P0D0R1RM3RW00_8i_3101_vwrapper",      6}}}},
        { "ing_pre_voq_processor",                    { .chain_lengths = {{"DIAGS",                                                          271},
                                                                          {"RSCR",                                                           769}},
                                                        .vwrappers =     {{"SACULS0G4L2P416X39M4B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       6},
                                                                          {"SACRLS0G4S1P256X18M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     6},
                                                                          {"SACRLS0G4S1P416X48M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     6},
                                                                          {"SACULS0G4L2P64X118M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       12},
                                                                          {"SADULS0G4L1P2048X99M4B2W0C1P0D0R1RM3SDRW01_9i_3101_vwrapper",    8}}}},
        { "ing_start_processor",                      { .chain_lengths = {{"DIAGS",                                                          549},
                                                                          {"RSCR",                                                           1511}},
                                                        .vwrappers =     {{"SACULS0G4L2P960X62M4B2W0C1P0D0R1RM3RW00_5i_3101_vwrapper",       6},
                                                                          {"SACULS0G4U2P128X142M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      1},
                                                                          {"SACULS0G4L2P80X146M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4U2P128X156M2B1W0C1P0D0R1RM3RW00_2i_3101_vwrapper",      6},
                                                                          {"SACULS0G4U2P80X152M2B1W0C1P0D0R1RM3RW00_2i_3101_vwrapper",       6},
                                                                          {"SACULS0G4U2P64X104M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACRLS0G4S1P512X22M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SADULS0G4L1P2048X112M4B2W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",   1},
                                                                          {"SADULS0G4L1P2048X99M4B2W0C1P0D0R1RM3SDRW01_4i_3101_vwrapper",    4},
                                                                          {"SACULS0G4L2P512X30M4B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       4},
                                                                          {"SADULS0G4S1P1024X47M4B1W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    16},
                                                                          {"SADULS0G4S1P4096X18M8B2W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    16},
                                                                          {"SACRLS0G4S1P512X30M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     16},
                                                                          {"SACRLS0G4S1P512X80M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     4},
                                                                          {"SACULS0G4L2P1024X20M4B2W0C0P0D0R1RM3RW00_1i_3101_vwrapper",      24},
                                                                          {"SACULS0G4L2P1024X60M4B2W0C1P0D0R1RM3RW00_2i_3101_vwrapper",      4},
                                                                          {"SACRLS0G4S1P512X48M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     4},
                                                                          {"SADCLS0G4S1P4096X98M4B4W0C1P0D0R1RM3SDRW00_2i_3101_vwrapper",    1},
                                                                          {"SACULS0G4L2P1024X63M4B2W0C1P0D0R1RM3RW00_2i_3101_vwrapper",      6},
                                                                          {"SACRLS0G4S1P136X254M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    12},
                                                                          {"SACULS0G4L2P1024X18M4B2W0C0P0D0R1RM3RW00_1i_3101_vwrapper",      12},
                                                                          {"SADRLS0G4L2P1024X96M4B4W0C1P0D0RM3SDRW00_1i_3101_vwrapper",      12}}}},
        { "mac_pool8_processor",                      { .chain_lengths = {{"DIAGS",                                                          124},
                                                                          {"RSCR",                                                           269}},
                                                        .vwrappers =     {{"SACULS0G4L2P152X68M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       16},
                                                                          {"SACULS0G4L2P96X120M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       4},
                                                                          {"SADRLS0G4S2P44X120M1B1W0C0P0D0RM3SDRW00_1i_3101_vwrapper",       4},
                                                                          {"SACULS0G4L2P72X66M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        8},
                                                                          {"SACULS0G4L2P72X64M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        8}}}},
        { "mmu_buff_processor",                       { .chain_lengths = {{"DIAGS",                                                          77},
                                                                          {"RSCR",                                                           129}},
                                                        .vwrappers =     {{"SACRLS0G4L1P512X138M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    16}}}},
        { "mmu_processor",                            { .chain_lengths = {{"DIAGS",                                                          82},
                                                                          {"RSCR",                                                           114}},
                                                        .vwrappers =     {{"SACRLS0G4L1P256X26M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     2},
                                                                          {"SACULS0G4L2P256X90M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4U2P48X208M2B1W0C1P0D0R1RM3RW00_3i_3101_vwrapper",       4}}}},
        { "mrb_processor",                            { .chain_lengths = {{"DIAGS",                                                          49},
                                                                          {"RSCR",                                                           7}},
                                                        .vwrappers =     {{"SADULS0G4L1P2048X32M4B2W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    1}}}},
        { "npe_macro_processor",                      { .chain_lengths = {{"DIAGS",                                                          173},
                                                                          {"RSCR",                                                           411}},
                                                        .vwrappers =     {{"SADRLS0G4S2P96X248M1B2W0C1P0D0RM3SDRW00_4i_3101_vwrapper",       2},
                                                                          {"SACRLS0G4S1P32X234M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SACRLS0G4S1P32X68M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",      1},
                                                                          {"SACULS0G4U2P96X168M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       4},
                                                                          {"SACULS0G4U2P96X88M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        4},
                                                                          {"SACULS0G4U2P192X168M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      2},
                                                                          {"SACULS0G4U2P192X88M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SACRLS0G4S1P32X226M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",     2},
                                                                          {"SACRLS0G4S1P32X140M2B1W0C1P0D0R1RM3SDRW00_2i_3101_vwrapper",     1},
                                                                          {"SACRLS0G4S1P32X178M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SACRLS0G4S1P32X210M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SACRLS0G4S1P32X150M2B1W0C1P0D0R1RM3SDRW00_2i_3101_vwrapper",     1},
                                                                          {"SACRLS0G4S1P32X162M2B1W0C1P0D0R1RM3SDRW00_2i_3101_vwrapper",     1},
                                                                          {"SACRLS0G4S1P32X180M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SACRLS0G4S1P32X212M2B1W0C1P0D0R1RM3SDRW00_2i_3101_vwrapper",     1},
                                                                          {"SACRLS0G4S1P32X182M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SACRLS0G4S1P32X232M2B1W0C1P0D0R1RM3SDRW00_3i_3101_vwrapper",     1},
                                                                          {"SADULS0G4S1P1024X33M4B1W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    5},
                                                                          {"SADULS0G4S1P2048X33M4B2W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    2},
                                                                          {"SADULS0G4S1P1024X97M4B1W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",    1},
                                                                          {"SADRLS0G4S2P192X236M1B4W0C1P0D0RM3SDRW00_8i_3101_vwrapper",      1}}}},
        { "npu_host_processor",                       { .chain_lengths = {{"DIAGS",                                                          110},
                                                                          {"RSCR",                                                           198}},
                                                        .vwrappers =     {{"SADULS0G4L1P4096X57M8B2W0C1P0D0R1RM3SDRW01_3i_3101_vwrapper",    1},
                                                                          {"SACRLS0G4S1P256X138M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    2},
                                                                          {"SACRLS0G4S1P256X54M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SADULS0G4S1P2048X88M4B2W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",    4},
                                                                          {"SADULS0G4S1P1024X69M4B1W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",    1},
                                                                          {"SADCLS0G4L1P4096X105M4B4W0C1P0D0R1RM3SDRW00_4i_3101_vwrapper",   1},
                                                                          {"SADULS0G4L1P4096X39M8B2W0C1P0D0R1RM3SDRW01_2i_3101_vwrapper",    1},
                                                                          {"SADULS0G4L1P8192X22M16B2W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",   1},
                                                                          {"SACRLS0G4S1P64X80M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",      1},
                                                                          {"SACRLS0G4S1P128X62M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SADRLS0G4S2P20X180M1B1W1C1P0D0RM3SDRW00_1i_3101_vwrapper",       1},
                                                                          {"SADRLS0G4S2P20X232M1B1W0C1P0D0RM3SDRW00_5i_3101_vwrapper",       1}}}},
        { "pcie_processor",                           { .chain_lengths = {{"DIAGS",                                                          67},
                                                                          {"RSCR",                                                           58}},
                                                        .vwrappers =     {{"SACULS0G4L2P1024X41M4B2W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      1},
                                                                          {"SACULS0G4U2P864X41M4B2W0C0P0D0R1RM3RW00_5i_3101_vwrapper",       1},
                                                                          {"SASULS0G4U2P1280X41M8B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    1},
                                                                          {"SADULS0G4S1P1152X41M4B2W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    1}}}},
        { "pdoq_dual_empd_processor",                 { .chain_lengths = {{"DIAGS",                                                          121},
                                                                          {"RSCR",                                                           183}},
                                                        .vwrappers =     {{"SACULS0G4L2P512X4M4B1W1C0P0D0R1RM3RW00_1i_3101_vwrapper",        14},
                                                                          {"SACRLS0G4S1P512X68M2B1W1C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     14},
                                                                          {"SACULS0G4L2P216X22M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SADULS0G4L1P3456X75M4B4W0C1P0D0R1RM3SDRW01_2i_3101_vwrapper",    2}}}},
        { "pdoq_processor",                           { .chain_lengths = {{"DIAGS",                                                          102},
                                                                          {"RSCR",                                                           200}},
                                                        .vwrappers =     {{"SACULS0G4L2P160X38M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4L2P160X26M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SACULS0G4L2P160X70M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4U2P160X142M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      1},
                                                                          {"SACULS0G4L2P48X150M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       6},
                                                                          {"SACULS0G4L2P256X30M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       6},
                                                                          {"SADRLS0G4L2P256X208M1B4W0C1P0D0RM3SDRW00_1i_3101_vwrapper",      6},
                                                                          {"SACULS0G4U2P256X174M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      6}}}},
        { "pdoq_slice_processor",                     { .chain_lengths = {{"DIAGS",                                                          165},
                                                                          {"RSCR",                                                           306}},
                                                        .vwrappers =     {{"SACULS0G4L2P416X22M4B1W0C0P0D0R1RM3RW00_2i_3101_vwrapper",       2},
                                                                          {"SACULS0G4U2P832X34M4B2W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SACULS0G4L2P416X22M4B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SACRLS0G4S1P416X22M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SACRLS0G4S1P208X16M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     4},
                                                                          {"SACRLS0G4S1P208X26M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     4},
                                                                          {"SACRLS0G4S1P128X76M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SACULS0G4L2P864X53M4B2W0C1P0D0R1RM3RW00_2i_3101_vwrapper",       2},
                                                                          {"SACULS0G4L2P864X21M4B2W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SACULS0G4L2P864X21M4B2W0C0P0D0R1RM3RW00_2i_3101_vwrapper",       2},
                                                                          {"SADRLS0G4S2P24X192M1B1W0C1P0D0RM3SDRW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4S2P256X15M4B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4L2P864X22M4B2W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4L2P128X38M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACRLS0G4S1P32X80M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",      2},
                                                                          {"SACRLS0G4S1P208X18M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     2},
                                                                          {"SACRLS0G4S1P208X22M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     2},
                                                                          {"SACULS0G4L2P192X62M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4L2P352X26M4B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SADRLS0G4S2P160X224M1B4W0C1P0D0RM3SDRW00_1i_3101_vwrapper",      1},
                                                                          {"SACULS0G4U2P1024X69M4B2W0C1P0D0R1RM3RW00_6i_3101_vwrapper",      1},
                                                                          {"SACULS0G4S2P48X58M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        1},
                                                                          {"SACULS0G4L2P1024X21M4B2W0C0P0D0R1RM3RW00_2i_3101_vwrapper",      1}}}},
        { "pdvoq_core_processor",                     { .chain_lengths = {{"DIAGS",                                                          116},
                                                                          {"RSCR",                                                           259}},
                                                        .vwrappers =     {{"SACULS0G4U2P64X100M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       6},
                                                                          {"SACULS0G4L2P64X144M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       6},
                                                                          {"SACULS0G4L2P256X32M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       6},
                                                                          {"SADRLS0G4L2P256X212M1B4W0C1P0D0RM3SDRW00_1i_3101_vwrapper",      6},
                                                                          {"SACULS0G4U2P64X156M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       6},
                                                                          {"SACULS0G4U2P256X184M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      6}}}},
        { "pdvoq_dual_empd_processor",                { .chain_lengths = {{"DIAGS",                                                          126},
                                                                          {"RSCR",                                                           233}},
                                                        .vwrappers =     {{"SACULS0G4L2P512X4M4B1W1C0P0D0R1RM3RW00_1i_3101_vwrapper",        12},
                                                                          {"SACRLS0G4S1P512X152M2B1W1C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    12},
                                                                          {"SACULS0G4L2P144X72M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SADULS0G4L1P2240X152M4B4W0C1P0D0R1RM3SDRW01_4i_3101_vwrapper",   2},
                                                                          {"SACULS0G4U2P40X92M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        2}}}},
        { "pdvoq_slice_processor",                    { .chain_lengths = {{"DIAGS",                                                          550},
                                                                          {"RSCR",                                                           1397}},
                                                        .vwrappers =     {{"SASULS0G4U2P2048X13M16B1W0C0P0D0R1RM3SDRW00_2i_3101_vwrapper",   3},
                                                                          {"SADULS0G4S1P2048X93M4B2W0C1P0D0R1RM3SDRW01_2i_3101_vwrapper",    1},
                                                                          {"SADULS0G4S1P1024X18M4B1W0C0P0D0R1RM3SDRW01_2i_3101_vwrapper",    1},
                                                                          {"SACULS0G4L2P1024X22M4B2W0C0P0D0R1RM3RW00_4i_3101_vwrapper",      1},
                                                                          {"SACULS0G4U2P1024X39M4B2W0C0P0D0R1RM3RW00_2i_3101_vwrapper",      6},
                                                                          {"SACULS0G4L2P64X72M2B1W0C0P0D0R1RM3RW00_2i_3101_vwrapper",        6},
                                                                          {"SACULS0G4L2P64X72M2B1W0C0P0D0R1RM3RW00_3i_3101_vwrapper",        4},
                                                                          {"SACULS0G4L2P64X72M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        1},
                                                                          {"SADULS0G4S1P2048X64M4B2W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",    1},
                                                                          {"SADULS0G4L1P1024X64M4B1W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    1},
                                                                          {"SADULS0G4L1P4096X20M8B2W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    1},
                                                                          {"SACRLS0G4S1P192X38M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     2},
                                                                          {"SACULS0G4L2P128X40M2B1W0C0P0D0R1RM3RW00_3i_3101_vwrapper",       6},
                                                                          {"SACULS0G4L2P128X40M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       5},
                                                                          {"SACRLS0G4S1P192X30M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SADULS0G4S1P1024X88M4B1W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",    1},
                                                                          {"SACULS0G4L2P1024X29M4B2W0C0P0D0R1RM3RW00_8i_3101_vwrapper",      2},
                                                                          {"SACULS0G4L2P1024X20M4B2W0C0P0D0R1RM3RW00_8i_3101_vwrapper",      4},
                                                                          {"SACULS0G4L2P1024X20M4B2W0C0P0D0R1RM3RW00_4i_3101_vwrapper",      2},
                                                                          {"SACRLS0G4S1P64X72M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",      1},
                                                                          {"SASULS0G4U2P2752X18M16B1W0C1P0D0R1RM3SDRW00_48i_3101_vwrapper",  1},
                                                                          {"SASULS0G4U2P2048X12M16B1W0C0P0D0R1RM3SDRW00_4i_3101_vwrapper",   2},
                                                                          {"SADULS0G4L1P4096X46M8B2W0C1P0D0R1RM3SDRW01_3i_3101_vwrapper",    1},
                                                                          {"SASULS0G4L2P2048X8M16B1W0C0P0D0R1RM3SDRW00_2i_3101_vwrapper",    2},
                                                                          {"SASULS0G4L2P2048X10M16B1W0C0P0D0R1RM3SDRW00_4i_3101_vwrapper",   1}}}},
        { "pier_processor",                           { .chain_lengths = {{"DIAGS",                                                          116},
                                                                          {"RSCR",                                                           212}},
                                                        .vwrappers =     {{"SADRLS0G4S2P128X244M1B2W0C1P0D0RM3SDRW00_2i_3101_vwrapper",      2},
                                                                          {"SACULS0G4L2P512X116M2B2W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      1},
                                                                          {"SASULS0G4U2P1024X75M4B1W0C1P0D0R1RM3SDRW00_6i_3101_vwrapper",    1},
                                                                          {"SACRLS0G4L1P64X246M2B1W0C1P0D0R1RM3SDRW00_2i_3101_vwrapper",     2},
                                                                          {"SASULS0G4U2P864X81M4B1W0C1P0D0R1RM3SDRW00_12i_3101_vwrapper",    1}}}},
        { "reorder_nw_reorder_block_processor",       { .chain_lengths = {{"DIAGS",                                                          109},
                                                                          {"RSCR",                                                           177}},
                                                        .vwrappers =     {{"SASULS0G4L2P2048X8M16B1W0C0P0D0R1RM3SDRW00_2i_3101_vwrapper",    1},
                                                                          {"SACULS0G4L2P1024X24M4B2W0C0P0D0R1RM3RW00_4i_3101_vwrapper",      1},
                                                                          {"SASULS0G4U2P720X120M4B1W0C1P0D0R1RM3SDRW00_6i_3101_vwrapper",    1},
                                                                          {"SACULS0G4L2P48X72M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        2},
                                                                          {"SADULS0G4L1P3072X121M4B4W0C1P0D0R1RM3SDRW01_2i_3101_vwrapper",   1},
                                                                          {"SACRLS0G4S1P512X56M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SACULS0G4L2P512X6M4B1W1C0P0D0R1RM3RW00_1i_3101_vwrapper",        4},
                                                                          {"SACRLS0G4S1P512X234M2B1W1C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    4},
                                                                          {"SACULS0G4U2P64X172M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       1}}}},
        { "reorder_pp_reorder_slice_processor",       { .chain_lengths = {{"DIAGS",                                                          132},
                                                                          {"RSCR",                                                           231}},
                                                        .vwrappers =     {{"SADRLS0G4S2P60X224M1B1W0C1P0D0RM3SDRW00_1i_3101_vwrapper",       4},
                                                                          {"SACULS0G4U2P64X172M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SACULS0G4L2P208X120M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      2},
                                                                          {"SADULS0G4S1P2048X60M4B2W0C1P0D0R1RM3SDRW01_2i_3101_vwrapper",    2},
                                                                          {"SACRLS0G4S1P512X56M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     2},
                                                                          {"SACULS0G4L2P256X4M4B1W1C0P0D0R1RM3RW00_1i_3101_vwrapper",        12},
                                                                          {"SACRLS0G4S1P256X112M2B1W1C0P0D0R1RM3SDRW00_1i_3101_vwrapper",    12},
                                                                          {"SACULS0G4L2P248X58M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2}}}},
        { "reorder_processor",                        { .chain_lengths = {{"DIAGS",                                                          153},
                                                                          {"RSCR",                                                           297}},
                                                        .vwrappers =     {{"SADRLS0G4S2P60X224M1B1W0C1P0D0RM3SDRW00_1i_3101_vwrapper",       12},
                                                                          {"SACULS0G4U2P96X206M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       3},
                                                                          {"SACRLS0G4S1P504X58M2B1W0C0P0D0R1RM3SDRW00_2i_3101_vwrapper",     6},
                                                                          {"SACRLS0G4S1P528X14M4B1W0C0P0D0R1RM3SDRW00_2i_3101_vwrapper",     3},
                                                                          {"SACULS0G4U2P128X170M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      9},
                                                                          {"SACULS0G4L2P64X72M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        2}}}},
        { "resolution_top_processor",                 { .chain_lengths = {{"DIAGS",                                                          823},
                                                                          {"RSCR",                                                           2391}},
                                                        .vwrappers =     {{"SADULS0G4S1P2048X88M4B2W0C1P0D0R1RM3SDRW01_5i_3101_vwrapper",    1},
                                                                          {"SADULS0G4S1P1024X72M4B1W0C1P0D0R1RM3SDRW01_5i_3101_vwrapper",    5},
                                                                          {"SACRLS0G4S1P1024X13M4B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",    8},
                                                                          {"SADULS0G4S1P2048X77M4B2W0C1P0D0R1RM3SDRW01_50i_3101_vwrapper",   1},
                                                                          {"SADULS0G4L1P2048X56M4B2W0C0P0D0R1RM3SDRW01_9i_3101_vwrapper",    12},
                                                                          {"SADULS0G4S1P2048X77M4B2W0C1P0D0R1RM3SDRW01_10i_3101_vwrapper",   2},
                                                                          {"SADULS0G4L1P2048X54M4B2W0C0P0D0R1RM3SDRW01_5i_3101_vwrapper",    8},
                                                                          {"SACRLS0G4S1P512X154M2B1W0C1P0D0R1RM3SDRW00_7i_3101_vwrapper",    1},
                                                                          {"SADULS0G4S1P1024X55M4B1W0C0P0D0R1RM3SDRW01_3i_3101_vwrapper",    6},
                                                                          {"SACULS0G4L2P1024X26M4B2W0C0P0D0R1RM3RW00_4i_3101_vwrapper",      8},
                                                                          {"SADULS0G4S1P8192X15M16B2W0C1P0D0R1RM3SDRW01_4i_3101_vwrapper",   2},
                                                                          {"SADULS0G4S1P8192X15M16B2W0C1P0D0R1RM3SDRW01_2i_3101_vwrapper",   6}}}},
        { "rx_pdr_2_slices_processor",                { .chain_lengths = {{"DIAGS",                                                          128},
                                                                          {"RSCR",                                                           233}},
                                                        .vwrappers =     {{"SACRLS0G4S1P512X120M2B1W0C0P0D0R1RM3SDRW00_5i_3101_vwrapper",    1},
                                                                          {"SACRLS0G4S1P56X116M2B1W0C0P0D0R1RM3SDRW00_3i_3101_vwrapper",     1},
                                                                          {"SACULS0G4U2P72X108M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SACULS0G4U2P56X96M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        2},
                                                                          {"SACULS0G4L2P512X116M2B2W0C1P0D0R1RM3RW00_2i_3101_vwrapper",      1},
                                                                          {"SACULS0G4L2P48X80M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        2},
                                                                          {"SADULS0G4L1P2752X104M4B4W0C1P0D0R1RM3SDRW01_3i_3101_vwrapper",   2},
                                                                          {"SACULS0G4L2P640X57M4B2W0C1P0D0R1RM3RW00_3i_3101_vwrapper",       2},
                                                                          {"SADRLS0G4L2P512X194M2B4W0C1P0D0RM3SDRW00_1i_3101_vwrapper",      2},
                                                                          {"SACULS0G4L2P56X80M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",        2}}}},
        { "rxpp_fi_stage_processor",                  { .chain_lengths = {{"DIAGS",                                                          190},
                                                                          {"RSCR",                                                           448}},
                                                        .vwrappers =     {{"SACRLS0G4S1P64X80M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",      8},
                                                                          {"SACRLS0G4S1P128X62M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     8},
                                                                          {"SADRLS0G4S2P20X180M1B1W1C1P0D0RM3SDRW00_1i_3101_vwrapper",       8},
                                                                          {"SADRLS0G4S2P20X232M1B1W0C1P0D0RM3SDRW00_5i_3101_vwrapper",       8},
                                                                          {"SACRLS0G4S1P64X82M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",      1}}}},
        { "rxpp_fwd_processor",                       { .chain_lengths = {{"DIAGS",                                                          254},
                                                                          {"RSCR",                                                           631}},
                                                        .vwrappers =     {{"SACULS0G4U2P192X138M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      1},
                                                                          {"SASSLS0G4U1P4096X221M4B4W0C1P0D0R1RM3SDRW00_9i_3101_vwrapper",   1},
                                                                          {"SACULS0G4L2P88X120M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SASULS0G4U2P1312X20M8B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",    2},
                                                                          {"SASULS0G4U2P1312X18M8B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",    1},
                                                                          {"SACULS0G4L2P1024X16M4B2W0C0P0D0R1RM3RW00_4i_3101_vwrapper",      3},
                                                                          {"SASULS0G4U2P1312X16M8B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",    1},
                                                                          {"SASULS0G4U2P2176X11M16B1W0C0P0D0R1RM3SDRW00_2i_3101_vwrapper",   2},
                                                                          {"SADULS0G4S1P1024X26M4B1W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    2},
                                                                          {"SACRLS0G4L1P1024X222M2B2W1C1P0D0R1RM3SDRW00_1i_3101_vwrapper",   1},
                                                                          {"SACRLS0G4L1P1024X206M2B2W1C1P0D0R1RM3SDRW00_1i_3101_vwrapper",   1},
                                                                          {"SACRLS0G4S1P256X66M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SADULS0G4L1P1024X114M4B1W1C1P0D0R1RM3SDRW01_3i_3101_vwrapper",   2},
                                                                          {"SACRLS0G4S1P256X134M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    1},
                                                                          {"SACULS0G4L2P1024X15M4B2W0C0P0D0R1RM3RW00_12i_3101_vwrapper",     1},
                                                                          {"SADULS0G4L1P4096X63M4B4W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",    1},
                                                                          {"SASRLS0G4L1P656X282M2B2W0C1P0D0R1RM3SDRW00_11i_3101_vwrapper",   2},
                                                                          {"SACULS0G4U2P448X72M2B2W0C0P0D0R1RM3RW00_3i_3101_vwrapper",       1},
                                                                          {"SACULS0G4L2P960X46M4B2W0C1P0D0R1RM3RW00_2i_3101_vwrapper",       1},
                                                                          {"SACULS0G4L2P448X84M2B2W0C1P0D0R1RM3RW00_3i_3101_vwrapper",       1}}}},
        { "rxpp_term_processor",                      { .chain_lengths = {{"DIAGS",                                                          126},
                                                                          {"RSCR",                                                           218}},
                                                        .vwrappers =     {{"SACULS0G4U2P656X15M4B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SASULS0G4U2P1312X32M8B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    1},
                                                                          {"SACRLS0G4S1P512X170M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    1},
                                                                          {"SACRLS0G4S1P256X170M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    1},
                                                                          {"SACRLS0G4S1P256X166M2B1W0C1P0D0R1RM3SDRW00_2i_3101_vwrapper",    1},
                                                                          {"SADULS0G4L1P1024X120M4B1W0C1P0D0R1RM3SDRW01_2i_3101_vwrapper",   8},
                                                                          {"SADULS0G4L1P4096X39M8B2W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",    1},
                                                                          {"SACRLS0G4S1P512X14M4B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SACULS0G4L2P512X26M4B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACULS0G4L2P448X94M2B2W0C1P0D0R1RM3RW00_3i_3101_vwrapper",       1}}}},
        { "sbif_processor",                           { .chain_lengths = {{"DIAGS",                                                          120},
                                                                          {"RSCR",                                                           229}},
                                                        .vwrappers =     {{"SACULS0G4L2P128X76M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SACULS0G4U2P192X76M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SACULS0G4U2P768X72M4B2W0C1P0D0R1RM3RW00_1i_3101_vwrapper",       1},
                                                                          {"SACRLS0G4S1P256X40M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     32}}}},
        { "sch_processor",                            { .chain_lengths = {{"DIAGS",                                                          219},
                                                                          {"RSCR",                                                           501}},
                                                        .vwrappers =     {{"SACRLS0G4S1P32X194M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SACRLS0G4S1P32X138M2B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SACRLS0G4S1P208X16M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     2},
                                                                          {"SACRLS0G4S1P208X26M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     2},
                                                                          {"SADULS0G4S1P2048X80M4B2W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",    1},
                                                                          {"SADULS0G4S1P4096X18M8B2W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    4},
                                                                          {"SACRLS0G4S1P256X22M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     2},
                                                                          {"SADULS0G4S1P4096X15M8B2W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    2},
                                                                          {"SADULS0G4L1P4096X25M8B2W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    2},
                                                                          {"SADCLS0G4L1P2048X217M4B2W0C1P0D0R1RM3SDRW00_3i_3101_vwrapper",   1},
                                                                          {"SADULS0G4S1P4096X16M8B2W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    1},
                                                                          {"SACULS0G4L2P256X40M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SACRLS0G4L1P2048X118M4B2W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",   1},
                                                                          {"SACRLS0G4S1P256X72M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     1},
                                                                          {"SACRLS0G4S1P32X80M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",      1},
                                                                          {"SACULS0G4U2P1024X40M4B2W0C0P0D0R1RM3RW00_1i_3101_vwrapper",      1},
                                                                          {"SACULS0G4U2P1024X39M4B2W0C0P0D0R1RM3RW00_1i_3101_vwrapper",      1},
                                                                          {"SACULS0G4L2P1024X19M4B2W0C0P0D0R1RM3RW00_32i_3101_vwrapper",     1},
                                                                          {"SADCLS0G4L1P8192X68M8B4W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    1},
                                                                          {"SACULS0G4U2P256X138M2B1W0C1P0D0R1RM3RW00_1i_3101_vwrapper",      1},
                                                                          {"SADCLS0G4L1P16384X15M16B4W0C0P0D0R1RM3SDRW00_2i_3101_vwrapper",  1},
                                                                          {"SADCLS0G4L1P16384X25M16B4W0C1P0D0R1RM3SDRW00_2i_3101_vwrapper",  1},
                                                                          {"SACULS0G4L2P1024X22M4B2W0C0P0D0R1RM3RW00_2i_3101_vwrapper",      1},
                                                                          {"SADCLS0G4S1P16384X21M16B4W0C1P0D0R1RM3SDRW00_2i_3101_vwrapper",  3},
                                                                          {"SADULS0G4S1P2048X22M8B1W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    2}}}},
        { "sms_main_processor",                       { .chain_lengths = {{"DIAGS",                                                          147},
                                                                          {"RSCR",                                                           365}},
                                                        .vwrappers =     {{"SACULS0G4L2P128X72M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       36},
                                                                          {"SASULS0G4U2P1152X42M8B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    14}}}},
        { "sms_quad_bank_flat_processor",             { .chain_lengths = {{"DIAGS",                                                          59},
                                                                          {"RSCR",                                                           31}},
                                                        .vwrappers =     {{"SASSLS0G4U1P8192X148M8B4W0C1P0D0R1RM3SDRW00_3i_3101_vwrapper",   1}}}},
        { "sms_quad_processor",                       { .chain_lengths = {{"DIAGS",                                                          332},
                                                                          {"RSCR",                                                           821}},
                                                        .vwrappers =     {{"SACRLS0G4S1P256X236M2B1W0C1P0D0R1RM3SDRW00_2i_3101_vwrapper",    4},
                                                                          {"SADRLS0G4L2P512X208M2B4W0C1P0D0RM3SDRW00_5i_3101_vwrapper",      4},
                                                                          {"SACULS0G4L2P512X19M4B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       4},
                                                                          {"SASULS0G4U2P1152X28M8B1W0C1P0D0R1RM3SDRW00_1i_3101_vwrapper",    4},
                                                                          {"SACULS0G4L2P1024X20M4B2W0C0P0D0R1RM3RW00_16i_3101_vwrapper",     5},
                                                                          {"SACRLS0G4S1P32X150M2B1W0C1P0D0R1RM3SDRW00_2i_3101_vwrapper",     4}}}},
        { "txpp_processor",                           { .chain_lengths = {{"DIAGS",                                                          166},
                                                                          {"RSCR",                                                           407}},
                                                        .vwrappers =     {{"SADRLS0G4S2P48X252M1B1W0C1P0D0RM3SDRW00_5i_3101_vwrapper",       2},
                                                                          {"SADULS0G4L1P1024X63M4B1W0C0P0D0R1RM3SDRW01_1i_3101_vwrapper",    4},
                                                                          {"SACRLS0G4S1P256X44M2B1W0C0P0D0R1RM3SDRW00_1i_3101_vwrapper",     2},
                                                                          {"SADULS0G4L1P4096X40M8B2W0C1P0D0R1RM3SDRW01_1i_3101_vwrapper",    4},
                                                                          {"SADCLS0G4L1P4096X130M4B4W0C1P0D0R1RM3SDRW00_4i_3101_vwrapper",   1},
                                                                          {"SADRLS0G4S2P768X123M4B4W0C1P0D0RM3SDRW00_13i_3101_vwrapper",     2},
                                                                          {"SACULS0G4U2P208X82M2B1W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       2},
                                                                          {"SACULS0G4L2P416X60M2B2W0C0P0D0R1RM3RW00_1i_3101_vwrapper",       1}}}},
    };
// clang-format on

static size_t
get_num_of_processors(string ring)
{
    string ring_type = ring_dict[ring].type;
    const auto& processors = ring_type_dict[ring_type].processors;
    size_t num_of_processors = 0;
    for (const auto& proc : processors) {
        num_of_processors += proc.num_of_processors;
    }
    return num_of_processors;
}

mbist::mbist(la_device_impl* dev) : m_device(dev), m_cpu2jtag(nullptr)
{
}

mbist::~mbist()
{
}

const la_device*
mbist::get_device() const
{
    return m_device;
}

static inline string
to_string(mbist::bist_type_e type)
{
    const char* strs[] = {
            [(size_t)mbist::bist_type_e::BIST] = "BIST",
            [(size_t)mbist::bist_type_e::BIRA] = "BIRA",
            [(size_t)mbist::bist_type_e::BISR] = "BISR",
            [(size_t)mbist::bist_type_e::BIST_AFTER_REPAIR] = "BIST_AFTER_REPAIR",
    };
    static_assert(array_size(strs) == (size_t)mbist::bist_type_e::LAST, "Bad size");
    return (type < mbist::bist_type_e::LAST ? strs[(size_t)type] : "unknown");
}

static inline string
to_string(const mbist::result::bist_type& errors)
{
    stringstream ss;
    ss << "{ rings: [ ";
    bool first = true;
    for (auto ring : errors.failed_rings) {
        ss << (first ? "" : ", ") << ring;
        first = false;
    }
    ss << " ], num_rings: " << errors.failed_rings.size();
    ss << ", num_processors: " << errors.num_failed_processors << " }";

    return ss.str();
}

la_status
mbist::select_sms(string ring)
{
    auto ring_number = ring_dict[ring].number;
    log_debug(HLD, "%s: ring name=%s, number=%d", __func__, ring.c_str(), ring_number);

    la_status rc = m_cpu2jtag->load_ir_dr_no_tdo((uint64_t)cpu2jtag::jtag_ir_e::SEL_JPC_WIR, 7, 0x42);
    return_on_error(rc);

    rc = m_cpu2jtag->load_ir_dr_no_tdo((uint64_t)cpu2jtag::jtag_ir_e::SEL_JPC_WDR, 9, bit_utils::reverse(ring_number, 9));
    return_on_error(rc);

    return LA_STATUS_SUCCESS;
}

la_status
mbist::shift_same_instruction_to_all_processors(bist_instruction_e instr, uint32_t num_of_processors, uint32_t wait_milliseconds)
{
    bit_vector instructions_to_shift;
    bit_vector instruction = bit_utils::reverse((uint64_t)instr, 6);
    for (size_t processor = 0; processor < num_of_processors; ++processor) {
        instructions_to_shift = instructions_to_shift | (instruction << (6 * processor + 3));
    }

    size_t width_bits = 6 * num_of_processors + 3;
    la_status rc = m_cpu2jtag->load_ir_dr_no_tdo((uint64_t)cpu2jtag::jtag_ir_e::SEL_SMS_WIR, width_bits, instructions_to_shift);
    return_on_error_log(rc, HLD, ERROR, "failed to issue 0x%x", (uint32_t)instr);

    this_thread::sleep_for(chrono::milliseconds(wait_milliseconds));

    return LA_STATUS_SUCCESS;
}

la_status
mbist::check_ring_results(string ring, uint32_t num_of_processors, mbist::bist_type_e type, bool& out_error)
{
    bool error = false;
    const bit_vector instruction = bit_utils::reverse((uint64_t)bist_instruction_e::STATUS_SEL, 6);
    for (int32_t processor = num_of_processors - 1; processor >= 0; --processor) {
        uint32_t instruction_lo_bit = 6 * (num_of_processors - 1 - processor) + 3;
        uint32_t tdo_lo_bit = (num_of_processors - 1 - processor + 3);
        uint32_t tdo_lo_bit_32 = (tdo_lo_bit % 32);
        bit_vector instructions_to_shift = instruction << instruction_lo_bit;
        uint32_t tdo_shift_length = (num_of_processors + 9);
        if ((tdo_lo_bit_32 > 25) || ((tdo_lo_bit >= 32) && (tdo_lo_bit_32 < 3))) {
            instructions_to_shift = instructions_to_shift | (instruction << 3);
            instructions_to_shift = instructions_to_shift | (instruction << 9);
            tdo_shift_length += 12;
            tdo_lo_bit += 12;
        }
        la_status rc = m_cpu2jtag->load_ir_dr_no_tdo(
            (uint64_t)cpu2jtag::jtag_ir_e::SEL_SMS_WIR, 6 * num_of_processors + 3, instructions_to_shift);
        return_on_error_log(rc, HLD, ERROR, "failed to issue SEL_SMS_WIR, type=%s", to_string(type).c_str());

        bit_vector tdo;
        rc = m_cpu2jtag->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::SEL_SMS_WDR, tdo_shift_length, 0, tdo);
        return_on_error_log(rc, HLD, ERROR, "failed to issue SEL_SMS_WDR, type=%s", to_string(type).c_str());

        bit_vector processor_tdo = tdo.bits(tdo_lo_bit + 6, tdo_lo_bit);
        error |= check_processor_result(ring, processor, processor_tdo, type);
    }

    out_error = error;
    if (error) {
        m_result.bist_types[(size_t)type].failed_rings.push_back(ring);
    }

    return LA_STATUS_SUCCESS;
}

bool
mbist::check_processor_result(string ring, uint32_t processor, bit_vector processor_tdo, bist_type_e type)
{
    uint32_t processor_tdo_mask = (type == bist_type_e::BIRA ? 0xe : 0x4e);
    uint32_t expected_processor_tdo = 0xa;
    bool error = ((processor_tdo.get_value() & processor_tdo_mask) != expected_processor_tdo);
    if (error) {
        bool ready_sms = processor_tdo.bit(1);
        bool exec_flag = processor_tdo.bit(3);
        log_err(HLD,
                "MBIST: ring=%s, processor=%d FAILED: type=%s, tdo=0x%lx, expected=0x%x, mask=0x%x, ready_sms=%d, exec_flag=%d",
                ring.c_str(),
                processor,
                to_string(type).c_str(),
                processor_tdo.get_value(),
                expected_processor_tdo,
                processor_tdo_mask,
                ready_sms,
                exec_flag);
        m_result.bist_types[(size_t)type].num_failed_processors++;
    }

    return error;
}

la_status
mbist::run_ring_mbist(string ring, bool repair)
{
    log_debug(HLD, "running the MBIST sequence on %s, repair=%d", ring.c_str(), repair);
    la_status rc = select_sms(ring);
    return_on_error_log(rc, HLD, ERROR, "failed to select_sms");

    size_t num_of_processors = get_num_of_processors(ring);
    log_debug(HLD, "running BIST, num_of_processors=%ld", num_of_processors);

    rc = shift_same_instruction_to_all_processors(bist_instruction_e::BIST_RUN, num_of_processors, 30);
    return_on_error(rc);

    bool error;
    rc = check_ring_results(ring, num_of_processors, bist_type_e::BIST, error);
    return_on_error(rc);

    if (!error) {
        log_debug(HLD, "%s: ring=%s, MBIST passed", __func__, ring.c_str());
    } else if (!repair) {
        log_err(HLD, "%s: ring=%s, MBIST failed, repair=%d", __func__, ring.c_str(), repair);
    } else {
        log_debug(HLD, "%s: ring=%s, running BIRA", __func__, ring.c_str());
        rc = shift_same_instruction_to_all_processors(bist_instruction_e::BIRA_RUN, num_of_processors, 100);
        return_on_error(rc);

        rc = check_ring_results(ring, num_of_processors, bist_type_e::BIRA, error);
        return_on_error(rc);
        if (error) {
            log_err(HLD, "%s: ring=%s, BIRA failed", __func__, ring.c_str());
            rc = shift_same_instruction_to_all_processors(bist_instruction_e::INBR_RST, num_of_processors, 100);
            return_on_error(rc);
        } else {
            log_debug(HLD, "%s: ring=%s, running BISR", __func__, ring.c_str());
            rc = shift_same_instruction_to_all_processors(bist_instruction_e::BISR_RUN, num_of_processors, 1);
            return_on_error(rc);

            rc = check_ring_results(ring, num_of_processors, bist_type_e::BISR, error);
            return_on_error(rc);
            if (error) {
                log_err(HLD, "%s: ring=%s, BISR failed", __func__, ring.c_str());
            } else {
                log_debug(HLD, "%s: ring=%s, running BIST", __func__, ring.c_str());
                rc = shift_same_instruction_to_all_processors(bist_instruction_e::BIST_RUN, num_of_processors, 30);
                return_on_error(rc);

                rc = check_ring_results(ring, num_of_processors, bist_type_e::BIST_AFTER_REPAIR, error);
                return_on_error(rc);
                if (error) {
                    log_err(HLD, "%s: ring=%s, MBIST failed after repair", __func__, ring.c_str());
                } else {
                    log_info(HLD, "%s: ring=%s, MBIST passed after repair", __func__, ring.c_str());
                }
            }
        }
    }

    rc = shift_same_instruction_to_all_processors(bist_instruction_e::BYPASS, num_of_processors, 0);
    return_on_error(rc);

    return LA_STATUS_SUCCESS;
}

void
mbist::clear_result()
{
    for (size_t i = 0; i < (size_t)bist_type_e::LAST; ++i) {
        m_result.bist_types[i].num_failed_processors = 0;
        m_result.bist_types[i].failed_rings.clear();
    }
}

la_status
mbist::run(bool repair, result& out_mbist_result)
{
    log_debug(HLD, "%s: %s, repair=%d", __func__, MBIST_VERSION, repair);

    if (!m_cpu2jtag) {
        la_status rc = m_device->get_cpu2jtag_handler(m_cpu2jtag);
        return_on_error_log(rc, HLD, ERROR, "failed getting cpu2jtag handler");
    }

    clear_result();

    int matilda_model;
    m_device->get_int_property(la_device_property_e::MATILDA_MODEL_TYPE, matilda_model);

    set<string> exclude_rings{};
    if (matilda_model == matilda_model_e::MATILDA_32A) {
        exclude_rings = matilda_32A_disabled_rings;
    } else if (matilda_model == matilda_model_e::MATILDA_32B) {
        exclude_rings = matilda_32B_disabled_rings;
    } else if (matilda_model == matilda_model_e::MATILDA_8T_A) {
        exclude_rings = matilda_8T_A_disabled_rings;
    } else if (matilda_model == matilda_model_e::MATILDA_8T_B) {
        exclude_rings = matilda_8T_B_disabled_rings;
    }

    // This is a sanity test, to check that the names of the excluded rings are found in the ring_dict,
    // i.e. it validates nobady changed the ring_dict and forgot to update the exclude_rings
    set<string> ring_names;
    for (auto ring : ring_dict) {
        ring_names.insert(ring.first);
    }
    for (auto excluded_name : exclude_rings) {
        dassert_crit(
            contains(ring_names, excluded_name),
            "Excluded test seems to be missing from the ring_dict. Probably sombody changed the test name. Matilda type=%d",
            matilda_model)
    }

    // Now we run the actuall MBIST tests
    exclude_rings.insert("dmc_css");

    for (auto ring : ring_dict) {
        if (contains(exclude_rings, ring.first)) {
            continue;
        }

        la_status rc = run_ring_mbist(ring.first, repair);
        return_on_error(rc);
    }

    out_mbist_result = m_result;

    // Repair:    Ignore errors of the discovery stage (the initial BIST).
    //            Check errors of all other stages (BIRA - analysis, BISR - repair, BIST - test after repair)
    // No-repair: Check the initial BIST, ignore the rest.
    bist_type_e type_first = (repair ? bist_type_e::BIRA : bist_type_e::BIST);
    bist_type_e type_last = (repair ? bist_type_e::BIST_AFTER_REPAIR : bist_type_e::BIST);

    bool ok = true;
    for (bist_type_e type = type_first; type <= type_last; type = (bist_type_e)((size_t)type + 1)) {
        const auto& errors = m_result.bist_types[(size_t)type];
        if (errors.failed_rings.size()) {
            log_err(HLD,
                    "%s: FAILED, repair=%d, type=%s, errors=%s",
                    __func__,
                    repair,
                    to_string(type).c_str(),
                    to_string(errors).c_str());
            ok = false;
        } else {
            log_info(HLD, "%s: PASSED, repair=%d, type=%s", __func__, repair, to_string(type).c_str());
        }
    }

    return (ok ? LA_STATUS_SUCCESS : LA_STATUS_EUNKNOWN);
}
} // namespace silicon_one
