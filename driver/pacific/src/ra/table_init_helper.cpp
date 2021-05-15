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

#include "table_init_helper.h"
#include "common/defines.h"
#include "hw_tables/memory_sram.h"

namespace silicon_one
{

namespace ra
{

la_status
table_init_helper<npl_ifgb_tc_lut_table_t, TABLE_TYPE_DIRECT>::init_table(npl_ifgb_tc_lut_table_t& table,
                                                                          ra_translator_creator& creator,
                                                                          const std::vector<size_t>& indices)
{
    auto ldevice = creator.get_ll_device();
    auto pt = ldevice->get_pacific_tree();
    const size_t NUM_MEMORIES_PER_IFG = pt->slice[0]->ifg[0]->ifgb->tc_lut_mem->size();
    const size_t NUM_INVALID_SECTIONS = (1 << SERDES_PAIR_KEY_PART_WIDTH) - NUM_MEMORIES_PER_IFG;

    npl_ifgb_tc_lut_table_t::table_translator_sptr_vec_t translator_vec;

    for (size_t slice_id : indices) {
        std::vector<sram_section> sections;
        for (size_t ifg_id = 0; ifg_id < engine_block_mapper::NUM_IFGS_PER_SLICE; ifg_id++) {
            // Add valid sections
            for (size_t mem_idx = 0; mem_idx < NUM_MEMORIES_PER_IFG; mem_idx++) {
                // Create the physical sram
                physical_sram sram = {.start_line = 0,
                                      .offset = 0,
                                      .width = PHYSICAL_TABLE_PAYLOAD_WIDTH,
                                      .memories = {(*pt->slice[slice_id]->ifg[ifg_id]->ifgb->tc_lut_mem)[mem_idx]}};

                // create a section for the physical sram
                sram_section section{
                    .size = (1 << PHYSICAL_TABLE_KEY_WIDTH), .entries_per_line = 1, .srams = {sram}, .is_valid = true};

                sections.push_back(section);
            }
            // Add invalid sections
            for (size_t i = 0; i < NUM_INVALID_SECTIONS; i++) {
                sram_section section{
                    .size = (1 << PHYSICAL_TABLE_KEY_WIDTH), .entries_per_line = 0, .srams = {}, .is_valid = false};
                sections.push_back(section);
            }
        }

        std::unique_ptr<logical_sram> lsram
            = silicon_one::make_unique<memory_sram>(ldevice, PHYSICAL_TABLE_PAYLOAD_WIDTH, sections);
        npl_ifgb_tc_lut_table_t::table_translator_sptr_t tr
            = std::make_shared<ra_direct_translator<npl_ifgb_tc_lut_table_functional_traits_t> >(
                creator.get_ll_device(), NPL_NONE_CONTEXT, 0 /*replication_idx*/, std::move(lsram));
        translator_vec.push_back(tr);
    }

    dassert_crit(translator_vec.size());
    table.initialize(translator_vec);
    return LA_STATUS_SUCCESS;
}

la_status
table_init_helper<npl_rx_meter_rate_limiter_shaper_configuration_table_t, TABLE_TYPE_DIRECT>::init_table(
    npl_rx_meter_rate_limiter_shaper_configuration_table_t& table,
    ra_translator_creator& creator,
    const std::vector<size_t>& indices)
{
    // indices corresponds to num slices. Since this is a per device table, indices is not used.
    auto ldevice = creator.get_ll_device();
    auto pt = ldevice->get_pacific_tree();
    const size_t NUM_TABLES_PER_DEVICE = pt->rx_meter->top->rate_limiter_shaper_configuration_table->size();
    const size_t NUM_TABLE_ENTRIES = (*pt->rx_meter->top->rate_limiter_shaper_configuration_table)[0]->get_desc()->entries;
    const size_t NUM_INVALID_TABLE_ENTRIES = (1 << PORT_PACKET_INDEX_KEY_PART_WIDTH) - NUM_TABLE_ENTRIES;

    npl_rx_meter_rate_limiter_shaper_configuration_table_t::table_translator_sptr_vec_t translator_vec;

    std::vector<sram_section> sections;
    for (size_t table_idx = 0; table_idx < NUM_TABLES_PER_DEVICE; table_idx++) {
        // Add valid sections
        // Create the physical sram
        physical_sram sram = {.start_line = 0,
                              .offset = 0,
                              .width = PHYSICAL_TABLE_PAYLOAD_WIDTH,
                              .memories = {(*pt->rx_meter->top->rate_limiter_shaper_configuration_table)[table_idx]}};

        // create a section for the physical sram
        sram_section section{.size = (NUM_TABLE_ENTRIES), .entries_per_line = 1, .srams = {sram}, .is_valid = true};

        sections.push_back(section);
        // Add invalid sections
        sram_section invalid_section{.size = (NUM_INVALID_TABLE_ENTRIES), .entries_per_line = 0, .srams = {}, .is_valid = false};
        sections.push_back(invalid_section);
    }

    std::unique_ptr<logical_sram> lsram = silicon_one::make_unique<memory_sram>(ldevice, PHYSICAL_TABLE_PAYLOAD_WIDTH, sections);
    npl_rx_meter_rate_limiter_shaper_configuration_table_t::table_translator_sptr_t tr
        = std::make_shared<ra_direct_translator<npl_rx_meter_rate_limiter_shaper_configuration_table_functional_traits_t> >(
            creator.get_ll_device(), NPL_NONE_CONTEXT, 0 /*replication_idx*/, std::move(lsram));
    translator_vec.push_back(tr);

    dassert_crit(translator_vec.size());
    table.initialize(translator_vec);
    return LA_STATUS_SUCCESS;
}
}; // namespace ra

} // namespace silicon_one
