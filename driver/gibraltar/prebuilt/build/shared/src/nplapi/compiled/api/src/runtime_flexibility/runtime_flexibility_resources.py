def get_compiler_udk_resources(cli_object, context):
    result = cli_object.udk_resources_map()
    resources = cli_object.udk_resources()



    if context == 'network':
        resources = cli_object.udk_resources()
        resources.macro_id = 6
        resources.tables_properties[0] = cli_object.udk_table_properties()
        resources.tables_properties[0].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[0].table_calculated_fields[1] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[0].table_calculated_fields[2] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[0].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[0].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[0].m_constant_bits_per_key_part.push_back(4)
        resources.tables_properties[0].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[0].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[0].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(0))
        resources.tables_properties[0].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 16
        resources.tables_properties[0].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 15
        resources.tables_properties[0].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.tables_properties[0].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(1))
        resources.tables_properties[0].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 16
        resources.tables_properties[0].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 15
        resources.tables_properties[0].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.tables_properties[1] = cli_object.udk_table_properties()
        resources.tables_properties[1].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[1].table_calculated_fields[1] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[1].table_calculated_fields[2] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[1].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[1].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[1].m_constant_bits_per_key_part.push_back(4)
        resources.tables_properties[1].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[1].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[1].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(2))
        resources.tables_properties[1].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 16
        resources.tables_properties[1].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 15
        resources.tables_properties[1].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.tables_properties[1].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(3))
        resources.tables_properties[1].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 16
        resources.tables_properties[1].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 15
        resources.tables_properties[1].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.scoper_macro_table_pointer.block_name = "rxpp_fwd.npe"
        resources.scoper_macro_table_pointer.table_name = "scoper_macro"
        resources.scoper_macro_table_pointer.table_lines.push_back(cli_object.table_line_info_t(6))
        resources.lookup_keys_construction_macro_table_pointer.block_name = "rxpp_fwd.npe"
        resources.lookup_keys_construction_macro_table_pointer.table_name = "lookup_keys_construction_macro"
        resources.lookup_keys_construction_macro_table_pointer.table_lines.push_back(cli_object.table_line_info_t(6))
        resources.field_selects.push_back(cli_object.field_select_info(3, 16, 38, 4, 23))
        resources.field_selects.push_back(cli_object.field_select_info(4, 32, 49, 7, 24))
        resources.field_selects.push_back(cli_object.field_select_info(8, 16, 101, 5, 22))
        resources.field_selects.push_back(cli_object.field_select_info(9, 128, 113, 7, 26))
        resources.field_selects.push_back(cli_object.field_select_info(12, 16, 152, 6, 21))
        resources.field_selects.push_back(cli_object.field_select_info(17, 8, 217, 5, 20))
        resources.field_select_index_width_in_bits = 5
        resources.field_select_not_used_value = 31
        resources.offset_of_field_selects_in_key_construction_microcode_line = 0
        resources.first_lsb_channel_with_no_pd_support = 10
        resources.first_bypass_channel_with_pd_support = 33

        result[198] = resources
        resources = cli_object.udk_resources()
        resources.macro_id = 12
        resources.tables_properties[2] = cli_object.udk_table_properties()
        resources.tables_properties[2].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[2].table_calculated_fields[1] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[2].table_calculated_fields[2] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[2].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[2].table_calculated_fields[4] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[2].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[2].table_calculated_fields[6] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[2].table_calculated_fields[7] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[2].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[2].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[2].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[2].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[2].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[2].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(10))
        resources.tables_properties[2].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[2].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[2].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[2].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[2].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[2].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[2].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.tables_properties[2].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.tables_properties[3] = cli_object.udk_table_properties()
        resources.tables_properties[3].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[3].table_calculated_fields[1] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[3].table_calculated_fields[2] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[3].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[3].table_calculated_fields[4] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[3].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[3].table_calculated_fields[6] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[3].table_calculated_fields[7] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[3].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[3].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[3].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[3].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[3].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[3].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(14))
        resources.tables_properties[3].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[3].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[3].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[3].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[3].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[3].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[3].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.tables_properties[3].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.tables_properties[4] = cli_object.udk_table_properties()
        resources.tables_properties[4].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[4].table_calculated_fields[1] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[4].table_calculated_fields[2] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[4].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[4].table_calculated_fields[4] = cli_object.calculated_field_info_t(2, 1)
        resources.tables_properties[4].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[4].table_calculated_fields[6] = cli_object.calculated_field_info_t(1, 1)
        resources.tables_properties[4].table_calculated_fields[7] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[4].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[4].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[4].m_constant_bits_per_key_part.push_back(1)
        resources.tables_properties[4].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[4].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[4].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[4].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(14))
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.tables_properties[4].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(10))
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[4].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.tables_properties[5] = cli_object.udk_table_properties()
        resources.tables_properties[5].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[5].table_calculated_fields[1] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[5].table_calculated_fields[2] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[5].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[5].table_calculated_fields[4] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[5].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[5].table_calculated_fields[6] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[5].table_calculated_fields[7] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[5].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[5].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[5].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[5].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[5].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[5].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(11))
        resources.tables_properties[5].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[5].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[5].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[5].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[5].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[5].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[5].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.tables_properties[5].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.tables_properties[6] = cli_object.udk_table_properties()
        resources.tables_properties[6].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[6].table_calculated_fields[1] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[6].table_calculated_fields[2] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[6].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[6].table_calculated_fields[4] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[6].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[6].table_calculated_fields[6] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[6].table_calculated_fields[7] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[6].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[6].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[6].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[6].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[6].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[6].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(15))
        resources.tables_properties[6].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[6].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[6].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[6].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[6].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[6].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[6].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.tables_properties[6].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.tables_properties[7] = cli_object.udk_table_properties()
        resources.tables_properties[7].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[7].table_calculated_fields[1] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[7].table_calculated_fields[2] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[7].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[7].table_calculated_fields[4] = cli_object.calculated_field_info_t(2, 1)
        resources.tables_properties[7].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[7].table_calculated_fields[6] = cli_object.calculated_field_info_t(1, 1)
        resources.tables_properties[7].table_calculated_fields[7] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[7].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[7].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[7].m_constant_bits_per_key_part.push_back(1)
        resources.tables_properties[7].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[7].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[7].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[7].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(15))
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.tables_properties[7].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(11))
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[7].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.tables_properties[8] = cli_object.udk_table_properties()
        resources.tables_properties[8].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[8].table_calculated_fields[1] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[8].table_calculated_fields[2] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[8].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[8].table_calculated_fields[4] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[8].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[8].table_calculated_fields[6] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[8].table_calculated_fields[7] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[8].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[8].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[8].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[8].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[8].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[8].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(12))
        resources.tables_properties[8].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[8].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[8].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[8].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[8].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[8].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[8].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.tables_properties[8].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.tables_properties[9] = cli_object.udk_table_properties()
        resources.tables_properties[9].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[9].table_calculated_fields[1] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[9].table_calculated_fields[2] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[9].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[9].table_calculated_fields[4] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[9].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[9].table_calculated_fields[6] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[9].table_calculated_fields[7] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[9].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[9].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[9].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[9].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[9].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[9].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(16))
        resources.tables_properties[9].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[9].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[9].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[9].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[9].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[9].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[9].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.tables_properties[9].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.tables_properties[10] = cli_object.udk_table_properties()
        resources.tables_properties[10].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[10].table_calculated_fields[1] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[10].table_calculated_fields[2] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[10].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[10].table_calculated_fields[4] = cli_object.calculated_field_info_t(2, 1)
        resources.tables_properties[10].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[10].table_calculated_fields[6] = cli_object.calculated_field_info_t(1, 1)
        resources.tables_properties[10].table_calculated_fields[7] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[10].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[10].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[10].m_constant_bits_per_key_part.push_back(1)
        resources.tables_properties[10].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[10].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[10].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[10].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(16))
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.tables_properties[10].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(12))
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[10].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.tables_properties[11] = cli_object.udk_table_properties()
        resources.tables_properties[11].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[11].table_calculated_fields[1] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[11].table_calculated_fields[2] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[11].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[11].table_calculated_fields[4] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[11].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[11].table_calculated_fields[6] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[11].table_calculated_fields[7] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[11].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[11].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[11].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[11].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[11].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[11].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(13))
        resources.tables_properties[11].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[11].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[11].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[11].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[11].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[11].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[11].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.tables_properties[11].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.tables_properties[12] = cli_object.udk_table_properties()
        resources.tables_properties[12].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[12].table_calculated_fields[1] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[12].table_calculated_fields[2] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[12].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[12].table_calculated_fields[4] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[12].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[12].table_calculated_fields[6] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[12].table_calculated_fields[7] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[12].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[12].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[12].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[12].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[12].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[12].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(17))
        resources.tables_properties[12].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[12].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[12].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[12].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[12].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[12].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[12].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.tables_properties[12].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.tables_properties[13] = cli_object.udk_table_properties()
        resources.tables_properties[13].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[13].table_calculated_fields[1] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[13].table_calculated_fields[2] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[13].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[13].table_calculated_fields[4] = cli_object.calculated_field_info_t(2, 1)
        resources.tables_properties[13].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[13].table_calculated_fields[6] = cli_object.calculated_field_info_t(1, 1)
        resources.tables_properties[13].table_calculated_fields[7] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[13].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[13].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[13].m_constant_bits_per_key_part.push_back(1)
        resources.tables_properties[13].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[13].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[13].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[13].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(17))
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[2] = 18
        resources.tables_properties[13].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(13))
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 2
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 14
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[4] = 5
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 13
        resources.tables_properties[13].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 15
        resources.scoper_macro_table_pointer.block_name = "rxpp_fwd.npe"
        resources.scoper_macro_table_pointer.table_name = "scoper_macro"
        resources.scoper_macro_table_pointer.table_lines.push_back(cli_object.table_line_info_t(12))
        resources.lookup_keys_construction_macro_table_pointer.block_name = "rxpp_fwd.npe"
        resources.lookup_keys_construction_macro_table_pointer.table_name = "lookup_keys_construction_macro"
        resources.lookup_keys_construction_macro_table_pointer.table_lines.push_back(cli_object.table_line_info_t(12))
        resources.field_selects.push_back(cli_object.field_select_info(3, 16, 38, 4, 7))
        resources.field_selects.push_back(cli_object.field_select_info(4, 128, 49, 7, 27))
        resources.field_selects.push_back(cli_object.field_select_info(6, 8, 76, 4, 17))
        resources.field_selects.push_back(cli_object.field_select_info(7, 16, 88, 5, 10))
        resources.field_selects.push_back(cli_object.field_select_info(8, 16, 101, 5, 18))
        resources.field_selects.push_back(cli_object.field_select_info(9, 128, 113, 7, 19))
        resources.field_selects.push_back(cli_object.field_select_info(10, 8, 127, 4, 16))
        resources.field_selects.push_back(cli_object.field_select_info(11, 16, 139, 5, 9))
        resources.field_selects.push_back(cli_object.field_select_info(16, 16, 204, 5, 8))
        resources.field_selects.push_back(cli_object.field_select_info(17, 32, 217, 5, 11))
        resources.field_select_index_width_in_bits = 5
        resources.field_select_not_used_value = 31
        resources.offset_of_field_selects_in_key_construction_microcode_line = 0
        resources.first_lsb_channel_with_no_pd_support = 10
        resources.first_bypass_channel_with_pd_support = 33

        result[204] = resources
        resources = cli_object.udk_resources()
        resources.macro_id = 13
        resources.tables_properties[14] = cli_object.udk_table_properties()
        resources.tables_properties[14].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[14].table_calculated_fields[1] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[14].table_calculated_fields[2] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[14].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[14].table_calculated_fields[4] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[14].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[14].table_calculated_fields[6] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[14].table_calculated_fields[7] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[14].table_calculated_fields[8] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[14].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[14].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[14].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[14].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[14].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[14].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(18))
        resources.tables_properties[14].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[14].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[14].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[14].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[14].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[14].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[14].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[14].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.tables_properties[14].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[4] = 18
        resources.tables_properties[15] = cli_object.udk_table_properties()
        resources.tables_properties[15].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[15].table_calculated_fields[1] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[15].table_calculated_fields[2] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[15].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[15].table_calculated_fields[4] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[15].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[15].table_calculated_fields[6] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[15].table_calculated_fields[7] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[15].table_calculated_fields[8] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[15].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[15].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[15].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[15].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[15].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[15].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(22))
        resources.tables_properties[15].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[15].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[15].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[15].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[15].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[15].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[15].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[15].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.tables_properties[15].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[4] = 18
        resources.tables_properties[16] = cli_object.udk_table_properties()
        resources.tables_properties[16].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[16].table_calculated_fields[1] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[16].table_calculated_fields[2] = cli_object.calculated_field_info_t(7, 1)
        resources.tables_properties[16].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 1)
        resources.tables_properties[16].table_calculated_fields[4] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[16].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[16].table_calculated_fields[6] = cli_object.calculated_field_info_t(2, 1)
        resources.tables_properties[16].table_calculated_fields[7] = cli_object.calculated_field_info_t(1, 1)
        resources.tables_properties[16].table_calculated_fields[8] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[16].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[16].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[16].m_constant_bits_per_key_part.push_back(1)
        resources.tables_properties[16].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[16].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[16].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[16].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(22))
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[4] = 18
        resources.tables_properties[16].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(18))
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[16].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.tables_properties[17] = cli_object.udk_table_properties()
        resources.tables_properties[17].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[17].table_calculated_fields[1] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[17].table_calculated_fields[2] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[17].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[17].table_calculated_fields[4] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[17].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[17].table_calculated_fields[6] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[17].table_calculated_fields[7] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[17].table_calculated_fields[8] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[17].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[17].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[17].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[17].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[17].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[17].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(19))
        resources.tables_properties[17].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[17].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[17].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[17].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[17].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[17].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[17].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[17].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.tables_properties[17].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[4] = 18
        resources.tables_properties[18] = cli_object.udk_table_properties()
        resources.tables_properties[18].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[18].table_calculated_fields[1] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[18].table_calculated_fields[2] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[18].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[18].table_calculated_fields[4] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[18].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[18].table_calculated_fields[6] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[18].table_calculated_fields[7] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[18].table_calculated_fields[8] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[18].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[18].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[18].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[18].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[18].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[18].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(23))
        resources.tables_properties[18].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[18].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[18].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[18].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[18].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[18].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[18].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[18].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.tables_properties[18].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[4] = 18
        resources.tables_properties[19] = cli_object.udk_table_properties()
        resources.tables_properties[19].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[19].table_calculated_fields[1] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[19].table_calculated_fields[2] = cli_object.calculated_field_info_t(7, 1)
        resources.tables_properties[19].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 1)
        resources.tables_properties[19].table_calculated_fields[4] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[19].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[19].table_calculated_fields[6] = cli_object.calculated_field_info_t(2, 1)
        resources.tables_properties[19].table_calculated_fields[7] = cli_object.calculated_field_info_t(1, 1)
        resources.tables_properties[19].table_calculated_fields[8] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[19].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[19].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[19].m_constant_bits_per_key_part.push_back(1)
        resources.tables_properties[19].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[19].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[19].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[19].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(23))
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[4] = 18
        resources.tables_properties[19].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(19))
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[19].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.tables_properties[20] = cli_object.udk_table_properties()
        resources.tables_properties[20].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[20].table_calculated_fields[1] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[20].table_calculated_fields[2] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[20].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[20].table_calculated_fields[4] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[20].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[20].table_calculated_fields[6] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[20].table_calculated_fields[7] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[20].table_calculated_fields[8] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[20].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[20].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[20].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[20].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[20].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[20].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(20))
        resources.tables_properties[20].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[20].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[20].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[20].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[20].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[20].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[20].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[20].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.tables_properties[20].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[4] = 18
        resources.tables_properties[21] = cli_object.udk_table_properties()
        resources.tables_properties[21].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[21].table_calculated_fields[1] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[21].table_calculated_fields[2] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[21].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[21].table_calculated_fields[4] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[21].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[21].table_calculated_fields[6] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[21].table_calculated_fields[7] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[21].table_calculated_fields[8] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[21].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[21].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[21].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[21].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[21].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[21].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(24))
        resources.tables_properties[21].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[21].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[21].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[21].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[21].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[21].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[21].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[21].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.tables_properties[21].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[4] = 18
        resources.tables_properties[22] = cli_object.udk_table_properties()
        resources.tables_properties[22].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[22].table_calculated_fields[1] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[22].table_calculated_fields[2] = cli_object.calculated_field_info_t(7, 1)
        resources.tables_properties[22].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 1)
        resources.tables_properties[22].table_calculated_fields[4] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[22].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[22].table_calculated_fields[6] = cli_object.calculated_field_info_t(2, 1)
        resources.tables_properties[22].table_calculated_fields[7] = cli_object.calculated_field_info_t(1, 1)
        resources.tables_properties[22].table_calculated_fields[8] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[22].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[22].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[22].m_constant_bits_per_key_part.push_back(1)
        resources.tables_properties[22].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[22].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[22].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[22].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(24))
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[4] = 18
        resources.tables_properties[22].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(20))
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[22].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.tables_properties[23] = cli_object.udk_table_properties()
        resources.tables_properties[23].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[23].table_calculated_fields[1] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[23].table_calculated_fields[2] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[23].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[23].table_calculated_fields[4] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[23].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[23].table_calculated_fields[6] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[23].table_calculated_fields[7] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[23].table_calculated_fields[8] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[23].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[23].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[23].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[23].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[23].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[23].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(21))
        resources.tables_properties[23].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[23].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[23].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[23].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[23].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[23].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[23].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[23].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.tables_properties[23].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[4] = 18
        resources.tables_properties[24] = cli_object.udk_table_properties()
        resources.tables_properties[24].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[24].table_calculated_fields[1] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[24].table_calculated_fields[2] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[24].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 0)
        resources.tables_properties[24].table_calculated_fields[4] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[24].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[24].table_calculated_fields[6] = cli_object.calculated_field_info_t(2, 0)
        resources.tables_properties[24].table_calculated_fields[7] = cli_object.calculated_field_info_t(1, 0)
        resources.tables_properties[24].table_calculated_fields[8] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[24].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[24].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[24].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[24].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[24].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[24].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(25))
        resources.tables_properties[24].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[24].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[24].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[24].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[24].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[24].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[24].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[24].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.tables_properties[24].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[4] = 18
        resources.tables_properties[25] = cli_object.udk_table_properties()
        resources.tables_properties[25].table_calculated_fields[0] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[25].table_calculated_fields[1] = cli_object.calculated_field_info_t(8, 0)
        resources.tables_properties[25].table_calculated_fields[2] = cli_object.calculated_field_info_t(7, 1)
        resources.tables_properties[25].table_calculated_fields[3] = cli_object.calculated_field_info_t(16, 1)
        resources.tables_properties[25].table_calculated_fields[4] = cli_object.calculated_field_info_t(12, 0)
        resources.tables_properties[25].table_calculated_fields[5] = cli_object.calculated_field_info_t(48, 0)
        resources.tables_properties[25].table_calculated_fields[6] = cli_object.calculated_field_info_t(2, 1)
        resources.tables_properties[25].table_calculated_fields[7] = cli_object.calculated_field_info_t(1, 1)
        resources.tables_properties[25].table_calculated_fields[8] = cli_object.calculated_field_info_t(7, 0)
        resources.tables_properties[25].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[25].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[25].m_constant_bits_per_key_part.push_back(1)
        resources.tables_properties[25].max_number_of_field_selects_for_each_key_part.push_back(9)
        resources.tables_properties[25].m_key_sizes_per_key_part.push_back(160)
        resources.tables_properties[25].m_constant_bits_per_key_part.push_back(5)
        resources.tables_properties[25].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().array_index = 0
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(25))
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index_per_row[4] = 18
        resources.tables_properties[25].lookup_keys_construction_table_pointers.push_back(cli_object.microcode_pointers("rxpp_fwd.npe", "lookup_keys_construction_low_buckets"))
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().array_index = 1
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.push_back(cli_object.table_line_info_t(21))
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[0] = 6
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[1] = 10
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[2] = 14
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[3] = 0
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[5] = 12
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[6] = 2
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[7] = 13
        resources.tables_properties[25].lookup_keys_construction_table_pointers.back().table_lines.back().calculated_field_id_to_fs_index[8] = 15
        resources.scoper_macro_table_pointer.block_name = "rxpp_fwd.npe"
        resources.scoper_macro_table_pointer.table_name = "scoper_macro"
        resources.scoper_macro_table_pointer.table_lines.push_back(cli_object.table_line_info_t(13))
        resources.lookup_keys_construction_macro_table_pointer.block_name = "rxpp_fwd.npe"
        resources.lookup_keys_construction_macro_table_pointer.table_name = "lookup_keys_construction_macro"
        resources.lookup_keys_construction_macro_table_pointer.table_lines.push_back(cli_object.table_line_info_t(13))
        resources.field_selects.push_back(cli_object.field_select_info(3, 16, 38, 4, 17))
        resources.field_selects.push_back(cli_object.field_select_info(4, 128, 49, 7, 26))
        resources.field_selects.push_back(cli_object.field_select_info(7, 16, 88, 5, 11))
        resources.field_selects.push_back(cli_object.field_select_info(8, 16, 101, 5, 16))
        resources.field_selects.push_back(cli_object.field_select_info(9, 128, 113, 7, 18))
        resources.field_selects.push_back(cli_object.field_select_info(11, 16, 139, 5, 10))
        resources.field_selects.push_back(cli_object.field_select_info(16, 16, 204, 5, 9))
        resources.field_selects.push_back(cli_object.field_select_info(17, 32, 217, 5, 12))
        resources.field_select_index_width_in_bits = 5
        resources.field_select_not_used_value = 31
        resources.offset_of_field_selects_in_key_construction_microcode_line = 0
        resources.first_lsb_channel_with_no_pd_support = 10
        resources.first_bypass_channel_with_pd_support = 33

        result[205] = resources

    return result


