
# This file has been automatically generated using nplc.py. Do not edit it manually.
# Version: 1.76.2_0.0.0.0 generated on devsrv15.leaba.local at 2021-05-12 16:09:15


from python_npl_api_base_structs import *

class npl_additional_mpls_labels_offset_t(basic_npl_struct):
    def __init__(self, ene_three_labels_jump_offset=0, ene_four_labels_jump_offset=0, ene_five_labels_jump_offset=0, ene_six_labels_jump_offset=0, ene_seven_labels_jump_offset=0):
        super().__init__(24)
        self.ene_three_labels_jump_offset = ene_three_labels_jump_offset
        self.ene_four_labels_jump_offset = ene_four_labels_jump_offset
        self.ene_five_labels_jump_offset = ene_five_labels_jump_offset
        self.ene_six_labels_jump_offset = ene_six_labels_jump_offset
        self.ene_seven_labels_jump_offset = ene_seven_labels_jump_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_additional_mpls_labels_offset_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ene_three_labels_jump_offset(self):
        return self._get_field_value(20, 4)
    @ene_three_labels_jump_offset.setter
    def ene_three_labels_jump_offset(self, value):
        self._set_field_value('field ene_three_labels_jump_offset', 20, 4, int, value)
    @property
    def ene_four_labels_jump_offset(self):
        return self._get_field_value(16, 4)
    @ene_four_labels_jump_offset.setter
    def ene_four_labels_jump_offset(self, value):
        self._set_field_value('field ene_four_labels_jump_offset', 16, 4, int, value)
    @property
    def ene_five_labels_jump_offset(self):
        return self._get_field_value(8, 8)
    @ene_five_labels_jump_offset.setter
    def ene_five_labels_jump_offset(self, value):
        self._set_field_value('field ene_five_labels_jump_offset', 8, 8, int, value)
    @property
    def ene_six_labels_jump_offset(self):
        return self._get_field_value(4, 4)
    @ene_six_labels_jump_offset.setter
    def ene_six_labels_jump_offset(self, value):
        self._set_field_value('field ene_six_labels_jump_offset', 4, 4, int, value)
    @property
    def ene_seven_labels_jump_offset(self):
        return self._get_field_value(0, 4)
    @ene_seven_labels_jump_offset.setter
    def ene_seven_labels_jump_offset(self, value):
        self._set_field_value('field ene_seven_labels_jump_offset', 0, 4, int, value)



class npl_all_reachable_vector_result_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(108)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_all_reachable_vector_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def reachable(self):
        return basic_npl_array(108, 108, int, self._data, self._offset_in_data + 0)
    @reachable.setter
    def reachable(self, value):
        field = basic_npl_array(108, 108, int, self._data, self._offset_in_data + 0)
        field._set_field_value('field reachable', 0, 108, basic_npl_array, value)



class npl_app_traps_t(basic_npl_struct):
    def __init__(self, sgacl_drop=0, sgacl_log=0, ip_inactivity=0):
        super().__init__(3)
        self.sgacl_drop = sgacl_drop
        self.sgacl_log = sgacl_log
        self.ip_inactivity = ip_inactivity

    def _get_as_sub_field(data, offset_in_data):
        result = npl_app_traps_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sgacl_drop(self):
        return self._get_field_value(2, 1)
    @sgacl_drop.setter
    def sgacl_drop(self, value):
        self._set_field_value('field sgacl_drop', 2, 1, int, value)
    @property
    def sgacl_log(self):
        return self._get_field_value(1, 1)
    @sgacl_log.setter
    def sgacl_log(self, value):
        self._set_field_value('field sgacl_log', 1, 1, int, value)
    @property
    def ip_inactivity(self):
        return self._get_field_value(0, 1)
    @ip_inactivity.setter
    def ip_inactivity(self, value):
        self._set_field_value('field ip_inactivity', 0, 1, int, value)



class npl_aux_table_key_t(basic_npl_struct):
    def __init__(self, rd_address=0):
        super().__init__(12)
        self.rd_address = rd_address

    def _get_as_sub_field(data, offset_in_data):
        result = npl_aux_table_key_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rd_address(self):
        return self._get_field_value(0, 12)
    @rd_address.setter
    def rd_address(self, value):
        self._set_field_value('field rd_address', 0, 12, int, value)



class npl_aux_table_result_t(basic_npl_struct):
    def __init__(self, packet_header_type=0, count_phase=0, aux_data=0):
        super().__init__(160)
        self.packet_header_type = packet_header_type
        self.count_phase = count_phase
        self.aux_data = aux_data

    def _get_as_sub_field(data, offset_in_data):
        result = npl_aux_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def packet_header_type(self):
        return self._get_field_value(152, 8)
    @packet_header_type.setter
    def packet_header_type(self, value):
        self._set_field_value('field packet_header_type', 152, 8, int, value)
    @property
    def count_phase(self):
        return self._get_field_value(144, 8)
    @count_phase.setter
    def count_phase(self, value):
        self._set_field_value('field count_phase', 144, 8, int, value)
    @property
    def aux_data(self):
        return self._get_field_value(0, 144)
    @aux_data.setter
    def aux_data(self, value):
        self._set_field_value('field aux_data', 0, 144, int, value)



class npl_base_voq_nr_t(basic_npl_struct):
    def __init__(self, val=0):
        super().__init__(16)
        self.val = val

    def _get_as_sub_field(data, offset_in_data):
        result = npl_base_voq_nr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def val(self):
        return self._get_field_value(0, 16)
    @val.setter
    def val(self, value):
        self._set_field_value('field val', 0, 16, int, value)



class npl_bd_attributes_t(basic_npl_struct):
    def __init__(self, l2_lpts_attributes=0, flush_all_macs=0):
        super().__init__(8)
        self.l2_lpts_attributes = l2_lpts_attributes
        self.flush_all_macs = flush_all_macs

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bd_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2_lpts_attributes(self):
        return self._get_field_value(1, 6)
    @l2_lpts_attributes.setter
    def l2_lpts_attributes(self, value):
        self._set_field_value('field l2_lpts_attributes', 1, 6, int, value)
    @property
    def flush_all_macs(self):
        return self._get_field_value(0, 1)
    @flush_all_macs.setter
    def flush_all_macs(self, value):
        self._set_field_value('field flush_all_macs', 0, 1, int, value)



class npl_bfd_aux_ipv4_trans_payload_t(basic_npl_struct):
    def __init__(self, sip=0):
        super().__init__(32)
        self.sip = sip

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_aux_ipv4_trans_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sip(self):
        return self._get_field_value(0, 32)
    @sip.setter
    def sip(self, value):
        self._set_field_value('field sip', 0, 32, int, value)



class npl_bfd_aux_ipv6_trans_payload_t(basic_npl_struct):
    def __init__(self, ipv6_dip_b=0):
        super().__init__(32)
        self.ipv6_dip_b = ipv6_dip_b

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_aux_ipv6_trans_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ipv6_dip_b(self):
        return self._get_field_value(0, 32)
    @ipv6_dip_b.setter
    def ipv6_dip_b(self, value):
        self._set_field_value('field ipv6_dip_b', 0, 32, int, value)



class npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t(basic_npl_struct):
    def __init__(self):
        super().__init__(32)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ipv4(self):
        return npl_bfd_aux_ipv4_trans_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ipv4.setter
    def ipv4(self, value):
        self._set_field_value('field ipv4', 0, 32, npl_bfd_aux_ipv4_trans_payload_t, value)
    @property
    def ipv6(self):
        return npl_bfd_aux_ipv6_trans_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ipv6.setter
    def ipv6(self, value):
        self._set_field_value('field ipv6', 0, 32, npl_bfd_aux_ipv6_trans_payload_t, value)



class npl_bfd_em_t(basic_npl_struct):
    def __init__(self, rmep_id=0, mep_id=0, access_rmep=0, mp_data_select=0, access_mp=0):
        super().__init__(40)
        self.rmep_id = rmep_id
        self.mep_id = mep_id
        self.access_rmep = access_rmep
        self.mp_data_select = mp_data_select
        self.access_mp = access_mp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_em_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rmep_id(self):
        return self._get_field_value(16, 13)
    @rmep_id.setter
    def rmep_id(self, value):
        self._set_field_value('field rmep_id', 16, 13, int, value)
    @property
    def mep_id(self):
        return self._get_field_value(3, 13)
    @mep_id.setter
    def mep_id(self, value):
        self._set_field_value('field mep_id', 3, 13, int, value)
    @property
    def access_rmep(self):
        return self._get_field_value(2, 1)
    @access_rmep.setter
    def access_rmep(self, value):
        self._set_field_value('field access_rmep', 2, 1, int, value)
    @property
    def mp_data_select(self):
        return self._get_field_value(1, 1)
    @mp_data_select.setter
    def mp_data_select(self, value):
        self._set_field_value('field mp_data_select', 1, 1, int, value)
    @property
    def access_mp(self):
        return self._get_field_value(0, 1)
    @access_mp.setter
    def access_mp(self, value):
        self._set_field_value('field access_mp', 0, 1, int, value)



class npl_bfd_flags_t(basic_npl_struct):
    def __init__(self, poll=0, final=0, ctrl_plane_independent=0, auth_present=0, demand=0, multipoint=0):
        super().__init__(6)
        self.poll = poll
        self.final = final
        self.ctrl_plane_independent = ctrl_plane_independent
        self.auth_present = auth_present
        self.demand = demand
        self.multipoint = multipoint

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_flags_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def poll(self):
        return self._get_field_value(5, 1)
    @poll.setter
    def poll(self, value):
        self._set_field_value('field poll', 5, 1, int, value)
    @property
    def final(self):
        return self._get_field_value(4, 1)
    @final.setter
    def final(self, value):
        self._set_field_value('field final', 4, 1, int, value)
    @property
    def ctrl_plane_independent(self):
        return self._get_field_value(3, 1)
    @ctrl_plane_independent.setter
    def ctrl_plane_independent(self, value):
        self._set_field_value('field ctrl_plane_independent', 3, 1, int, value)
    @property
    def auth_present(self):
        return self._get_field_value(2, 1)
    @auth_present.setter
    def auth_present(self, value):
        self._set_field_value('field auth_present', 2, 1, int, value)
    @property
    def demand(self):
        return self._get_field_value(1, 1)
    @demand.setter
    def demand(self, value):
        self._set_field_value('field demand', 1, 1, int, value)
    @property
    def multipoint(self):
        return self._get_field_value(0, 1)
    @multipoint.setter
    def multipoint(self, value):
        self._set_field_value('field multipoint', 0, 1, int, value)



class npl_bfd_inject_ttl_t(basic_npl_struct):
    def __init__(self, ttl=0):
        super().__init__(8)
        self.ttl = ttl

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_inject_ttl_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ttl(self):
        return self._get_field_value(0, 8)
    @ttl.setter
    def ttl(self, value):
        self._set_field_value('field ttl', 0, 8, int, value)



class npl_bfd_ipv4_prot_shared_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(40)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_ipv4_prot_shared_t()
        result._set_data_pointer(data, offset_in_data)
        return result




class npl_bfd_ipv6_prot_shared_t(basic_npl_struct):
    def __init__(self, ipv6_dip_c=0):
        super().__init__(40)
        self.ipv6_dip_c = ipv6_dip_c

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_ipv6_prot_shared_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ipv6_dip_c(self):
        return self._get_field_value(0, 40)
    @ipv6_dip_c.setter
    def ipv6_dip_c(self, value):
        self._set_field_value('field ipv6_dip_c', 0, 40, int, value)



class npl_bfd_ipv6_selector_t(basic_npl_struct):
    def __init__(self, data=0):
        super().__init__(8)
        self.data = data

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_ipv6_selector_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def data(self):
        return self._get_field_value(0, 8)
    @data.setter
    def data(self, value):
        self._set_field_value('field data', 0, 8, int, value)



class npl_bfd_local_ipv6_sip_t(basic_npl_struct):
    def __init__(self, sip=0):
        super().__init__(32)
        self.sip = sip

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_local_ipv6_sip_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sip(self):
        return self._get_field_value(0, 32)
    @sip.setter
    def sip(self, value):
        self._set_field_value('field sip', 0, 32, int, value)



class npl_bfd_mp_ipv4_transport_t(basic_npl_struct):
    def __init__(self, dip=0, checksum=0):
        super().__init__(57)
        self.dip = dip
        self.checksum = checksum

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_mp_ipv4_transport_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dip(self):
        return self._get_field_value(25, 32)
    @dip.setter
    def dip(self, value):
        self._set_field_value('field dip', 25, 32, int, value)
    @property
    def checksum(self):
        return self._get_field_value(9, 16)
    @checksum.setter
    def checksum(self, value):
        self._set_field_value('field checksum', 9, 16, int, value)



class npl_bfd_mp_ipv6_transport_t(basic_npl_struct):
    def __init__(self, ipv6_dip_a=0):
        super().__init__(57)
        self.ipv6_dip_a = ipv6_dip_a

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_mp_ipv6_transport_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ipv6_dip_a(self):
        return self._get_field_value(1, 56)
    @ipv6_dip_a.setter
    def ipv6_dip_a(self, value):
        self._set_field_value('field ipv6_dip_a', 1, 56, int, value)



class npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t(basic_npl_struct):
    def __init__(self):
        super().__init__(57)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ipv4(self):
        return npl_bfd_mp_ipv4_transport_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ipv4.setter
    def ipv4(self, value):
        self._set_field_value('field ipv4', 0, 57, npl_bfd_mp_ipv4_transport_t, value)
    @property
    def ipv6(self):
        return npl_bfd_mp_ipv6_transport_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ipv6.setter
    def ipv6(self, value):
        self._set_field_value('field ipv6', 0, 57, npl_bfd_mp_ipv6_transport_t, value)



class npl_bfd_mp_table_transmit_b_payload_t(basic_npl_struct):
    def __init__(self, local_state_and_flags=0, sip_selector=0):
        super().__init__(16)
        self.local_state_and_flags = local_state_and_flags
        self.sip_selector = sip_selector

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_mp_table_transmit_b_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def local_state_and_flags(self):
        return self._get_field_value(8, 8)
    @local_state_and_flags.setter
    def local_state_and_flags(self, value):
        self._set_field_value('field local_state_and_flags', 8, 8, int, value)
    @property
    def sip_selector(self):
        return self._get_field_value(0, 8)
    @sip_selector.setter
    def sip_selector(self, value):
        self._set_field_value('field sip_selector', 0, 8, int, value)



class npl_bfd_transport_and_label_t(basic_npl_struct):
    def __init__(self, transport=0, requires_label=0):
        super().__init__(3)
        self.transport = transport
        self.requires_label = requires_label

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_transport_and_label_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def transport(self):
        return self._get_field_value(1, 2)
    @transport.setter
    def transport(self, value):
        self._set_field_value('field transport', 1, 2, int, value)
    @property
    def requires_label(self):
        return self._get_field_value(0, 1)
    @requires_label.setter
    def requires_label(self, value):
        self._set_field_value('field requires_label', 0, 1, int, value)



class npl_bool_t(basic_npl_struct):
    def __init__(self, val=0):
        super().__init__(1)
        self.val = val

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bool_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def val(self):
        return self._get_field_value(0, 1)
    @val.setter
    def val(self, value):
        self._set_field_value('field val', 0, 1, int, value)



class npl_burst_size_len_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(18)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_burst_size_len_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 18)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 18, int, value)



class npl_bvn_profile_t(basic_npl_struct):
    def __init__(self, lp_over_lag=0, tc_map_profile=0):
        super().__init__(4)
        self.lp_over_lag = lp_over_lag
        self.tc_map_profile = tc_map_profile

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bvn_profile_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lp_over_lag(self):
        return self._get_field_value(3, 1)
    @lp_over_lag.setter
    def lp_over_lag(self, value):
        self._set_field_value('field lp_over_lag', 3, 1, int, value)
    @property
    def tc_map_profile(self):
        return self._get_field_value(0, 3)
    @tc_map_profile.setter
    def tc_map_profile(self, value):
        self._set_field_value('field tc_map_profile', 0, 3, int, value)



class npl_calc_checksum_enable_t(basic_npl_struct):
    def __init__(self, enable=0):
        super().__init__(1)
        self.enable = enable

    def _get_as_sub_field(data, offset_in_data):
        result = npl_calc_checksum_enable_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enable(self):
        return self._get_field_value(0, 1)
    @enable.setter
    def enable(self, value):
        self._set_field_value('field enable', 0, 1, int, value)



class npl_color_aware_mode_len_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(1)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_color_aware_mode_len_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 1)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 1, int, value)



class npl_color_len_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(2)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_color_len_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 2)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 2, int, value)



class npl_common_cntr_5bits_offset_and_padding_t(basic_npl_struct):
    def __init__(self, offset=0):
        super().__init__(5)
        self.offset = offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_common_cntr_5bits_offset_and_padding_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def offset(self):
        return self._get_field_value(0, 5)
    @offset.setter
    def offset(self, value):
        self._set_field_value('field offset', 0, 5, int, value)



class npl_common_cntr_offset_t(basic_npl_struct):
    def __init__(self, base_cntr_offset=0):
        super().__init__(3)
        self.base_cntr_offset = base_cntr_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_common_cntr_offset_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def base_cntr_offset(self):
        return self._get_field_value(0, 3)
    @base_cntr_offset.setter
    def base_cntr_offset(self, value):
        self._set_field_value('field base_cntr_offset', 0, 3, int, value)



class npl_compound_termination_control_t(basic_npl_struct):
    def __init__(self, append_relay=0, attempt_termination=0):
        super().__init__(2)
        self.append_relay = append_relay
        self.attempt_termination = attempt_termination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_compound_termination_control_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def append_relay(self):
        return self._get_field_value(1, 1)
    @append_relay.setter
    def append_relay(self, value):
        self._set_field_value('field append_relay', 1, 1, int, value)
    @property
    def attempt_termination(self):
        return self._get_field_value(0, 1)
    @attempt_termination.setter
    def attempt_termination(self, value):
        self._set_field_value('field attempt_termination', 0, 1, int, value)



class npl_compressed_counter_t(basic_npl_struct):
    def __init__(self, counter_idx=0):
        super().__init__(8)
        self.counter_idx = counter_idx

    def _get_as_sub_field(data, offset_in_data):
        result = npl_compressed_counter_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def counter_idx(self):
        return self._get_field_value(0, 8)
    @counter_idx.setter
    def counter_idx(self, value):
        self._set_field_value('field counter_idx', 0, 8, int, value)



class npl_counter_flag_t(basic_npl_struct):
    def __init__(self, num_labels_is_3=0, pad=0):
        super().__init__(20)
        self.num_labels_is_3 = num_labels_is_3
        self.pad = pad

    def _get_as_sub_field(data, offset_in_data):
        result = npl_counter_flag_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def num_labels_is_3(self):
        return self._get_field_value(19, 1)
    @num_labels_is_3.setter
    def num_labels_is_3(self, value):
        self._set_field_value('field num_labels_is_3', 19, 1, int, value)
    @property
    def pad(self):
        return self._get_field_value(0, 19)
    @pad.setter
    def pad(self, value):
        self._set_field_value('field pad', 0, 19, int, value)



class npl_counter_offset_t(basic_npl_struct):
    def __init__(self, offset=0):
        super().__init__(3)
        self.offset = offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_counter_offset_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def offset(self):
        return self._get_field_value(0, 3)
    @offset.setter
    def offset(self, value):
        self._set_field_value('field offset', 0, 3, int, value)



class npl_counter_ptr_t(basic_npl_struct):
    def __init__(self, update_or_read=0, cb_id=0, cb_set_base=0):
        super().__init__(20)
        self.update_or_read = update_or_read
        self.cb_id = cb_id
        self.cb_set_base = cb_set_base

    def _get_as_sub_field(data, offset_in_data):
        result = npl_counter_ptr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def update_or_read(self):
        return self._get_field_value(19, 1)
    @update_or_read.setter
    def update_or_read(self, value):
        self._set_field_value('field update_or_read', 19, 1, int, value)
    @property
    def cb_id(self):
        return self._get_field_value(12, 7)
    @cb_id.setter
    def cb_id(self, value):
        self._set_field_value('field cb_id', 12, 7, int, value)
    @property
    def cb_set_base(self):
        return self._get_field_value(0, 12)
    @cb_set_base.setter
    def cb_set_base(self, value):
        self._set_field_value('field cb_set_base', 0, 12, int, value)



class npl_counters_block_config_t(basic_npl_struct):
    def __init__(self, lm_count_and_read=0, reset_on_max_counter_read=0, bank_counter_type=0, compensation=0, ignore_pd_compensation=0, wraparound=0, cpu_read_cc_wait_before_create_bubble=0, bank_pipe_client_allocation=0, bank_slice_allocation=0):
        super().__init__(24)
        self.lm_count_and_read = lm_count_and_read
        self.reset_on_max_counter_read = reset_on_max_counter_read
        self.bank_counter_type = bank_counter_type
        self.compensation = compensation
        self.ignore_pd_compensation = ignore_pd_compensation
        self.wraparound = wraparound
        self.cpu_read_cc_wait_before_create_bubble = cpu_read_cc_wait_before_create_bubble
        self.bank_pipe_client_allocation = bank_pipe_client_allocation
        self.bank_slice_allocation = bank_slice_allocation

    def _get_as_sub_field(data, offset_in_data):
        result = npl_counters_block_config_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lm_count_and_read(self):
        return self._get_field_value(23, 1)
    @lm_count_and_read.setter
    def lm_count_and_read(self, value):
        self._set_field_value('field lm_count_and_read', 23, 1, int, value)
    @property
    def reset_on_max_counter_read(self):
        return self._get_field_value(22, 1)
    @reset_on_max_counter_read.setter
    def reset_on_max_counter_read(self, value):
        self._set_field_value('field reset_on_max_counter_read', 22, 1, int, value)
    @property
    def bank_counter_type(self):
        return self._get_field_value(20, 2)
    @bank_counter_type.setter
    def bank_counter_type(self, value):
        self._set_field_value('field bank_counter_type', 20, 2, int, value)
    @property
    def compensation(self):
        return self._get_field_value(13, 7)
    @compensation.setter
    def compensation(self, value):
        self._set_field_value('field compensation', 13, 7, int, value)
    @property
    def ignore_pd_compensation(self):
        return self._get_field_value(12, 1)
    @ignore_pd_compensation.setter
    def ignore_pd_compensation(self, value):
        self._set_field_value('field ignore_pd_compensation', 12, 1, int, value)
    @property
    def wraparound(self):
        return self._get_field_value(11, 1)
    @wraparound.setter
    def wraparound(self, value):
        self._set_field_value('field wraparound', 11, 1, int, value)
    @property
    def cpu_read_cc_wait_before_create_bubble(self):
        return self._get_field_value(5, 6)
    @cpu_read_cc_wait_before_create_bubble.setter
    def cpu_read_cc_wait_before_create_bubble(self, value):
        self._set_field_value('field cpu_read_cc_wait_before_create_bubble', 5, 6, int, value)
    @property
    def bank_pipe_client_allocation(self):
        return self._get_field_value(3, 2)
    @bank_pipe_client_allocation.setter
    def bank_pipe_client_allocation(self, value):
        self._set_field_value('field bank_pipe_client_allocation', 3, 2, int, value)
    @property
    def bank_slice_allocation(self):
        return self._get_field_value(0, 3)
    @bank_slice_allocation.setter
    def bank_slice_allocation(self, value):
        self._set_field_value('field bank_slice_allocation', 0, 3, int, value)



class npl_counters_voq_block_map_result_t(basic_npl_struct):
    def __init__(self, map_groups_size=0, tc_profile=0, counter_offset=0, bank_id=0):
        super().__init__(23)
        self.map_groups_size = map_groups_size
        self.tc_profile = tc_profile
        self.counter_offset = counter_offset
        self.bank_id = bank_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_counters_voq_block_map_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def map_groups_size(self):
        return self._get_field_value(21, 2)
    @map_groups_size.setter
    def map_groups_size(self, value):
        self._set_field_value('field map_groups_size', 21, 2, int, value)
    @property
    def tc_profile(self):
        return self._get_field_value(20, 1)
    @tc_profile.setter
    def tc_profile(self, value):
        self._set_field_value('field tc_profile', 20, 1, int, value)
    @property
    def counter_offset(self):
        return self._get_field_value(7, 13)
    @counter_offset.setter
    def counter_offset(self, value):
        self._set_field_value('field counter_offset', 7, 13, int, value)
    @property
    def bank_id(self):
        return self._get_field_value(0, 7)
    @bank_id.setter
    def bank_id(self, value):
        self._set_field_value('field bank_id', 0, 7, int, value)



class npl_curr_and_next_prot_type_t(basic_npl_struct):
    def __init__(self, current_proto_type=0, next_proto_type=0):
        super().__init__(8)
        self.current_proto_type = current_proto_type
        self.next_proto_type = next_proto_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_curr_and_next_prot_type_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def current_proto_type(self):
        return self._get_field_value(4, 4)
    @current_proto_type.setter
    def current_proto_type(self, value):
        self._set_field_value('field current_proto_type', 4, 4, int, value)
    @property
    def next_proto_type(self):
        return self._get_field_value(0, 4)
    @next_proto_type.setter
    def next_proto_type(self, value):
        self._set_field_value('field next_proto_type', 0, 4, int, value)



class npl_dest_slice_voq_map_table_result_t(basic_npl_struct):
    def __init__(self, dest_slice_voq=0):
        super().__init__(16)
        self.dest_slice_voq = dest_slice_voq

    def _get_as_sub_field(data, offset_in_data):
        result = npl_dest_slice_voq_map_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dest_slice_voq(self):
        return self._get_field_value(0, 16)
    @dest_slice_voq.setter
    def dest_slice_voq(self, value):
        self._set_field_value('field dest_slice_voq', 0, 16, int, value)



class npl_destination_decoding_table_result_t(basic_npl_struct):
    def __init__(self, check_npp_range=0, lb_table_behavior=0, resolution_table=0, resolution_stage=0):
        super().__init__(8)
        self.check_npp_range = check_npp_range
        self.lb_table_behavior = lb_table_behavior
        self.resolution_table = resolution_table
        self.resolution_stage = resolution_stage

    def _get_as_sub_field(data, offset_in_data):
        result = npl_destination_decoding_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def check_npp_range(self):
        return self._get_field_value(7, 1)
    @check_npp_range.setter
    def check_npp_range(self, value):
        self._set_field_value('field check_npp_range', 7, 1, int, value)
    @property
    def lb_table_behavior(self):
        return self._get_field_value(6, 1)
    @lb_table_behavior.setter
    def lb_table_behavior(self, value):
        self._set_field_value('field lb_table_behavior', 6, 1, int, value)
    @property
    def resolution_table(self):
        return self._get_field_value(2, 4)
    @resolution_table.setter
    def resolution_table(self, value):
        self._set_field_value('field resolution_table', 2, 4, int, value)
    @property
    def resolution_stage(self):
        return self._get_field_value(0, 2)
    @resolution_stage.setter
    def resolution_stage(self, value):
        self._set_field_value('field resolution_stage', 0, 2, int, value)



class npl_destination_t(basic_npl_struct):
    def __init__(self, val=0):
        super().__init__(20)
        self.val = val

    def _get_as_sub_field(data, offset_in_data):
        result = npl_destination_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def val(self):
        return self._get_field_value(0, 20)
    @val.setter
    def val(self, value):
        self._set_field_value('field val', 0, 20, int, value)



class npl_device_mode_table_result_t(basic_npl_struct):
    def __init__(self, dev_mode=0):
        super().__init__(2)
        self.dev_mode = dev_mode

    def _get_as_sub_field(data, offset_in_data):
        result = npl_device_mode_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dev_mode(self):
        return self._get_field_value(0, 2)
    @dev_mode.setter
    def dev_mode(self, value):
        self._set_field_value('field dev_mode', 0, 2, int, value)



class npl_dip_index_t(basic_npl_struct):
    def __init__(self, dummy_index=0):
        super().__init__(9)
        self.dummy_index = dummy_index

    def _get_as_sub_field(data, offset_in_data):
        result = npl_dip_index_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dummy_index(self):
        return self._get_field_value(0, 9)
    @dummy_index.setter
    def dummy_index(self, value):
        self._set_field_value('field dummy_index', 0, 9, int, value)



class npl_drop_punt_or_permit_t(basic_npl_struct):
    def __init__(self, drop=0, force_punt=0, permit_count_enable=0):
        super().__init__(3)
        self.drop = drop
        self.force_punt = force_punt
        self.permit_count_enable = permit_count_enable

    def _get_as_sub_field(data, offset_in_data):
        result = npl_drop_punt_or_permit_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def drop(self):
        return self._get_field_value(2, 1)
    @drop.setter
    def drop(self, value):
        self._set_field_value('field drop', 2, 1, int, value)
    @property
    def force_punt(self):
        return self._get_field_value(1, 1)
    @force_punt.setter
    def force_punt(self, value):
        self._set_field_value('field force_punt', 1, 1, int, value)
    @property
    def permit_count_enable(self):
        return self._get_field_value(0, 1)
    @permit_count_enable.setter
    def permit_count_enable(self, value):
        self._set_field_value('field permit_count_enable', 0, 1, int, value)



class npl_dsp_map_info_t(basic_npl_struct):
    def __init__(self, dsp_punt_rcy=0, dsp_is_scheduled_rcy=0):
        super().__init__(2)
        self.dsp_punt_rcy = dsp_punt_rcy
        self.dsp_is_scheduled_rcy = dsp_is_scheduled_rcy

    def _get_as_sub_field(data, offset_in_data):
        result = npl_dsp_map_info_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dsp_punt_rcy(self):
        return self._get_field_value(1, 1)
    @dsp_punt_rcy.setter
    def dsp_punt_rcy(self, value):
        self._set_field_value('field dsp_punt_rcy', 1, 1, int, value)
    @property
    def dsp_is_scheduled_rcy(self):
        return self._get_field_value(0, 1)
    @dsp_is_scheduled_rcy.setter
    def dsp_is_scheduled_rcy(self, value):
        self._set_field_value('field dsp_is_scheduled_rcy', 0, 1, int, value)



class npl_egress_direct0_key_t(basic_npl_struct):
    def __init__(self, direct0_key=0):
        super().__init__(12)
        self.direct0_key = direct0_key

    def _get_as_sub_field(data, offset_in_data):
        result = npl_egress_direct0_key_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def direct0_key(self):
        return self._get_field_value(0, 12)
    @direct0_key.setter
    def direct0_key(self, value):
        self._set_field_value('field direct0_key', 0, 12, int, value)



class npl_egress_direct1_key_t(basic_npl_struct):
    def __init__(self, direct1_key=0):
        super().__init__(10)
        self.direct1_key = direct1_key

    def _get_as_sub_field(data, offset_in_data):
        result = npl_egress_direct1_key_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def direct1_key(self):
        return self._get_field_value(0, 10)
    @direct1_key.setter
    def direct1_key(self, value):
        self._set_field_value('field direct1_key', 0, 10, int, value)



class npl_egress_qos_result_t_anonymous_union_remark_l3_t(basic_npl_struct):
    def __init__(self):
        super().__init__(1)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_egress_qos_result_t_anonymous_union_remark_l3_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enable_egress_remark(self):
        return self._get_field_value(0, 1)
    @enable_egress_remark.setter
    def enable_egress_remark(self, value):
        self._set_field_value('field enable_egress_remark', 0, 1, int, value)
    @property
    def use_in_mpls_exp(self):
        return self._get_field_value(0, 1)
    @use_in_mpls_exp.setter
    def use_in_mpls_exp(self, value):
        self._set_field_value('field use_in_mpls_exp', 0, 1, int, value)



class npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def drop_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @drop_counter.setter
    def drop_counter(self, value):
        self._set_field_value('field drop_counter', 0, 20, npl_counter_ptr_t, value)
    @property
    def permit_ace_cntr(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @permit_ace_cntr.setter
    def permit_ace_cntr(self, value):
        self._set_field_value('field permit_ace_cntr', 0, 20, npl_counter_ptr_t, value)



class npl_em_result_dsp_host_t(basic_npl_struct):
    def __init__(self, dsp_or_dspa=0, host_mac=0):
        super().__init__(62)
        self.dsp_or_dspa = dsp_or_dspa
        self.host_mac = host_mac

    def _get_as_sub_field(data, offset_in_data):
        result = npl_em_result_dsp_host_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dsp_or_dspa(self):
        return self._get_field_value(48, 14)
    @dsp_or_dspa.setter
    def dsp_or_dspa(self, value):
        self._set_field_value('field dsp_or_dspa', 48, 14, int, value)
    @property
    def host_mac(self):
        return self._get_field_value(0, 48)
    @host_mac.setter
    def host_mac(self, value):
        self._set_field_value('field host_mac', 0, 48, int, value)



class npl_encap_mpls_exp_t(basic_npl_struct):
    def __init__(self, valid=0, exp=0):
        super().__init__(4)
        self.valid = valid
        self.exp = exp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_encap_mpls_exp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def valid(self):
        return self._get_field_value(3, 1)
    @valid.setter
    def valid(self, value):
        self._set_field_value('field valid', 3, 1, int, value)
    @property
    def exp(self):
        return self._get_field_value(0, 3)
    @exp.setter
    def exp(self, value):
        self._set_field_value('field exp', 0, 3, int, value)



class npl_ene_macro_id_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(8)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ene_macro_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 8)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 8, int, value)



class npl_ene_no_bos_t(basic_npl_struct):
    def __init__(self, exp=0):
        super().__init__(4)
        self.exp = exp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ene_no_bos_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def exp(self):
        return self._get_field_value(1, 3)
    @exp.setter
    def exp(self, value):
        self._set_field_value('field exp', 1, 3, int, value)



class npl_eth_mp_table_transmit_a_payload_t(basic_npl_struct):
    def __init__(self, tx_rdi=0, ccm_da=0, unicast_da=0):
        super().__init__(60)
        self.tx_rdi = tx_rdi
        self.ccm_da = ccm_da
        self.unicast_da = unicast_da

    def _get_as_sub_field(data, offset_in_data):
        result = npl_eth_mp_table_transmit_a_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tx_rdi(self):
        return self._get_field_value(52, 1)
    @tx_rdi.setter
    def tx_rdi(self, value):
        self._set_field_value('field tx_rdi', 52, 1, int, value)
    @property
    def ccm_da(self):
        return self._get_field_value(48, 1)
    @ccm_da.setter
    def ccm_da(self, value):
        self._set_field_value('field ccm_da', 48, 1, int, value)
    @property
    def unicast_da(self):
        return self._get_field_value(0, 48)
    @unicast_da.setter
    def unicast_da(self, value):
        self._set_field_value('field unicast_da', 0, 48, int, value)



class npl_eth_mp_table_transmit_b_payload_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(16)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_eth_mp_table_transmit_b_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result




class npl_eth_rmep_app_t(basic_npl_struct):
    def __init__(self, rmep_rdi=0, rmep_loc=0):
        super().__init__(4)
        self.rmep_rdi = rmep_rdi
        self.rmep_loc = rmep_loc

    def _get_as_sub_field(data, offset_in_data):
        result = npl_eth_rmep_app_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rmep_rdi(self):
        return self._get_field_value(1, 1)
    @rmep_rdi.setter
    def rmep_rdi(self, value):
        self._set_field_value('field rmep_rdi', 1, 1, int, value)
    @property
    def rmep_loc(self):
        return self._get_field_value(0, 1)
    @rmep_loc.setter
    def rmep_loc(self, value):
        self._set_field_value('field rmep_loc', 0, 1, int, value)



class npl_eth_rmep_attributes_t(basic_npl_struct):
    def __init__(self, app=0):
        super().__init__(11)
        self.app = app

    def _get_as_sub_field(data, offset_in_data):
        result = npl_eth_rmep_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def app(self):
        return npl_eth_rmep_app_t._get_as_sub_field(self._data, self._offset_in_data + 7)
    @app.setter
    def app(self, value):
        self._set_field_value('field app', 7, 4, npl_eth_rmep_app_t, value)



class npl_eth_rtf_prop_over_fwd0_t(basic_npl_struct):
    def __init__(self, table_index=0, acl_id=0):
        super().__init__(8)
        self.table_index = table_index
        self.acl_id = acl_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_eth_rtf_prop_over_fwd0_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def table_index(self):
        return self._get_field_value(7, 1)
    @table_index.setter
    def table_index(self, value):
        self._set_field_value('field table_index', 7, 1, int, value)
    @property
    def acl_id(self):
        return self._get_field_value(0, 7)
    @acl_id.setter
    def acl_id(self, value):
        self._set_field_value('field acl_id', 0, 7, int, value)



class npl_eth_rtf_prop_over_fwd1_t(basic_npl_struct):
    def __init__(self, table_index=0, acl_id=0):
        super().__init__(8)
        self.table_index = table_index
        self.acl_id = acl_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_eth_rtf_prop_over_fwd1_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def table_index(self):
        return self._get_field_value(7, 1)
    @table_index.setter
    def table_index(self, value):
        self._set_field_value('field table_index', 7, 1, int, value)
    @property
    def acl_id(self):
        return self._get_field_value(0, 7)
    @acl_id.setter
    def acl_id(self, value):
        self._set_field_value('field acl_id', 0, 7, int, value)



class npl_ethernet_header_flags_t(basic_npl_struct):
    def __init__(self, da_is_bc=0, sa_is_mc=0, sa_eq_da=0):
        super().__init__(3)
        self.da_is_bc = da_is_bc
        self.sa_is_mc = sa_is_mc
        self.sa_eq_da = sa_eq_da

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ethernet_header_flags_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def da_is_bc(self):
        return self._get_field_value(2, 1)
    @da_is_bc.setter
    def da_is_bc(self, value):
        self._set_field_value('field da_is_bc', 2, 1, int, value)
    @property
    def sa_is_mc(self):
        return self._get_field_value(1, 1)
    @sa_is_mc.setter
    def sa_is_mc(self, value):
        self._set_field_value('field sa_is_mc', 1, 1, int, value)
    @property
    def sa_eq_da(self):
        return self._get_field_value(0, 1)
    @sa_eq_da.setter
    def sa_eq_da(self, value):
        self._set_field_value('field sa_eq_da', 0, 1, int, value)



class npl_ethernet_oam_em_t(basic_npl_struct):
    def __init__(self, rmep_id=0, mep_id=0, access_rmep=0, mp_data_select=0, access_mp=0):
        super().__init__(29)
        self.rmep_id = rmep_id
        self.mep_id = mep_id
        self.access_rmep = access_rmep
        self.mp_data_select = mp_data_select
        self.access_mp = access_mp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ethernet_oam_em_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rmep_id(self):
        return self._get_field_value(16, 13)
    @rmep_id.setter
    def rmep_id(self, value):
        self._set_field_value('field rmep_id', 16, 13, int, value)
    @property
    def mep_id(self):
        return self._get_field_value(3, 13)
    @mep_id.setter
    def mep_id(self, value):
        self._set_field_value('field mep_id', 3, 13, int, value)
    @property
    def access_rmep(self):
        return self._get_field_value(2, 1)
    @access_rmep.setter
    def access_rmep(self, value):
        self._set_field_value('field access_rmep', 2, 1, int, value)
    @property
    def mp_data_select(self):
        return self._get_field_value(1, 1)
    @mp_data_select.setter
    def mp_data_select(self, value):
        self._set_field_value('field mp_data_select', 1, 1, int, value)
    @property
    def access_mp(self):
        return self._get_field_value(0, 1)
    @access_mp.setter
    def access_mp(self, value):
        self._set_field_value('field access_mp', 0, 1, int, value)



class npl_ethernet_traps_t(basic_npl_struct):
    def __init__(self, acl_drop=0, acl_force_punt=0, vlan_membership=0, acceptable_format=0, no_service_mapping=0, no_termination_on_l3_port=0, no_sip_mapping=0, no_vni_mapping=0, no_vsid_mapping=0, arp=0, sa_da_error=0, sa_error=0, da_error=0, sa_multicast=0, dhcpv4_server=0, dhcpv4_client=0, dhcpv6_server=0, dhcpv6_client=0, ingress_stp_block=0, ptp_over_eth=0, isis_over_l2=0, l2cp0=0, l2cp1=0, l2cp2=0, l2cp3=0, l2cp4=0, l2cp5=0, l2cp6=0, l2cp7=0, lacp=0, cisco_protocols=0, macsec=0, unknown_l3=0, test_oam_ac_mep=0, test_oam_ac_mip=0, test_oam_cfm_link_mdl0=0, system_mymac=0, unknown_bc=0, unknown_mc=0, unknown_uc=0, learn_punt=0, bcast_pkt=0, pfc_sample=0, hop_by_hop=0, l2_dlp_not_found=0, same_interface=0, dspa_mc_trim=0, egress_stp_block=0, split_horizon=0, disabled=0, incompatible_eve_cmd=0, padding_residue_in_second_line=0, pfc_direct_sample=0, svi_egress_dhcp=0, no_pwe_l3_dest=0):
        super().__init__(55)
        self.acl_drop = acl_drop
        self.acl_force_punt = acl_force_punt
        self.vlan_membership = vlan_membership
        self.acceptable_format = acceptable_format
        self.no_service_mapping = no_service_mapping
        self.no_termination_on_l3_port = no_termination_on_l3_port
        self.no_sip_mapping = no_sip_mapping
        self.no_vni_mapping = no_vni_mapping
        self.no_vsid_mapping = no_vsid_mapping
        self.arp = arp
        self.sa_da_error = sa_da_error
        self.sa_error = sa_error
        self.da_error = da_error
        self.sa_multicast = sa_multicast
        self.dhcpv4_server = dhcpv4_server
        self.dhcpv4_client = dhcpv4_client
        self.dhcpv6_server = dhcpv6_server
        self.dhcpv6_client = dhcpv6_client
        self.ingress_stp_block = ingress_stp_block
        self.ptp_over_eth = ptp_over_eth
        self.isis_over_l2 = isis_over_l2
        self.l2cp0 = l2cp0
        self.l2cp1 = l2cp1
        self.l2cp2 = l2cp2
        self.l2cp3 = l2cp3
        self.l2cp4 = l2cp4
        self.l2cp5 = l2cp5
        self.l2cp6 = l2cp6
        self.l2cp7 = l2cp7
        self.lacp = lacp
        self.cisco_protocols = cisco_protocols
        self.macsec = macsec
        self.unknown_l3 = unknown_l3
        self.test_oam_ac_mep = test_oam_ac_mep
        self.test_oam_ac_mip = test_oam_ac_mip
        self.test_oam_cfm_link_mdl0 = test_oam_cfm_link_mdl0
        self.system_mymac = system_mymac
        self.unknown_bc = unknown_bc
        self.unknown_mc = unknown_mc
        self.unknown_uc = unknown_uc
        self.learn_punt = learn_punt
        self.bcast_pkt = bcast_pkt
        self.pfc_sample = pfc_sample
        self.hop_by_hop = hop_by_hop
        self.l2_dlp_not_found = l2_dlp_not_found
        self.same_interface = same_interface
        self.dspa_mc_trim = dspa_mc_trim
        self.egress_stp_block = egress_stp_block
        self.split_horizon = split_horizon
        self.disabled = disabled
        self.incompatible_eve_cmd = incompatible_eve_cmd
        self.padding_residue_in_second_line = padding_residue_in_second_line
        self.pfc_direct_sample = pfc_direct_sample
        self.svi_egress_dhcp = svi_egress_dhcp
        self.no_pwe_l3_dest = no_pwe_l3_dest

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ethernet_traps_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def acl_drop(self):
        return self._get_field_value(54, 1)
    @acl_drop.setter
    def acl_drop(self, value):
        self._set_field_value('field acl_drop', 54, 1, int, value)
    @property
    def acl_force_punt(self):
        return self._get_field_value(53, 1)
    @acl_force_punt.setter
    def acl_force_punt(self, value):
        self._set_field_value('field acl_force_punt', 53, 1, int, value)
    @property
    def vlan_membership(self):
        return self._get_field_value(52, 1)
    @vlan_membership.setter
    def vlan_membership(self, value):
        self._set_field_value('field vlan_membership', 52, 1, int, value)
    @property
    def acceptable_format(self):
        return self._get_field_value(51, 1)
    @acceptable_format.setter
    def acceptable_format(self, value):
        self._set_field_value('field acceptable_format', 51, 1, int, value)
    @property
    def no_service_mapping(self):
        return self._get_field_value(50, 1)
    @no_service_mapping.setter
    def no_service_mapping(self, value):
        self._set_field_value('field no_service_mapping', 50, 1, int, value)
    @property
    def no_termination_on_l3_port(self):
        return self._get_field_value(49, 1)
    @no_termination_on_l3_port.setter
    def no_termination_on_l3_port(self, value):
        self._set_field_value('field no_termination_on_l3_port', 49, 1, int, value)
    @property
    def no_sip_mapping(self):
        return self._get_field_value(48, 1)
    @no_sip_mapping.setter
    def no_sip_mapping(self, value):
        self._set_field_value('field no_sip_mapping', 48, 1, int, value)
    @property
    def no_vni_mapping(self):
        return self._get_field_value(47, 1)
    @no_vni_mapping.setter
    def no_vni_mapping(self, value):
        self._set_field_value('field no_vni_mapping', 47, 1, int, value)
    @property
    def no_vsid_mapping(self):
        return self._get_field_value(46, 1)
    @no_vsid_mapping.setter
    def no_vsid_mapping(self, value):
        self._set_field_value('field no_vsid_mapping', 46, 1, int, value)
    @property
    def arp(self):
        return self._get_field_value(45, 1)
    @arp.setter
    def arp(self, value):
        self._set_field_value('field arp', 45, 1, int, value)
    @property
    def sa_da_error(self):
        return self._get_field_value(44, 1)
    @sa_da_error.setter
    def sa_da_error(self, value):
        self._set_field_value('field sa_da_error', 44, 1, int, value)
    @property
    def sa_error(self):
        return self._get_field_value(43, 1)
    @sa_error.setter
    def sa_error(self, value):
        self._set_field_value('field sa_error', 43, 1, int, value)
    @property
    def da_error(self):
        return self._get_field_value(42, 1)
    @da_error.setter
    def da_error(self, value):
        self._set_field_value('field da_error', 42, 1, int, value)
    @property
    def sa_multicast(self):
        return self._get_field_value(41, 1)
    @sa_multicast.setter
    def sa_multicast(self, value):
        self._set_field_value('field sa_multicast', 41, 1, int, value)
    @property
    def dhcpv4_server(self):
        return self._get_field_value(40, 1)
    @dhcpv4_server.setter
    def dhcpv4_server(self, value):
        self._set_field_value('field dhcpv4_server', 40, 1, int, value)
    @property
    def dhcpv4_client(self):
        return self._get_field_value(39, 1)
    @dhcpv4_client.setter
    def dhcpv4_client(self, value):
        self._set_field_value('field dhcpv4_client', 39, 1, int, value)
    @property
    def dhcpv6_server(self):
        return self._get_field_value(38, 1)
    @dhcpv6_server.setter
    def dhcpv6_server(self, value):
        self._set_field_value('field dhcpv6_server', 38, 1, int, value)
    @property
    def dhcpv6_client(self):
        return self._get_field_value(37, 1)
    @dhcpv6_client.setter
    def dhcpv6_client(self, value):
        self._set_field_value('field dhcpv6_client', 37, 1, int, value)
    @property
    def ingress_stp_block(self):
        return self._get_field_value(36, 1)
    @ingress_stp_block.setter
    def ingress_stp_block(self, value):
        self._set_field_value('field ingress_stp_block', 36, 1, int, value)
    @property
    def ptp_over_eth(self):
        return self._get_field_value(35, 1)
    @ptp_over_eth.setter
    def ptp_over_eth(self, value):
        self._set_field_value('field ptp_over_eth', 35, 1, int, value)
    @property
    def isis_over_l2(self):
        return self._get_field_value(34, 1)
    @isis_over_l2.setter
    def isis_over_l2(self, value):
        self._set_field_value('field isis_over_l2', 34, 1, int, value)
    @property
    def l2cp0(self):
        return self._get_field_value(33, 1)
    @l2cp0.setter
    def l2cp0(self, value):
        self._set_field_value('field l2cp0', 33, 1, int, value)
    @property
    def l2cp1(self):
        return self._get_field_value(32, 1)
    @l2cp1.setter
    def l2cp1(self, value):
        self._set_field_value('field l2cp1', 32, 1, int, value)
    @property
    def l2cp2(self):
        return self._get_field_value(31, 1)
    @l2cp2.setter
    def l2cp2(self, value):
        self._set_field_value('field l2cp2', 31, 1, int, value)
    @property
    def l2cp3(self):
        return self._get_field_value(30, 1)
    @l2cp3.setter
    def l2cp3(self, value):
        self._set_field_value('field l2cp3', 30, 1, int, value)
    @property
    def l2cp4(self):
        return self._get_field_value(29, 1)
    @l2cp4.setter
    def l2cp4(self, value):
        self._set_field_value('field l2cp4', 29, 1, int, value)
    @property
    def l2cp5(self):
        return self._get_field_value(28, 1)
    @l2cp5.setter
    def l2cp5(self, value):
        self._set_field_value('field l2cp5', 28, 1, int, value)
    @property
    def l2cp6(self):
        return self._get_field_value(27, 1)
    @l2cp6.setter
    def l2cp6(self, value):
        self._set_field_value('field l2cp6', 27, 1, int, value)
    @property
    def l2cp7(self):
        return self._get_field_value(26, 1)
    @l2cp7.setter
    def l2cp7(self, value):
        self._set_field_value('field l2cp7', 26, 1, int, value)
    @property
    def lacp(self):
        return self._get_field_value(25, 1)
    @lacp.setter
    def lacp(self, value):
        self._set_field_value('field lacp', 25, 1, int, value)
    @property
    def cisco_protocols(self):
        return self._get_field_value(24, 1)
    @cisco_protocols.setter
    def cisco_protocols(self, value):
        self._set_field_value('field cisco_protocols', 24, 1, int, value)
    @property
    def macsec(self):
        return self._get_field_value(23, 1)
    @macsec.setter
    def macsec(self, value):
        self._set_field_value('field macsec', 23, 1, int, value)
    @property
    def unknown_l3(self):
        return self._get_field_value(22, 1)
    @unknown_l3.setter
    def unknown_l3(self, value):
        self._set_field_value('field unknown_l3', 22, 1, int, value)
    @property
    def test_oam_ac_mep(self):
        return self._get_field_value(21, 1)
    @test_oam_ac_mep.setter
    def test_oam_ac_mep(self, value):
        self._set_field_value('field test_oam_ac_mep', 21, 1, int, value)
    @property
    def test_oam_ac_mip(self):
        return self._get_field_value(20, 1)
    @test_oam_ac_mip.setter
    def test_oam_ac_mip(self, value):
        self._set_field_value('field test_oam_ac_mip', 20, 1, int, value)
    @property
    def test_oam_cfm_link_mdl0(self):
        return self._get_field_value(19, 1)
    @test_oam_cfm_link_mdl0.setter
    def test_oam_cfm_link_mdl0(self, value):
        self._set_field_value('field test_oam_cfm_link_mdl0', 19, 1, int, value)
    @property
    def system_mymac(self):
        return self._get_field_value(18, 1)
    @system_mymac.setter
    def system_mymac(self, value):
        self._set_field_value('field system_mymac', 18, 1, int, value)
    @property
    def unknown_bc(self):
        return self._get_field_value(17, 1)
    @unknown_bc.setter
    def unknown_bc(self, value):
        self._set_field_value('field unknown_bc', 17, 1, int, value)
    @property
    def unknown_mc(self):
        return self._get_field_value(16, 1)
    @unknown_mc.setter
    def unknown_mc(self, value):
        self._set_field_value('field unknown_mc', 16, 1, int, value)
    @property
    def unknown_uc(self):
        return self._get_field_value(15, 1)
    @unknown_uc.setter
    def unknown_uc(self, value):
        self._set_field_value('field unknown_uc', 15, 1, int, value)
    @property
    def learn_punt(self):
        return self._get_field_value(14, 1)
    @learn_punt.setter
    def learn_punt(self, value):
        self._set_field_value('field learn_punt', 14, 1, int, value)
    @property
    def bcast_pkt(self):
        return self._get_field_value(13, 1)
    @bcast_pkt.setter
    def bcast_pkt(self, value):
        self._set_field_value('field bcast_pkt', 13, 1, int, value)
    @property
    def pfc_sample(self):
        return self._get_field_value(12, 1)
    @pfc_sample.setter
    def pfc_sample(self, value):
        self._set_field_value('field pfc_sample', 12, 1, int, value)
    @property
    def hop_by_hop(self):
        return self._get_field_value(11, 1)
    @hop_by_hop.setter
    def hop_by_hop(self, value):
        self._set_field_value('field hop_by_hop', 11, 1, int, value)
    @property
    def l2_dlp_not_found(self):
        return self._get_field_value(10, 1)
    @l2_dlp_not_found.setter
    def l2_dlp_not_found(self, value):
        self._set_field_value('field l2_dlp_not_found', 10, 1, int, value)
    @property
    def same_interface(self):
        return self._get_field_value(9, 1)
    @same_interface.setter
    def same_interface(self, value):
        self._set_field_value('field same_interface', 9, 1, int, value)
    @property
    def dspa_mc_trim(self):
        return self._get_field_value(8, 1)
    @dspa_mc_trim.setter
    def dspa_mc_trim(self, value):
        self._set_field_value('field dspa_mc_trim', 8, 1, int, value)
    @property
    def egress_stp_block(self):
        return self._get_field_value(7, 1)
    @egress_stp_block.setter
    def egress_stp_block(self, value):
        self._set_field_value('field egress_stp_block', 7, 1, int, value)
    @property
    def split_horizon(self):
        return self._get_field_value(6, 1)
    @split_horizon.setter
    def split_horizon(self, value):
        self._set_field_value('field split_horizon', 6, 1, int, value)
    @property
    def disabled(self):
        return self._get_field_value(5, 1)
    @disabled.setter
    def disabled(self, value):
        self._set_field_value('field disabled', 5, 1, int, value)
    @property
    def incompatible_eve_cmd(self):
        return self._get_field_value(4, 1)
    @incompatible_eve_cmd.setter
    def incompatible_eve_cmd(self, value):
        self._set_field_value('field incompatible_eve_cmd', 4, 1, int, value)
    @property
    def padding_residue_in_second_line(self):
        return self._get_field_value(3, 1)
    @padding_residue_in_second_line.setter
    def padding_residue_in_second_line(self, value):
        self._set_field_value('field padding_residue_in_second_line', 3, 1, int, value)
    @property
    def pfc_direct_sample(self):
        return self._get_field_value(2, 1)
    @pfc_direct_sample.setter
    def pfc_direct_sample(self, value):
        self._set_field_value('field pfc_direct_sample', 2, 1, int, value)
    @property
    def svi_egress_dhcp(self):
        return self._get_field_value(1, 1)
    @svi_egress_dhcp.setter
    def svi_egress_dhcp(self, value):
        self._set_field_value('field svi_egress_dhcp', 1, 1, int, value)
    @property
    def no_pwe_l3_dest(self):
        return self._get_field_value(0, 1)
    @no_pwe_l3_dest.setter
    def no_pwe_l3_dest(self, value):
        self._set_field_value('field no_pwe_l3_dest', 0, 1, int, value)



class npl_event_queue_address_t(basic_npl_struct):
    def __init__(self, address=0):
        super().__init__(10)
        self.address = address

    def _get_as_sub_field(data, offset_in_data):
        result = npl_event_queue_address_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def address(self):
        return self._get_field_value(0, 10)
    @address.setter
    def address(self, value):
        self._set_field_value('field address', 0, 10, int, value)



class npl_event_to_send_t(basic_npl_struct):
    def __init__(self, rmep_last_time=0, rmep_id=0, rmep_state_table_data=0):
        super().__init__(61)
        self.rmep_last_time = rmep_last_time
        self.rmep_id = rmep_id
        self.rmep_state_table_data = rmep_state_table_data

    def _get_as_sub_field(data, offset_in_data):
        result = npl_event_to_send_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rmep_last_time(self):
        return self._get_field_value(29, 32)
    @rmep_last_time.setter
    def rmep_last_time(self, value):
        self._set_field_value('field rmep_last_time', 29, 32, int, value)
    @property
    def rmep_id(self):
        return self._get_field_value(16, 13)
    @rmep_id.setter
    def rmep_id(self, value):
        self._set_field_value('field rmep_id', 16, 13, int, value)
    @property
    def rmep_state_table_data(self):
        return self._get_field_value(0, 16)
    @rmep_state_table_data.setter
    def rmep_state_table_data(self, value):
        self._set_field_value('field rmep_state_table_data', 0, 16, int, value)



class npl_exact_bank_index_len_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(4)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_exact_bank_index_len_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 4)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 4, int, value)



class npl_exact_meter_index_len_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(11)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_exact_meter_index_len_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 11)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 11, int, value)



class npl_exp_and_bos_t(basic_npl_struct):
    def __init__(self, exp=0, bos=0):
        super().__init__(4)
        self.exp = exp
        self.bos = bos

    def _get_as_sub_field(data, offset_in_data):
        result = npl_exp_and_bos_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def exp(self):
        return self._get_field_value(1, 3)
    @exp.setter
    def exp(self, value):
        self._set_field_value('field exp', 1, 3, int, value)
    @property
    def bos(self):
        return self._get_field_value(0, 1)
    @bos.setter
    def bos(self, value):
        self._set_field_value('field bos', 0, 1, int, value)



class npl_exp_bos_and_label_t(basic_npl_struct):
    def __init__(self, label_exp_bos=0, label=0):
        super().__init__(24)
        self.label_exp_bos = label_exp_bos
        self.label = label

    def _get_as_sub_field(data, offset_in_data):
        result = npl_exp_bos_and_label_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def label_exp_bos(self):
        return npl_exp_and_bos_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @label_exp_bos.setter
    def label_exp_bos(self, value):
        self._set_field_value('field label_exp_bos', 20, 4, npl_exp_and_bos_t, value)
    @property
    def label(self):
        return self._get_field_value(0, 20)
    @label.setter
    def label(self, value):
        self._set_field_value('field label', 0, 20, int, value)



class npl_extended_encap_data2_t(basic_npl_struct):
    def __init__(self, ene_ipv6_dip_lsb=0):
        super().__init__(48)
        self.ene_ipv6_dip_lsb = ene_ipv6_dip_lsb

    def _get_as_sub_field(data, offset_in_data):
        result = npl_extended_encap_data2_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ene_ipv6_dip_lsb(self):
        return self._get_field_value(0, 48)
    @ene_ipv6_dip_lsb.setter
    def ene_ipv6_dip_lsb(self, value):
        self._set_field_value('field ene_ipv6_dip_lsb', 0, 48, int, value)



class npl_extended_encap_data_t(basic_npl_struct):
    def __init__(self, ene_ipv6_dip_msb=0):
        super().__init__(80)
        self.ene_ipv6_dip_msb = ene_ipv6_dip_msb

    def _get_as_sub_field(data, offset_in_data):
        result = npl_extended_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ene_ipv6_dip_msb(self):
        return self._get_field_value(0, 80)
    @ene_ipv6_dip_msb.setter
    def ene_ipv6_dip_msb(self, value):
        self._set_field_value('field ene_ipv6_dip_msb', 0, 80, int, value)



class npl_fabric_cfg_t(basic_npl_struct):
    def __init__(self, issu_codespace=0, plb_type=0, device=0):
        super().__init__(11)
        self.issu_codespace = issu_codespace
        self.plb_type = plb_type
        self.device = device

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fabric_cfg_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def issu_codespace(self):
        return self._get_field_value(10, 1)
    @issu_codespace.setter
    def issu_codespace(self, value):
        self._set_field_value('field issu_codespace', 10, 1, int, value)
    @property
    def plb_type(self):
        return self._get_field_value(9, 1)
    @plb_type.setter
    def plb_type(self, value):
        self._set_field_value('field plb_type', 9, 1, int, value)
    @property
    def device(self):
        return self._get_field_value(0, 9)
    @device.setter
    def device(self, value):
        self._set_field_value('field device', 0, 9, int, value)



class npl_fabric_header_ctrl_sn_plb_t(basic_npl_struct):
    def __init__(self, link_fc=0, fcn=0, plb_ctxt=0):
        super().__init__(4)
        self.link_fc = link_fc
        self.fcn = fcn
        self.plb_ctxt = plb_ctxt

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fabric_header_ctrl_sn_plb_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def link_fc(self):
        return self._get_field_value(3, 1)
    @link_fc.setter
    def link_fc(self, value):
        self._set_field_value('field link_fc', 3, 1, int, value)
    @property
    def fcn(self):
        return self._get_field_value(2, 1)
    @fcn.setter
    def fcn(self, value):
        self._set_field_value('field fcn', 2, 1, int, value)
    @property
    def plb_ctxt(self):
        return self._get_field_value(0, 1)
    @plb_ctxt.setter
    def plb_ctxt(self, value):
        self._set_field_value('field plb_ctxt', 0, 1, int, value)



class npl_fabric_header_ctrl_ts_plb_t(basic_npl_struct):
    def __init__(self, link_fc=0, fcn=0, plb_ctxt=0):
        super().__init__(4)
        self.link_fc = link_fc
        self.fcn = fcn
        self.plb_ctxt = plb_ctxt

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fabric_header_ctrl_ts_plb_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def link_fc(self):
        return self._get_field_value(3, 1)
    @link_fc.setter
    def link_fc(self, value):
        self._set_field_value('field link_fc', 3, 1, int, value)
    @property
    def fcn(self):
        return self._get_field_value(2, 1)
    @fcn.setter
    def fcn(self, value):
        self._set_field_value('field fcn', 2, 1, int, value)
    @property
    def plb_ctxt(self):
        return self._get_field_value(0, 2)
    @plb_ctxt.setter
    def plb_ctxt(self, value):
        self._set_field_value('field plb_ctxt', 0, 2, int, value)



class npl_fabric_header_start_template_t_anonymous_union_ctrl_t(basic_npl_struct):
    def __init__(self):
        super().__init__(4)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_fabric_header_start_template_t_anonymous_union_ctrl_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ts_plb(self):
        return npl_fabric_header_ctrl_ts_plb_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ts_plb.setter
    def ts_plb(self, value):
        self._set_field_value('field ts_plb', 0, 4, npl_fabric_header_ctrl_ts_plb_t, value)
    @property
    def sn_plb(self):
        return npl_fabric_header_ctrl_sn_plb_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @sn_plb.setter
    def sn_plb(self, value):
        self._set_field_value('field sn_plb', 0, 4, npl_fabric_header_ctrl_sn_plb_t, value)



class npl_fabric_ibm_cmd_t(basic_npl_struct):
    def __init__(self, ibm_cmd_padding=0, ibm_cmd=0):
        super().__init__(8)
        self.ibm_cmd_padding = ibm_cmd_padding
        self.ibm_cmd = ibm_cmd

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fabric_ibm_cmd_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ibm_cmd_padding(self):
        return self._get_field_value(5, 3)
    @ibm_cmd_padding.setter
    def ibm_cmd_padding(self, value):
        self._set_field_value('field ibm_cmd_padding', 5, 3, int, value)
    @property
    def ibm_cmd(self):
        return self._get_field_value(0, 5)
    @ibm_cmd.setter
    def ibm_cmd(self, value):
        self._set_field_value('field ibm_cmd', 0, 5, int, value)



class npl_fabric_mc_ibm_cmd_t(basic_npl_struct):
    def __init__(self, fabric_mc_encapsulation_type=0, fabric_mc_ibm_cmd_padding=0, fabric_mc_ibm_cmd=0, fabric_mc_ibm_cmd_src=0):
        super().__init__(24)
        self.fabric_mc_encapsulation_type = fabric_mc_encapsulation_type
        self.fabric_mc_ibm_cmd_padding = fabric_mc_ibm_cmd_padding
        self.fabric_mc_ibm_cmd = fabric_mc_ibm_cmd
        self.fabric_mc_ibm_cmd_src = fabric_mc_ibm_cmd_src

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fabric_mc_ibm_cmd_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def fabric_mc_encapsulation_type(self):
        return self._get_field_value(20, 4)
    @fabric_mc_encapsulation_type.setter
    def fabric_mc_encapsulation_type(self, value):
        self._set_field_value('field fabric_mc_encapsulation_type', 20, 4, int, value)
    @property
    def fabric_mc_ibm_cmd_padding(self):
        return self._get_field_value(17, 3)
    @fabric_mc_ibm_cmd_padding.setter
    def fabric_mc_ibm_cmd_padding(self, value):
        self._set_field_value('field fabric_mc_ibm_cmd_padding', 17, 3, int, value)
    @property
    def fabric_mc_ibm_cmd(self):
        return self._get_field_value(12, 5)
    @fabric_mc_ibm_cmd.setter
    def fabric_mc_ibm_cmd(self, value):
        self._set_field_value('field fabric_mc_ibm_cmd', 12, 5, int, value)
    @property
    def fabric_mc_ibm_cmd_src(self):
        return self._get_field_value(8, 4)
    @fabric_mc_ibm_cmd_src.setter
    def fabric_mc_ibm_cmd_src(self, value):
        self._set_field_value('field fabric_mc_ibm_cmd_src', 8, 4, int, value)



class npl_fb_link_2_link_bundle_table_result_t(basic_npl_struct):
    def __init__(self, bundle_num=0):
        super().__init__(6)
        self.bundle_num = bundle_num

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fb_link_2_link_bundle_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def bundle_num(self):
        return self._get_field_value(0, 6)
    @bundle_num.setter
    def bundle_num(self, value):
        self._set_field_value('field bundle_num', 0, 6, int, value)



class npl_fe_broadcast_bmp_table_result_t(basic_npl_struct):
    def __init__(self, links_bmp=0):
        super().__init__(108)
        self.links_bmp = links_bmp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fe_broadcast_bmp_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def links_bmp(self):
        return self._get_field_value(0, 108)
    @links_bmp.setter
    def links_bmp(self, value):
        self._set_field_value('field links_bmp', 0, 108, int, value)



class npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t(basic_npl_struct):
    def __init__(self, base_oq=0):
        super().__init__(9)
        self.base_oq = base_oq

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def base_oq(self):
        return self._get_field_value(0, 9)
    @base_oq.setter
    def base_oq(self, value):
        self._set_field_value('field base_oq', 0, 9, int, value)



class npl_fe_uc_bundle_selected_link_t(basic_npl_struct):
    def __init__(self, bundle_link=0):
        super().__init__(7)
        self.bundle_link = bundle_link

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fe_uc_bundle_selected_link_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def bundle_link(self):
        return self._get_field_value(0, 7)
    @bundle_link.setter
    def bundle_link(self, value):
        self._set_field_value('field bundle_link', 0, 7, int, value)



class npl_fe_uc_link_bundle_desc_table_result_t(basic_npl_struct):
    def __init__(self, bundle_link_3_bc=0, bundle_link_3=0, bundle_link_2_bc=0, bundle_link_2=0, bundle_link_1_bc=0, bundle_link_1=0, bundle_link_0_bc=0, bundle_link_0=0):
        super().__init__(88)
        self.bundle_link_3_bc = bundle_link_3_bc
        self.bundle_link_3 = bundle_link_3
        self.bundle_link_2_bc = bundle_link_2_bc
        self.bundle_link_2 = bundle_link_2
        self.bundle_link_1_bc = bundle_link_1_bc
        self.bundle_link_1 = bundle_link_1
        self.bundle_link_0_bc = bundle_link_0_bc
        self.bundle_link_0 = bundle_link_0

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fe_uc_link_bundle_desc_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def bundle_link_3_bc(self):
        return self._get_field_value(73, 15)
    @bundle_link_3_bc.setter
    def bundle_link_3_bc(self, value):
        self._set_field_value('field bundle_link_3_bc', 73, 15, int, value)
    @property
    def bundle_link_3(self):
        return self._get_field_value(66, 7)
    @bundle_link_3.setter
    def bundle_link_3(self, value):
        self._set_field_value('field bundle_link_3', 66, 7, int, value)
    @property
    def bundle_link_2_bc(self):
        return self._get_field_value(51, 15)
    @bundle_link_2_bc.setter
    def bundle_link_2_bc(self, value):
        self._set_field_value('field bundle_link_2_bc', 51, 15, int, value)
    @property
    def bundle_link_2(self):
        return self._get_field_value(44, 7)
    @bundle_link_2.setter
    def bundle_link_2(self, value):
        self._set_field_value('field bundle_link_2', 44, 7, int, value)
    @property
    def bundle_link_1_bc(self):
        return self._get_field_value(29, 15)
    @bundle_link_1_bc.setter
    def bundle_link_1_bc(self, value):
        self._set_field_value('field bundle_link_1_bc', 29, 15, int, value)
    @property
    def bundle_link_1(self):
        return self._get_field_value(22, 7)
    @bundle_link_1.setter
    def bundle_link_1(self, value):
        self._set_field_value('field bundle_link_1', 22, 7, int, value)
    @property
    def bundle_link_0_bc(self):
        return self._get_field_value(7, 15)
    @bundle_link_0_bc.setter
    def bundle_link_0_bc(self, value):
        self._set_field_value('field bundle_link_0_bc', 7, 15, int, value)
    @property
    def bundle_link_0(self):
        return self._get_field_value(0, 7)
    @bundle_link_0.setter
    def bundle_link_0(self, value):
        self._set_field_value('field bundle_link_0', 0, 7, int, value)



class npl_fe_uc_random_fb_link_t(basic_npl_struct):
    def __init__(self, link_num=0):
        super().__init__(7)
        self.link_num = link_num

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fe_uc_random_fb_link_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def link_num(self):
        return self._get_field_value(0, 7)
    @link_num.setter
    def link_num(self, value):
        self._set_field_value('field link_num', 0, 7, int, value)



class npl_fec_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(12)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fec_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 12)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 12, int, value)



class npl_fi_macro_config_data_t(basic_npl_struct):
    def __init__(self, tcam_key_inst1_offset=0, tcam_key_inst1_width=0, tcam_key_inst0_offset=0, tcam_key_inst0_width=0, alu_shift2=0, alu_shift1=0, hw_logic_select=0, alu_mux2_select=0, alu_mux1_select=0, fs2_const=0, fs1_const=0, alu_fs2_valid_bits=0, alu_fs2_offset=0, alu_fs1_valid_bits=0, alu_fs1_offset=0):
        super().__init__(72)
        self.tcam_key_inst1_offset = tcam_key_inst1_offset
        self.tcam_key_inst1_width = tcam_key_inst1_width
        self.tcam_key_inst0_offset = tcam_key_inst0_offset
        self.tcam_key_inst0_width = tcam_key_inst0_width
        self.alu_shift2 = alu_shift2
        self.alu_shift1 = alu_shift1
        self.hw_logic_select = hw_logic_select
        self.alu_mux2_select = alu_mux2_select
        self.alu_mux1_select = alu_mux1_select
        self.fs2_const = fs2_const
        self.fs1_const = fs1_const
        self.alu_fs2_valid_bits = alu_fs2_valid_bits
        self.alu_fs2_offset = alu_fs2_offset
        self.alu_fs1_valid_bits = alu_fs1_valid_bits
        self.alu_fs1_offset = alu_fs1_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fi_macro_config_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tcam_key_inst1_offset(self):
        return self._get_field_value(67, 5)
    @tcam_key_inst1_offset.setter
    def tcam_key_inst1_offset(self, value):
        self._set_field_value('field tcam_key_inst1_offset', 67, 5, int, value)
    @property
    def tcam_key_inst1_width(self):
        return self._get_field_value(61, 6)
    @tcam_key_inst1_width.setter
    def tcam_key_inst1_width(self, value):
        self._set_field_value('field tcam_key_inst1_width', 61, 6, int, value)
    @property
    def tcam_key_inst0_offset(self):
        return self._get_field_value(55, 6)
    @tcam_key_inst0_offset.setter
    def tcam_key_inst0_offset(self, value):
        self._set_field_value('field tcam_key_inst0_offset', 55, 6, int, value)
    @property
    def tcam_key_inst0_width(self):
        return self._get_field_value(50, 5)
    @tcam_key_inst0_width.setter
    def tcam_key_inst0_width(self, value):
        self._set_field_value('field tcam_key_inst0_width', 50, 5, int, value)
    @property
    def alu_shift2(self):
        return self._get_field_value(45, 5)
    @alu_shift2.setter
    def alu_shift2(self, value):
        self._set_field_value('field alu_shift2', 45, 5, int, value)
    @property
    def alu_shift1(self):
        return self._get_field_value(41, 4)
    @alu_shift1.setter
    def alu_shift1(self, value):
        self._set_field_value('field alu_shift1', 41, 4, int, value)
    @property
    def hw_logic_select(self):
        return self._get_field_value(38, 3)
    @hw_logic_select.setter
    def hw_logic_select(self, value):
        self._set_field_value('field hw_logic_select', 38, 3, int, value)
    @property
    def alu_mux2_select(self):
        return self._get_field_value(37, 1)
    @alu_mux2_select.setter
    def alu_mux2_select(self, value):
        self._set_field_value('field alu_mux2_select', 37, 1, int, value)
    @property
    def alu_mux1_select(self):
        return self._get_field_value(36, 1)
    @alu_mux1_select.setter
    def alu_mux1_select(self, value):
        self._set_field_value('field alu_mux1_select', 36, 1, int, value)
    @property
    def fs2_const(self):
        return self._get_field_value(28, 8)
    @fs2_const.setter
    def fs2_const(self, value):
        self._set_field_value('field fs2_const', 28, 8, int, value)
    @property
    def fs1_const(self):
        return self._get_field_value(20, 8)
    @fs1_const.setter
    def fs1_const(self, value):
        self._set_field_value('field fs1_const', 20, 8, int, value)
    @property
    def alu_fs2_valid_bits(self):
        return self._get_field_value(16, 4)
    @alu_fs2_valid_bits.setter
    def alu_fs2_valid_bits(self, value):
        self._set_field_value('field alu_fs2_valid_bits', 16, 4, int, value)
    @property
    def alu_fs2_offset(self):
        return self._get_field_value(10, 6)
    @alu_fs2_offset.setter
    def alu_fs2_offset(self, value):
        self._set_field_value('field alu_fs2_offset', 10, 6, int, value)
    @property
    def alu_fs1_valid_bits(self):
        return self._get_field_value(6, 4)
    @alu_fs1_valid_bits.setter
    def alu_fs1_valid_bits(self, value):
        self._set_field_value('field alu_fs1_valid_bits', 6, 4, int, value)
    @property
    def alu_fs1_offset(self):
        return self._get_field_value(0, 6)
    @alu_fs1_offset.setter
    def alu_fs1_offset(self, value):
        self._set_field_value('field alu_fs1_offset', 0, 6, int, value)



class npl_filb_voq_mapping_result_t(basic_npl_struct):
    def __init__(self, packing_eligible=0, snr_plb_ss2dd=0, dest_oq=0, dest_slice=0, dest_dev=0):
        super().__init__(26)
        self.packing_eligible = packing_eligible
        self.snr_plb_ss2dd = snr_plb_ss2dd
        self.dest_oq = dest_oq
        self.dest_slice = dest_slice
        self.dest_dev = dest_dev

    def _get_as_sub_field(data, offset_in_data):
        result = npl_filb_voq_mapping_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def packing_eligible(self):
        return self._get_field_value(25, 1)
    @packing_eligible.setter
    def packing_eligible(self, value):
        self._set_field_value('field packing_eligible', 25, 1, int, value)
    @property
    def snr_plb_ss2dd(self):
        return self._get_field_value(21, 4)
    @snr_plb_ss2dd.setter
    def snr_plb_ss2dd(self, value):
        self._set_field_value('field snr_plb_ss2dd', 21, 4, int, value)
    @property
    def dest_oq(self):
        return self._get_field_value(12, 9)
    @dest_oq.setter
    def dest_oq(self, value):
        self._set_field_value('field dest_oq', 12, 9, int, value)
    @property
    def dest_slice(self):
        return self._get_field_value(9, 3)
    @dest_slice.setter
    def dest_slice(self, value):
        self._set_field_value('field dest_slice', 9, 3, int, value)
    @property
    def dest_dev(self):
        return self._get_field_value(0, 9)
    @dest_dev.setter
    def dest_dev(self, value):
        self._set_field_value('field dest_dev', 0, 9, int, value)



class npl_frm_db_fabric_routing_table_result_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(108)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_frm_db_fabric_routing_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def fabric_routing_table_data(self):
        return basic_npl_array(108, 108, int, self._data, self._offset_in_data + 0)
    @fabric_routing_table_data.setter
    def fabric_routing_table_data(self, value):
        field = basic_npl_array(108, 108, int, self._data, self._offset_in_data + 0)
        field._set_field_value('field fabric_routing_table_data', 0, 108, basic_npl_array, value)



class npl_frr_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(8)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_frr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 8)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 8, int, value)



class npl_fwd_class_qos_group_t(basic_npl_struct):
    def __init__(self, fwd_class=0, qos_group=0):
        super().__init__(8)
        self.fwd_class = fwd_class
        self.qos_group = qos_group

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fwd_class_qos_group_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def fwd_class(self):
        return self._get_field_value(5, 3)
    @fwd_class.setter
    def fwd_class(self, value):
        self._set_field_value('field fwd_class', 5, 3, int, value)
    @property
    def qos_group(self):
        return self._get_field_value(0, 5)
    @qos_group.setter
    def qos_group(self, value):
        self._set_field_value('field qos_group', 0, 5, int, value)



class npl_fwd_layer_and_rtf_stage_compressed_fields_t(basic_npl_struct):
    def __init__(self, fwd_layer=0, rtf_stage=0):
        super().__init__(3)
        self.fwd_layer = fwd_layer
        self.rtf_stage = rtf_stage

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fwd_layer_and_rtf_stage_compressed_fields_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def fwd_layer(self):
        return self._get_field_value(2, 1)
    @fwd_layer.setter
    def fwd_layer(self, value):
        self._set_field_value('field fwd_layer', 2, 1, int, value)
    @property
    def rtf_stage(self):
        return self._get_field_value(0, 2)
    @rtf_stage.setter
    def rtf_stage(self, value):
        self._set_field_value('field rtf_stage', 0, 2, int, value)



class npl_fwd_qos_tag_dscp_t(basic_npl_struct):
    def __init__(self, dscp=0):
        super().__init__(7)
        self.dscp = dscp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fwd_qos_tag_dscp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dscp(self):
        return self._get_field_value(0, 6)
    @dscp.setter
    def dscp(self, value):
        self._set_field_value('field dscp', 0, 6, int, value)



class npl_fwd_qos_tag_exp_or_qosgroup_t(basic_npl_struct):
    def __init__(self, exp_or_qos_group=0):
        super().__init__(7)
        self.exp_or_qos_group = exp_or_qos_group

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fwd_qos_tag_exp_or_qosgroup_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def exp_or_qos_group(self):
        return self._get_field_value(0, 5)
    @exp_or_qos_group.setter
    def exp_or_qos_group(self, value):
        self._set_field_value('field exp_or_qos_group', 0, 5, int, value)



class npl_fwd_qos_tag_group_t(basic_npl_struct):
    def __init__(self, qos_group_id=0):
        super().__init__(7)
        self.qos_group_id = qos_group_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fwd_qos_tag_group_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def qos_group_id(self):
        return self._get_field_value(0, 5)
    @qos_group_id.setter
    def qos_group_id(self, value):
        self._set_field_value('field qos_group_id', 0, 5, int, value)



class npl_fwd_qos_tag_pcpdei_or_qosgroup_t(basic_npl_struct):
    def __init__(self, pcp_dei_or_qos_group=0):
        super().__init__(7)
        self.pcp_dei_or_qos_group = pcp_dei_or_qos_group

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fwd_qos_tag_pcpdei_or_qosgroup_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def pcp_dei_or_qos_group(self):
        return self._get_field_value(0, 5)
    @pcp_dei_or_qos_group.setter
    def pcp_dei_or_qos_group(self, value):
        self._set_field_value('field pcp_dei_or_qos_group', 0, 5, int, value)



class npl_fwd_qos_tag_t(basic_npl_struct):
    def __init__(self):
        super().__init__(7)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_fwd_qos_tag_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2(self):
        return npl_fwd_qos_tag_pcpdei_or_qosgroup_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2.setter
    def l2(self, value):
        self._set_field_value('field l2', 0, 7, npl_fwd_qos_tag_pcpdei_or_qosgroup_t, value)
    @property
    def l3(self):
        return npl_fwd_qos_tag_dscp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3.setter
    def l3(self, value):
        self._set_field_value('field l3', 0, 7, npl_fwd_qos_tag_dscp_t, value)
    @property
    def mpls(self):
        return npl_fwd_qos_tag_exp_or_qosgroup_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mpls.setter
    def mpls(self, value):
        self._set_field_value('field mpls', 0, 7, npl_fwd_qos_tag_exp_or_qosgroup_t, value)
    @property
    def group(self):
        return npl_fwd_qos_tag_group_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @group.setter
    def group(self, value):
        self._set_field_value('field group', 0, 7, npl_fwd_qos_tag_group_t, value)



class npl_g_ifg_len_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(4)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_g_ifg_len_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 4)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 4, int, value)



class npl_gre_encap_data_t(basic_npl_struct):
    def __init__(self, flag_res_version=0, proto=0):
        super().__init__(32)
        self.flag_res_version = flag_res_version
        self.proto = proto

    def _get_as_sub_field(data, offset_in_data):
        result = npl_gre_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def flag_res_version(self):
        return self._get_field_value(16, 16)
    @flag_res_version.setter
    def flag_res_version(self, value):
        self._set_field_value('field flag_res_version', 16, 16, int, value)
    @property
    def proto(self):
        return self._get_field_value(0, 16)
    @proto.setter
    def proto(self, value):
        self._set_field_value('field proto', 0, 16, int, value)



class npl_hmc_cgm_cgm_lut_results_t(basic_npl_struct):
    def __init__(self, dp1=0, dp0=0, mark=0):
        super().__init__(3)
        self.dp1 = dp1
        self.dp0 = dp0
        self.mark = mark

    def _get_as_sub_field(data, offset_in_data):
        result = npl_hmc_cgm_cgm_lut_results_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dp1(self):
        return self._get_field_value(2, 1)
    @dp1.setter
    def dp1(self, value):
        self._set_field_value('field dp1', 2, 1, int, value)
    @property
    def dp0(self):
        return self._get_field_value(1, 1)
    @dp0.setter
    def dp0(self, value):
        self._set_field_value('field dp0', 1, 1, int, value)
    @property
    def mark(self):
        return self._get_field_value(0, 1)
    @mark.setter
    def mark(self, value):
        self._set_field_value('field mark', 0, 1, int, value)



class npl_hw_mp_table_app_t(basic_npl_struct):
    def __init__(self, lm_count_phase_lsb=0, lm_period=0, ccm_count_phase_msb=0):
        super().__init__(16)
        self.lm_count_phase_lsb = lm_count_phase_lsb
        self.lm_period = lm_period
        self.ccm_count_phase_msb = ccm_count_phase_msb

    def _get_as_sub_field(data, offset_in_data):
        result = npl_hw_mp_table_app_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lm_count_phase_lsb(self):
        return self._get_field_value(14, 2)
    @lm_count_phase_lsb.setter
    def lm_count_phase_lsb(self, value):
        self._set_field_value('field lm_count_phase_lsb', 14, 2, int, value)
    @property
    def lm_period(self):
        return self._get_field_value(11, 3)
    @lm_period.setter
    def lm_period(self, value):
        self._set_field_value('field lm_period', 11, 3, int, value)
    @property
    def ccm_count_phase_msb(self):
        return self._get_field_value(0, 11)
    @ccm_count_phase_msb.setter
    def ccm_count_phase_msb(self, value):
        self._set_field_value('field ccm_count_phase_msb', 0, 11, int, value)



class npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t(basic_npl_struct):
    def __init__(self):
        super().__init__(16)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def base_voq(self):
        return self._get_field_value(0, 16)
    @base_voq.setter
    def base_voq(self, value):
        self._set_field_value('field base_voq', 0, 16, int, value)
    @property
    def mc_bitmap(self):
        return self._get_field_value(0, 6)
    @mc_bitmap.setter
    def mc_bitmap(self, value):
        self._set_field_value('field mc_bitmap', 0, 6, int, value)



class npl_ibm_enables_table_result_t(basic_npl_struct):
    def __init__(self, ibm_partial_mirror_packet_size=0, ibm_partial_mirror_en=0, ibm_enable_ive=0, ibm_enable_hw_termination=0, cud_ibm_offset=0, cud_has_ibm=0):
        super().__init__(159)
        self.ibm_partial_mirror_packet_size = ibm_partial_mirror_packet_size
        self.ibm_partial_mirror_en = ibm_partial_mirror_en
        self.ibm_enable_ive = ibm_enable_ive
        self.ibm_enable_hw_termination = ibm_enable_hw_termination
        self.cud_ibm_offset = cud_ibm_offset
        self.cud_has_ibm = cud_has_ibm

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ibm_enables_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ibm_partial_mirror_packet_size(self):
        return self._get_field_value(145, 14)
    @ibm_partial_mirror_packet_size.setter
    def ibm_partial_mirror_packet_size(self, value):
        self._set_field_value('field ibm_partial_mirror_packet_size', 145, 14, int, value)
    @property
    def ibm_partial_mirror_en(self):
        return self._get_field_value(113, 32)
    @ibm_partial_mirror_en.setter
    def ibm_partial_mirror_en(self, value):
        self._set_field_value('field ibm_partial_mirror_en', 113, 32, int, value)
    @property
    def ibm_enable_ive(self):
        return self._get_field_value(81, 32)
    @ibm_enable_ive.setter
    def ibm_enable_ive(self, value):
        self._set_field_value('field ibm_enable_ive', 81, 32, int, value)
    @property
    def ibm_enable_hw_termination(self):
        return self._get_field_value(49, 32)
    @ibm_enable_hw_termination.setter
    def ibm_enable_hw_termination(self, value):
        self._set_field_value('field ibm_enable_hw_termination', 49, 32, int, value)
    @property
    def cud_ibm_offset(self):
        return self._get_field_value(9, 40)
    @cud_ibm_offset.setter
    def cud_ibm_offset(self, value):
        self._set_field_value('field cud_ibm_offset', 9, 40, int, value)
    @property
    def cud_has_ibm(self):
        return self._get_field_value(0, 9)
    @cud_has_ibm.setter
    def cud_has_ibm(self, value):
        self._set_field_value('field cud_has_ibm', 0, 9, int, value)



class npl_icmp_type_code_t(basic_npl_struct):
    def __init__(self, type=0, code=0):
        super().__init__(16)
        self.type = type
        self.code = code

    def _get_as_sub_field(data, offset_in_data):
        result = npl_icmp_type_code_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def type(self):
        return self._get_field_value(8, 8)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 8, 8, int, value)
    @property
    def code(self):
        return self._get_field_value(0, 8)
    @code.setter
    def code(self, value):
        self._set_field_value('field code', 0, 8, int, value)



class npl_ifg_len_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(1)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ifg_len_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 1)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 1, int, value)



class npl_ifg_t(basic_npl_struct):
    def __init__(self, index=0):
        super().__init__(1)
        self.index = index

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ifg_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def index(self):
        return self._get_field_value(0, 1)
    @index.setter
    def index(self, value):
        self._set_field_value('field index', 0, 1, int, value)



class npl_ifgb_tc_lut_results_t(basic_npl_struct):
    def __init__(self, use_lut=0, data=0):
        super().__init__(6)
        self.use_lut = use_lut
        self.data = data

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ifgb_tc_lut_results_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def use_lut(self):
        return self._get_field_value(5, 1)
    @use_lut.setter
    def use_lut(self, value):
        self._set_field_value('field use_lut', 5, 1, int, value)
    @property
    def data(self):
        return self._get_field_value(0, 5)
    @data.setter
    def data(self, value):
        self._set_field_value('field data', 0, 5, int, value)



class npl_ingress_lpts_og_app_data_t(basic_npl_struct):
    def __init__(self, lpts_og_app_id=0):
        super().__init__(5)
        self.lpts_og_app_id = lpts_og_app_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ingress_lpts_og_app_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lpts_og_app_id(self):
        return self._get_field_value(0, 4)
    @lpts_og_app_id.setter
    def lpts_og_app_id(self, value):
        self._set_field_value('field lpts_og_app_id', 0, 4, int, value)



class npl_ingress_ptp_info_t(basic_npl_struct):
    def __init__(self, ptp_transport_type=0, is_ptp_trans_sup=0):
        super().__init__(3)
        self.ptp_transport_type = ptp_transport_type
        self.is_ptp_trans_sup = is_ptp_trans_sup

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ingress_ptp_info_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ptp_transport_type(self):
        return self._get_field_value(1, 2)
    @ptp_transport_type.setter
    def ptp_transport_type(self, value):
        self._set_field_value('field ptp_transport_type', 1, 2, int, value)
    @property
    def is_ptp_trans_sup(self):
        return self._get_field_value(0, 1)
    @is_ptp_trans_sup.setter
    def is_ptp_trans_sup(self, value):
        self._set_field_value('field is_ptp_trans_sup', 0, 1, int, value)



class npl_ingress_qos_mapping_remark_t(basic_npl_struct):
    def __init__(self, qos_group=0, encap_mpls_exp=0, enable_ingress_remark=0, fwd_qos_tag=0):
        super().__init__(19)
        self.qos_group = qos_group
        self.encap_mpls_exp = encap_mpls_exp
        self.enable_ingress_remark = enable_ingress_remark
        self.fwd_qos_tag = fwd_qos_tag

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ingress_qos_mapping_remark_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def qos_group(self):
        return self._get_field_value(12, 7)
    @qos_group.setter
    def qos_group(self, value):
        self._set_field_value('field qos_group', 12, 7, int, value)
    @property
    def encap_mpls_exp(self):
        return npl_encap_mpls_exp_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @encap_mpls_exp.setter
    def encap_mpls_exp(self, value):
        self._set_field_value('field encap_mpls_exp', 8, 4, npl_encap_mpls_exp_t, value)
    @property
    def enable_ingress_remark(self):
        return self._get_field_value(7, 1)
    @enable_ingress_remark.setter
    def enable_ingress_remark(self, value):
        self._set_field_value('field enable_ingress_remark', 7, 1, int, value)
    @property
    def fwd_qos_tag(self):
        return self._get_field_value(0, 7)
    @fwd_qos_tag.setter
    def fwd_qos_tag(self, value):
        self._set_field_value('field fwd_qos_tag', 0, 7, int, value)



class npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t(basic_npl_struct):
    def __init__(self):
        super().__init__(8)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def fwd_class_qos_group(self):
        return npl_fwd_class_qos_group_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @fwd_class_qos_group.setter
    def fwd_class_qos_group(self, value):
        self._set_field_value('field fwd_class_qos_group', 0, 8, npl_fwd_class_qos_group_t, value)
    @property
    def qos_group_pd(self):
        return self._get_field_value(0, 7)
    @qos_group_pd.setter
    def qos_group_pd(self, value):
        self._set_field_value('field qos_group_pd', 0, 7, int, value)



class npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t(basic_npl_struct):
    def __init__(self):
        super().__init__(8)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def initial_npp_attributes_index(self):
        return self._get_field_value(0, 8)
    @initial_npp_attributes_index.setter
    def initial_npp_attributes_index(self, value):
        self._set_field_value('field initial_npp_attributes_index', 0, 8, int, value)
    @property
    def initial_slice_id(self):
        return self._get_field_value(0, 3)
    @initial_slice_id.setter
    def initial_slice_id(self, value):
        self._set_field_value('field initial_slice_id', 0, 3, int, value)



class npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t(basic_npl_struct):
    def __init__(self):
        super().__init__(8)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def initial_npp_attributes_index(self):
        return self._get_field_value(0, 8)
    @initial_npp_attributes_index.setter
    def initial_npp_attributes_index(self, value):
        self._set_field_value('field initial_npp_attributes_index', 0, 8, int, value)
    @property
    def initial_slice_id(self):
        return self._get_field_value(0, 3)
    @initial_slice_id.setter
    def initial_slice_id(self, value):
        self._set_field_value('field initial_slice_id', 0, 3, int, value)



class npl_inject_header_type_t(basic_npl_struct):
    def __init__(self, inject_type=0):
        super().__init__(8)
        self.inject_type = inject_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_header_type_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inject_type(self):
        return self._get_field_value(0, 8)
    @inject_type.setter
    def inject_type(self, value):
        self._set_field_value('field inject_type', 0, 8, int, value)



class npl_inject_source_if_t(basic_npl_struct):
    def __init__(self, inject_ifg=0, inject_pif=0):
        super().__init__(8)
        self.inject_ifg = inject_ifg
        self.inject_pif = inject_pif

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_source_if_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inject_ifg(self):
        return self._get_field_value(7, 1)
    @inject_ifg.setter
    def inject_ifg(self, value):
        self._set_field_value('field inject_ifg', 7, 1, int, value)
    @property
    def inject_pif(self):
        return self._get_field_value(2, 5)
    @inject_pif.setter
    def inject_pif(self, value):
        self._set_field_value('field inject_pif', 2, 5, int, value)



class npl_inject_up_destination_override_t(basic_npl_struct):
    def __init__(self, dest_override=0):
        super().__init__(24)
        self.dest_override = dest_override

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_up_destination_override_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dest_override(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dest_override.setter
    def dest_override(self, value):
        self._set_field_value('field dest_override', 0, 20, npl_destination_t, value)



class npl_inject_up_eth_header_t_anonymous_union_from_port_t(basic_npl_struct):
    def __init__(self):
        super().__init__(12)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_up_eth_header_t_anonymous_union_from_port_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def up_ssp(self):
        return self._get_field_value(0, 12)
    @up_ssp.setter
    def up_ssp(self, value):
        self._set_field_value('field up_ssp', 0, 12, int, value)
    @property
    def up_source_if(self):
        return npl_inject_source_if_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @up_source_if.setter
    def up_source_if(self, value):
        self._set_field_value('field up_source_if', 4, 8, npl_inject_source_if_t, value)



class npl_inject_up_none_routable_mc_lpts_t(basic_npl_struct):
    def __init__(self, placeholder=0):
        super().__init__(20)
        self.placeholder = placeholder

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_up_none_routable_mc_lpts_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def placeholder(self):
        return self._get_field_value(0, 20)
    @placeholder.setter
    def placeholder(self, value):
        self._set_field_value('field placeholder', 0, 20, int, value)



class npl_inject_up_vxlan_mc_t(basic_npl_struct):
    def __init__(self, placeholder=0):
        super().__init__(28)
        self.placeholder = placeholder

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_up_vxlan_mc_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def placeholder(self):
        return self._get_field_value(0, 28)
    @placeholder.setter
    def placeholder(self, value):
        self._set_field_value('field placeholder', 0, 28, int, value)



class npl_internal_traps_t(basic_npl_struct):
    def __init__(self, l3_lpm_lpts=0, ipv4_non_routable_mc_routing=0, ipv4_non_routable_mc_bridging=0, ipv6_non_routable_mc_routing=0, ipv6_non_routable_mc_bridging=0):
        super().__init__(5)
        self.l3_lpm_lpts = l3_lpm_lpts
        self.ipv4_non_routable_mc_routing = ipv4_non_routable_mc_routing
        self.ipv4_non_routable_mc_bridging = ipv4_non_routable_mc_bridging
        self.ipv6_non_routable_mc_routing = ipv6_non_routable_mc_routing
        self.ipv6_non_routable_mc_bridging = ipv6_non_routable_mc_bridging

    def _get_as_sub_field(data, offset_in_data):
        result = npl_internal_traps_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_lpm_lpts(self):
        return self._get_field_value(4, 1)
    @l3_lpm_lpts.setter
    def l3_lpm_lpts(self, value):
        self._set_field_value('field l3_lpm_lpts', 4, 1, int, value)
    @property
    def ipv4_non_routable_mc_routing(self):
        return self._get_field_value(3, 1)
    @ipv4_non_routable_mc_routing.setter
    def ipv4_non_routable_mc_routing(self, value):
        self._set_field_value('field ipv4_non_routable_mc_routing', 3, 1, int, value)
    @property
    def ipv4_non_routable_mc_bridging(self):
        return self._get_field_value(2, 1)
    @ipv4_non_routable_mc_bridging.setter
    def ipv4_non_routable_mc_bridging(self, value):
        self._set_field_value('field ipv4_non_routable_mc_bridging', 2, 1, int, value)
    @property
    def ipv6_non_routable_mc_routing(self):
        return self._get_field_value(1, 1)
    @ipv6_non_routable_mc_routing.setter
    def ipv6_non_routable_mc_routing(self, value):
        self._set_field_value('field ipv6_non_routable_mc_routing', 1, 1, int, value)
    @property
    def ipv6_non_routable_mc_bridging(self):
        return self._get_field_value(0, 1)
    @ipv6_non_routable_mc_bridging.setter
    def ipv6_non_routable_mc_bridging(self, value):
        self._set_field_value('field ipv6_non_routable_mc_bridging', 0, 1, int, value)



class npl_invert_crc_and_context_id_local_var_t(basic_npl_struct):
    def __init__(self, inver_crc=0, context_id_bit_8=0):
        super().__init__(2)
        self.inver_crc = inver_crc
        self.context_id_bit_8 = context_id_bit_8

    def _get_as_sub_field(data, offset_in_data):
        result = npl_invert_crc_and_context_id_local_var_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inver_crc(self):
        return self._get_field_value(1, 1)
    @inver_crc.setter
    def inver_crc(self, value):
        self._set_field_value('field inver_crc', 1, 1, int, value)
    @property
    def context_id_bit_8(self):
        return self._get_field_value(0, 1)
    @context_id_bit_8.setter
    def context_id_bit_8(self, value):
        self._set_field_value('field context_id_bit_8', 0, 1, int, value)



class npl_ip_lpm_result_t_anonymous_union_destination_or_default_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_lpm_result_t_anonymous_union_destination_or_default_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 20, npl_destination_t, value)
    @property
    def is_default(self):
        return self._get_field_value(19, 1)
    @is_default.setter
    def is_default(self, value):
        self._set_field_value('field is_default', 19, 1, int, value)



class npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t(basic_npl_struct):
    def __init__(self):
        super().__init__(2)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rtype(self):
        return self._get_field_value(0, 2)
    @rtype.setter
    def rtype(self, value):
        self._set_field_value('field rtype', 0, 2, int, value)
    @property
    def is_fec(self):
        return self._get_field_value(0, 1)
    @is_fec.setter
    def is_fec(self, value):
        self._set_field_value('field is_fec', 0, 1, int, value)



class npl_ip_prefix_destination_compound_results_t(basic_npl_struct):
    def __init__(self, ip_prefix_destination=0):
        super().__init__(20)
        self.ip_prefix_destination = ip_prefix_destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_prefix_destination_compound_results_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ip_prefix_destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ip_prefix_destination.setter
    def ip_prefix_destination(self, value):
        self._set_field_value('field ip_prefix_destination', 0, 20, npl_destination_t, value)



class npl_ip_relay_egress_qos_key_pack_table_load_t(basic_npl_struct):
    def __init__(self, muxed_qos_group=0, mapping_qos_fwd_qos_tag=0, mapping_qos_pd_tag=0, zero_counter_ptr=0):
        super().__init__(44)
        self.muxed_qos_group = muxed_qos_group
        self.mapping_qos_fwd_qos_tag = mapping_qos_fwd_qos_tag
        self.mapping_qos_pd_tag = mapping_qos_pd_tag
        self.zero_counter_ptr = zero_counter_ptr

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_relay_egress_qos_key_pack_table_load_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def muxed_qos_group(self):
        return npl_fwd_qos_tag_t._get_as_sub_field(self._data, self._offset_in_data + 36)
    @muxed_qos_group.setter
    def muxed_qos_group(self, value):
        self._set_field_value('field muxed_qos_group', 36, 7, npl_fwd_qos_tag_t, value)
    @property
    def mapping_qos_fwd_qos_tag(self):
        return npl_fwd_qos_tag_t._get_as_sub_field(self._data, self._offset_in_data + 28)
    @mapping_qos_fwd_qos_tag.setter
    def mapping_qos_fwd_qos_tag(self, value):
        self._set_field_value('field mapping_qos_fwd_qos_tag', 28, 7, npl_fwd_qos_tag_t, value)
    @property
    def mapping_qos_pd_tag(self):
        return npl_fwd_qos_tag_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @mapping_qos_pd_tag.setter
    def mapping_qos_pd_tag(self, value):
        self._set_field_value('field mapping_qos_pd_tag', 20, 7, npl_fwd_qos_tag_t, value)
    @property
    def zero_counter_ptr(self):
        return self._get_field_value(0, 20)
    @zero_counter_ptr.setter
    def zero_counter_ptr(self, value):
        self._set_field_value('field zero_counter_ptr', 0, 20, int, value)



class npl_ip_rtf_iter_prop_over_fwd0_t(basic_npl_struct):
    def __init__(self, table_index=0, acl_id=0):
        super().__init__(10)
        self.table_index = table_index
        self.acl_id = acl_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_rtf_iter_prop_over_fwd0_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def table_index(self):
        return self._get_field_value(7, 3)
    @table_index.setter
    def table_index(self, value):
        self._set_field_value('field table_index', 7, 3, int, value)
    @property
    def acl_id(self):
        return self._get_field_value(0, 7)
    @acl_id.setter
    def acl_id(self, value):
        self._set_field_value('field acl_id', 0, 7, int, value)



class npl_ip_rtf_iter_prop_over_fwd1_t(basic_npl_struct):
    def __init__(self, table_index=0, acl_id=0):
        super().__init__(9)
        self.table_index = table_index
        self.acl_id = acl_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_rtf_iter_prop_over_fwd1_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def table_index(self):
        return self._get_field_value(7, 2)
    @table_index.setter
    def table_index(self, value):
        self._set_field_value('field table_index', 7, 2, int, value)
    @property
    def acl_id(self):
        return self._get_field_value(0, 7)
    @acl_id.setter
    def acl_id(self, value):
        self._set_field_value('field acl_id', 0, 7, int, value)



class npl_ip_rx_global_counter_t(basic_npl_struct):
    def __init__(self, tunnel_transit_counter_p=0):
        super().__init__(20)
        self.tunnel_transit_counter_p = tunnel_transit_counter_p

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_rx_global_counter_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tunnel_transit_counter_p(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @tunnel_transit_counter_p.setter
    def tunnel_transit_counter_p(self, value):
        self._set_field_value('field tunnel_transit_counter_p', 0, 20, npl_counter_ptr_t, value)



class npl_ip_tunnel_dip_t(basic_npl_struct):
    def __init__(self):
        super().__init__(32)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_tunnel_dip_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ipv6_dip_index(self):
        return self._get_field_value(20, 12)
    @ipv6_dip_index.setter
    def ipv6_dip_index(self, value):
        self._set_field_value('field ipv6_dip_index', 20, 12, int, value)
    @property
    def ipv4_dip(self):
        return self._get_field_value(0, 32)
    @ipv4_dip.setter
    def ipv4_dip(self, value):
        self._set_field_value('field ipv4_dip', 0, 32, int, value)



class npl_ip_ver_and_post_fwd_stage_t(basic_npl_struct):
    def __init__(self, ip_ver=0, post_fwd_rtf_stage=0):
        super().__init__(4)
        self.ip_ver = ip_ver
        self.post_fwd_rtf_stage = post_fwd_rtf_stage

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_ver_and_post_fwd_stage_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ip_ver(self):
        return self._get_field_value(3, 1)
    @ip_ver.setter
    def ip_ver(self, value):
        self._set_field_value('field ip_ver', 3, 1, int, value)
    @property
    def post_fwd_rtf_stage(self):
        return self._get_field_value(0, 3)
    @post_fwd_rtf_stage.setter
    def post_fwd_rtf_stage(self, value):
        self._set_field_value('field post_fwd_rtf_stage', 0, 3, int, value)



class npl_ip_ver_mc_t(basic_npl_struct):
    def __init__(self, ip_version=0, is_mc=0):
        super().__init__(2)
        self.ip_version = ip_version
        self.is_mc = is_mc

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_ver_mc_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ip_version(self):
        return self._get_field_value(1, 1)
    @ip_version.setter
    def ip_version(self, value):
        self._set_field_value('field ip_version', 1, 1, int, value)
    @property
    def is_mc(self):
        return npl_bool_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @is_mc.setter
    def is_mc(self, value):
        self._set_field_value('field is_mc', 0, 1, npl_bool_t, value)



class npl_ipv4_header_flags_t(basic_npl_struct):
    def __init__(self, header_error=0, fragmented=0, checksum_error=0):
        super().__init__(3)
        self.header_error = header_error
        self.fragmented = fragmented
        self.checksum_error = checksum_error

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ipv4_header_flags_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def header_error(self):
        return self._get_field_value(2, 1)
    @header_error.setter
    def header_error(self, value):
        self._set_field_value('field header_error', 2, 1, int, value)
    @property
    def fragmented(self):
        return self._get_field_value(1, 1)
    @fragmented.setter
    def fragmented(self, value):
        self._set_field_value('field fragmented', 1, 1, int, value)
    @property
    def checksum_error(self):
        return self._get_field_value(0, 1)
    @checksum_error.setter
    def checksum_error(self, value):
        self._set_field_value('field checksum_error', 0, 1, int, value)



class npl_ipv4_ipv6_init_rtf_stage_t(basic_npl_struct):
    def __init__(self, ipv4_init_rtf_stage=0, ipv6_init_rtf_stage=0):
        super().__init__(4)
        self.ipv4_init_rtf_stage = ipv4_init_rtf_stage
        self.ipv6_init_rtf_stage = ipv6_init_rtf_stage

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ipv4_ipv6_init_rtf_stage_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ipv4_init_rtf_stage(self):
        return self._get_field_value(2, 2)
    @ipv4_init_rtf_stage.setter
    def ipv4_init_rtf_stage(self, value):
        self._set_field_value('field ipv4_init_rtf_stage', 2, 2, int, value)
    @property
    def ipv6_init_rtf_stage(self):
        return self._get_field_value(0, 2)
    @ipv6_init_rtf_stage.setter
    def ipv6_init_rtf_stage(self, value):
        self._set_field_value('field ipv6_init_rtf_stage', 0, 2, int, value)



class npl_ipv4_sip_dip_t(basic_npl_struct):
    def __init__(self, sip=0, dip=0):
        super().__init__(64)
        self.sip = sip
        self.dip = dip

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ipv4_sip_dip_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sip(self):
        return self._get_field_value(32, 32)
    @sip.setter
    def sip(self, value):
        self._set_field_value('field sip', 32, 32, int, value)
    @property
    def dip(self):
        return self._get_field_value(0, 32)
    @dip.setter
    def dip(self, value):
        self._set_field_value('field dip', 0, 32, int, value)



class npl_ipv4_traps_t(basic_npl_struct):
    def __init__(self, mc_forwarding_disabled=0, uc_forwarding_disabled=0, checksum=0, header_error=0, unknown_protocol=0, options_exist=0, non_comp_mc=0):
        super().__init__(7)
        self.mc_forwarding_disabled = mc_forwarding_disabled
        self.uc_forwarding_disabled = uc_forwarding_disabled
        self.checksum = checksum
        self.header_error = header_error
        self.unknown_protocol = unknown_protocol
        self.options_exist = options_exist
        self.non_comp_mc = non_comp_mc

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ipv4_traps_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mc_forwarding_disabled(self):
        return self._get_field_value(6, 1)
    @mc_forwarding_disabled.setter
    def mc_forwarding_disabled(self, value):
        self._set_field_value('field mc_forwarding_disabled', 6, 1, int, value)
    @property
    def uc_forwarding_disabled(self):
        return self._get_field_value(5, 1)
    @uc_forwarding_disabled.setter
    def uc_forwarding_disabled(self, value):
        self._set_field_value('field uc_forwarding_disabled', 5, 1, int, value)
    @property
    def checksum(self):
        return self._get_field_value(4, 1)
    @checksum.setter
    def checksum(self, value):
        self._set_field_value('field checksum', 4, 1, int, value)
    @property
    def header_error(self):
        return self._get_field_value(3, 1)
    @header_error.setter
    def header_error(self, value):
        self._set_field_value('field header_error', 3, 1, int, value)
    @property
    def unknown_protocol(self):
        return self._get_field_value(2, 1)
    @unknown_protocol.setter
    def unknown_protocol(self, value):
        self._set_field_value('field unknown_protocol', 2, 1, int, value)
    @property
    def options_exist(self):
        return self._get_field_value(1, 1)
    @options_exist.setter
    def options_exist(self, value):
        self._set_field_value('field options_exist', 1, 1, int, value)
    @property
    def non_comp_mc(self):
        return self._get_field_value(0, 1)
    @non_comp_mc.setter
    def non_comp_mc(self, value):
        self._set_field_value('field non_comp_mc', 0, 1, int, value)



class npl_ipv4_ttl_and_protocol_t(basic_npl_struct):
    def __init__(self, ttl=0, protocol=0):
        super().__init__(16)
        self.ttl = ttl
        self.protocol = protocol

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ipv4_ttl_and_protocol_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ttl(self):
        return self._get_field_value(8, 8)
    @ttl.setter
    def ttl(self, value):
        self._set_field_value('field ttl', 8, 8, int, value)
    @property
    def protocol(self):
        return self._get_field_value(0, 8)
    @protocol.setter
    def protocol(self, value):
        self._set_field_value('field protocol', 0, 8, int, value)



class npl_ipv6_header_flags_t(basic_npl_struct):
    def __init__(self, header_error=0, not_first_fragment=0):
        super().__init__(3)
        self.header_error = header_error
        self.not_first_fragment = not_first_fragment

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ipv6_header_flags_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def header_error(self):
        return self._get_field_value(2, 1)
    @header_error.setter
    def header_error(self, value):
        self._set_field_value('field header_error', 2, 1, int, value)
    @property
    def not_first_fragment(self):
        return self._get_field_value(1, 1)
    @not_first_fragment.setter
    def not_first_fragment(self, value):
        self._set_field_value('field not_first_fragment', 1, 1, int, value)



class npl_ipv6_next_header_and_hop_limit_t(basic_npl_struct):
    def __init__(self, next_header=0, hop_limit=0):
        super().__init__(16)
        self.next_header = next_header
        self.hop_limit = hop_limit

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ipv6_next_header_and_hop_limit_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def next_header(self):
        return self._get_field_value(8, 8)
    @next_header.setter
    def next_header(self, value):
        self._set_field_value('field next_header', 8, 8, int, value)
    @property
    def hop_limit(self):
        return self._get_field_value(0, 8)
    @hop_limit.setter
    def hop_limit(self, value):
        self._set_field_value('field hop_limit', 0, 8, int, value)



class npl_ipv6_traps_t(basic_npl_struct):
    def __init__(self, mc_forwarding_disabled=0, uc_forwarding_disabled=0, hop_by_hop=0, header_error=0, illegal_sip=0, illegal_dip=0, zero_payload=0, next_header_check=0, non_comp_mc=0):
        super().__init__(9)
        self.mc_forwarding_disabled = mc_forwarding_disabled
        self.uc_forwarding_disabled = uc_forwarding_disabled
        self.hop_by_hop = hop_by_hop
        self.header_error = header_error
        self.illegal_sip = illegal_sip
        self.illegal_dip = illegal_dip
        self.zero_payload = zero_payload
        self.next_header_check = next_header_check
        self.non_comp_mc = non_comp_mc

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ipv6_traps_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mc_forwarding_disabled(self):
        return self._get_field_value(8, 1)
    @mc_forwarding_disabled.setter
    def mc_forwarding_disabled(self, value):
        self._set_field_value('field mc_forwarding_disabled', 8, 1, int, value)
    @property
    def uc_forwarding_disabled(self):
        return self._get_field_value(7, 1)
    @uc_forwarding_disabled.setter
    def uc_forwarding_disabled(self, value):
        self._set_field_value('field uc_forwarding_disabled', 7, 1, int, value)
    @property
    def hop_by_hop(self):
        return self._get_field_value(6, 1)
    @hop_by_hop.setter
    def hop_by_hop(self, value):
        self._set_field_value('field hop_by_hop', 6, 1, int, value)
    @property
    def header_error(self):
        return self._get_field_value(5, 1)
    @header_error.setter
    def header_error(self, value):
        self._set_field_value('field header_error', 5, 1, int, value)
    @property
    def illegal_sip(self):
        return self._get_field_value(4, 1)
    @illegal_sip.setter
    def illegal_sip(self, value):
        self._set_field_value('field illegal_sip', 4, 1, int, value)
    @property
    def illegal_dip(self):
        return self._get_field_value(3, 1)
    @illegal_dip.setter
    def illegal_dip(self, value):
        self._set_field_value('field illegal_dip', 3, 1, int, value)
    @property
    def zero_payload(self):
        return self._get_field_value(2, 1)
    @zero_payload.setter
    def zero_payload(self, value):
        self._set_field_value('field zero_payload', 2, 1, int, value)
    @property
    def next_header_check(self):
        return self._get_field_value(1, 1)
    @next_header_check.setter
    def next_header_check(self, value):
        self._set_field_value('field next_header_check', 1, 1, int, value)
    @property
    def non_comp_mc(self):
        return self._get_field_value(0, 1)
    @non_comp_mc.setter
    def non_comp_mc(self, value):
        self._set_field_value('field non_comp_mc', 0, 1, int, value)



class npl_is_inject_up_and_ip_first_fragment_t(basic_npl_struct):
    def __init__(self, is_inject_up_dest_override=0, is_inject_up=0, ip_first_fragment=0):
        super().__init__(3)
        self.is_inject_up_dest_override = is_inject_up_dest_override
        self.is_inject_up = is_inject_up
        self.ip_first_fragment = ip_first_fragment

    def _get_as_sub_field(data, offset_in_data):
        result = npl_is_inject_up_and_ip_first_fragment_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_inject_up_dest_override(self):
        return npl_bool_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @is_inject_up_dest_override.setter
    def is_inject_up_dest_override(self, value):
        self._set_field_value('field is_inject_up_dest_override', 2, 1, npl_bool_t, value)
    @property
    def is_inject_up(self):
        return npl_bool_t._get_as_sub_field(self._data, self._offset_in_data + 1)
    @is_inject_up.setter
    def is_inject_up(self, value):
        self._set_field_value('field is_inject_up', 1, 1, npl_bool_t, value)
    @property
    def ip_first_fragment(self):
        return npl_bool_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ip_first_fragment.setter
    def ip_first_fragment(self, value):
        self._set_field_value('field ip_first_fragment', 0, 1, npl_bool_t, value)



class npl_is_pbts_prefix_t(basic_npl_struct):
    def __init__(self, val=0):
        super().__init__(1)
        self.val = val

    def _get_as_sub_field(data, offset_in_data):
        result = npl_is_pbts_prefix_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def val(self):
        return self._get_field_value(0, 1)
    @val.setter
    def val(self, value):
        self._set_field_value('field val', 0, 1, int, value)



class npl_ive_enable_t(basic_npl_struct):
    def __init__(self, enable=0):
        super().__init__(1)
        self.enable = enable

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ive_enable_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enable(self):
        return self._get_field_value(0, 1)
    @enable.setter
    def enable(self, value):
        self._set_field_value('field enable', 0, 1, int, value)



class npl_l2_dlp_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(18)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 18)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 18, int, value)



class npl_l2_global_slp_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(20)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_global_slp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 18)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 18, int, value)



class npl_l2_lpts_attributes_t(basic_npl_struct):
    def __init__(self, mac_terminated=0):
        super().__init__(1)
        self.mac_terminated = mac_terminated

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_lpts_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mac_terminated(self):
        return self._get_field_value(0, 1)
    @mac_terminated.setter
    def mac_terminated(self, value):
        self._set_field_value('field mac_terminated', 0, 1, int, value)



class npl_l2_lpts_ip_fragment_t(basic_npl_struct):
    def __init__(self, v6_not_first_fragment=0, v4_not_first_fragment=0):
        super().__init__(2)
        self.v6_not_first_fragment = v6_not_first_fragment
        self.v4_not_first_fragment = v4_not_first_fragment

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_lpts_ip_fragment_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def v6_not_first_fragment(self):
        return self._get_field_value(1, 1)
    @v6_not_first_fragment.setter
    def v6_not_first_fragment(self, value):
        self._set_field_value('field v6_not_first_fragment', 1, 1, int, value)
    @property
    def v4_not_first_fragment(self):
        return self._get_field_value(0, 1)
    @v4_not_first_fragment.setter
    def v4_not_first_fragment(self, value):
        self._set_field_value('field v4_not_first_fragment', 0, 1, int, value)



class npl_l2_lpts_next_macro_pack_fields_t(basic_npl_struct):
    def __init__(self, l2_lpts=0):
        super().__init__(2)
        self.l2_lpts = l2_lpts

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_lpts_next_macro_pack_fields_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2_lpts(self):
        return self._get_field_value(0, 2)
    @l2_lpts.setter
    def l2_lpts(self, value):
        self._set_field_value('field l2_lpts', 0, 2, int, value)



class npl_l2_lpts_traps_t(basic_npl_struct):
    def __init__(self, trap0=0, trap1=0, trap2=0, trap3=0, trap4=0, trap5=0, trap6=0, trap7=0, trap8=0, trap9=0, trap10=0, trap11=0):
        super().__init__(12)
        self.trap0 = trap0
        self.trap1 = trap1
        self.trap2 = trap2
        self.trap3 = trap3
        self.trap4 = trap4
        self.trap5 = trap5
        self.trap6 = trap6
        self.trap7 = trap7
        self.trap8 = trap8
        self.trap9 = trap9
        self.trap10 = trap10
        self.trap11 = trap11

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_lpts_traps_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def trap0(self):
        return self._get_field_value(11, 1)
    @trap0.setter
    def trap0(self, value):
        self._set_field_value('field trap0', 11, 1, int, value)
    @property
    def trap1(self):
        return self._get_field_value(10, 1)
    @trap1.setter
    def trap1(self, value):
        self._set_field_value('field trap1', 10, 1, int, value)
    @property
    def trap2(self):
        return self._get_field_value(9, 1)
    @trap2.setter
    def trap2(self, value):
        self._set_field_value('field trap2', 9, 1, int, value)
    @property
    def trap3(self):
        return self._get_field_value(8, 1)
    @trap3.setter
    def trap3(self, value):
        self._set_field_value('field trap3', 8, 1, int, value)
    @property
    def trap4(self):
        return self._get_field_value(7, 1)
    @trap4.setter
    def trap4(self, value):
        self._set_field_value('field trap4', 7, 1, int, value)
    @property
    def trap5(self):
        return self._get_field_value(6, 1)
    @trap5.setter
    def trap5(self, value):
        self._set_field_value('field trap5', 6, 1, int, value)
    @property
    def trap6(self):
        return self._get_field_value(5, 1)
    @trap6.setter
    def trap6(self, value):
        self._set_field_value('field trap6', 5, 1, int, value)
    @property
    def trap7(self):
        return self._get_field_value(4, 1)
    @trap7.setter
    def trap7(self, value):
        self._set_field_value('field trap7', 4, 1, int, value)
    @property
    def trap8(self):
        return self._get_field_value(3, 1)
    @trap8.setter
    def trap8(self, value):
        self._set_field_value('field trap8', 3, 1, int, value)
    @property
    def trap9(self):
        return self._get_field_value(2, 1)
    @trap9.setter
    def trap9(self, value):
        self._set_field_value('field trap9', 2, 1, int, value)
    @property
    def trap10(self):
        return self._get_field_value(1, 1)
    @trap10.setter
    def trap10(self, value):
        self._set_field_value('field trap10', 1, 1, int, value)
    @property
    def trap11(self):
        return self._get_field_value(0, 1)
    @trap11.setter
    def trap11(self, value):
        self._set_field_value('field trap11', 0, 1, int, value)



class npl_l2_relay_id_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(14)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_relay_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 14)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 14, int, value)



class npl_l2vpn_control_bits_t(basic_npl_struct):
    def __init__(self, enable_pwe_cntr=0, no_fat=0, cw_fat_exists=0):
        super().__init__(4)
        self.enable_pwe_cntr = enable_pwe_cntr
        self.no_fat = no_fat
        self.cw_fat_exists = cw_fat_exists

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2vpn_control_bits_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enable_pwe_cntr(self):
        return self._get_field_value(3, 1)
    @enable_pwe_cntr.setter
    def enable_pwe_cntr(self, value):
        self._set_field_value('field enable_pwe_cntr', 3, 1, int, value)
    @property
    def no_fat(self):
        return self._get_field_value(2, 1)
    @no_fat.setter
    def no_fat(self, value):
        self._set_field_value('field no_fat', 2, 1, int, value)
    @property
    def cw_fat_exists(self):
        return self._get_field_value(0, 2)
    @cw_fat_exists.setter
    def cw_fat_exists(self, value):
        self._set_field_value('field cw_fat_exists', 0, 2, int, value)



class npl_l2vpn_label_encap_data_t(basic_npl_struct):
    def __init__(self, pwe_encap_cntr=0, lp_profile=0, first_ene_macro=0, pwe_l2_dlp_id=0, l2vpn_control_bits=0, label=0):
        super().__init__(76)
        self.pwe_encap_cntr = pwe_encap_cntr
        self.lp_profile = lp_profile
        self.first_ene_macro = first_ene_macro
        self.pwe_l2_dlp_id = pwe_l2_dlp_id
        self.l2vpn_control_bits = l2vpn_control_bits
        self.label = label

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2vpn_label_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def pwe_encap_cntr(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 56)
    @pwe_encap_cntr.setter
    def pwe_encap_cntr(self, value):
        self._set_field_value('field pwe_encap_cntr', 56, 20, npl_counter_ptr_t, value)
    @property
    def lp_profile(self):
        return self._get_field_value(52, 2)
    @lp_profile.setter
    def lp_profile(self, value):
        self._set_field_value('field lp_profile', 52, 2, int, value)
    @property
    def first_ene_macro(self):
        return npl_ene_macro_id_t._get_as_sub_field(self._data, self._offset_in_data + 44)
    @first_ene_macro.setter
    def first_ene_macro(self, value):
        self._set_field_value('field first_ene_macro', 44, 8, npl_ene_macro_id_t, value)
    @property
    def pwe_l2_dlp_id(self):
        return self._get_field_value(24, 20)
    @pwe_l2_dlp_id.setter
    def pwe_l2_dlp_id(self, value):
        self._set_field_value('field pwe_l2_dlp_id', 24, 20, int, value)
    @property
    def l2vpn_control_bits(self):
        return npl_l2vpn_control_bits_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @l2vpn_control_bits.setter
    def l2vpn_control_bits(self, value):
        self._set_field_value('field l2vpn_control_bits', 20, 4, npl_l2vpn_control_bits_t, value)
    @property
    def label(self):
        return self._get_field_value(0, 20)
    @label.setter
    def label(self, value):
        self._set_field_value('field label', 0, 20, int, value)



class npl_l3_dlp_lsbs_t(basic_npl_struct):
    def __init__(self, l3_dlp_lsbs=0):
        super().__init__(12)
        self.l3_dlp_lsbs = l3_dlp_lsbs

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_dlp_lsbs_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_dlp_lsbs(self):
        return self._get_field_value(0, 12)
    @l3_dlp_lsbs.setter
    def l3_dlp_lsbs(self, value):
        self._set_field_value('field l3_dlp_lsbs', 0, 12, int, value)



class npl_l3_ecn_ctrl_t(basic_npl_struct):
    def __init__(self, count_cong_pkt=0, disable_ecn=0):
        super().__init__(2)
        self.count_cong_pkt = count_cong_pkt
        self.disable_ecn = disable_ecn

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_ecn_ctrl_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def count_cong_pkt(self):
        return self._get_field_value(1, 1)
    @count_cong_pkt.setter
    def count_cong_pkt(self, value):
        self._set_field_value('field count_cong_pkt', 1, 1, int, value)
    @property
    def disable_ecn(self):
        return self._get_field_value(0, 1)
    @disable_ecn.setter
    def disable_ecn(self, value):
        self._set_field_value('field disable_ecn', 0, 1, int, value)



class npl_l3_pfc_data_t(basic_npl_struct):
    def __init__(self, tc=0, dsp=0):
        super().__init__(15)
        self.tc = tc
        self.dsp = dsp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_pfc_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tc(self):
        return self._get_field_value(12, 3)
    @tc.setter
    def tc(self, value):
        self._set_field_value('field tc', 12, 3, int, value)
    @property
    def dsp(self):
        return self._get_field_value(0, 12)
    @dsp.setter
    def dsp(self, value):
        self._set_field_value('field dsp', 0, 12, int, value)



class npl_l3_relay_id_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(11)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_relay_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 11)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 11, int, value)



class npl_l3_slp_lsbs_t(basic_npl_struct):
    def __init__(self, l3_slp_lsbs=0):
        super().__init__(12)
        self.l3_slp_lsbs = l3_slp_lsbs

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_slp_lsbs_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_slp_lsbs(self):
        return self._get_field_value(0, 12)
    @l3_slp_lsbs.setter
    def l3_slp_lsbs(self, value):
        self._set_field_value('field l3_slp_lsbs', 0, 12, int, value)



class npl_l3_traps_t(basic_npl_struct):
    def __init__(self, ip_unicast_rpf=0, ip_multicast_rpf=0, ip_mc_drop=0, ip_mc_punt_dc_pass=0, ip_mc_snoop_dc_pass=0, ip_mc_snoop_rpf_fail=0, ip_mc_punt_rpf_fail=0, ip_mc_snoop_lookup_miss=0, ip_multicast_not_found=0, ip_mc_s_g_punt_member=0, ip_mc_g_punt_member=0, ip_mc_egress_punt=0, isis_over_l3=0, isis_drain=0, no_hbm_access_dip=0, no_hbm_access_sip=0, lpm_error=0, lpm_drop=0, local_subnet=0, icmp_redirect=0, no_lp_over_lag_mapping=0, ingress_monitor=0, egress_monitor=0, acl_drop=0, acl_force_punt=0, acl_force_punt1=0, acl_force_punt2=0, acl_force_punt3=0, acl_force_punt4=0, acl_force_punt5=0, acl_force_punt6=0, acl_force_punt7=0, glean_adj=0, drop_adj=0, drop_adj_non_inject=0, null_adj=0, user_trap1=0, user_trap2=0, lpm_default_drop=0, lpm_incomplete0=0, lpm_incomplete2=0, bfd_micro_ip_disabled=0, no_vni_mapping=0, no_hbm_access_og_sip=0, no_hbm_access_og_dip=0, no_l3_dlp_mapping=0, l3_dlp_disabled=0, split_horizon=0, mc_same_interface=0, no_vpn_label_found=0, ttl_or_hop_limit_is_one=0, tx_mtu_failure=0, tx_frr_drop=0):
        super().__init__(53)
        self.ip_unicast_rpf = ip_unicast_rpf
        self.ip_multicast_rpf = ip_multicast_rpf
        self.ip_mc_drop = ip_mc_drop
        self.ip_mc_punt_dc_pass = ip_mc_punt_dc_pass
        self.ip_mc_snoop_dc_pass = ip_mc_snoop_dc_pass
        self.ip_mc_snoop_rpf_fail = ip_mc_snoop_rpf_fail
        self.ip_mc_punt_rpf_fail = ip_mc_punt_rpf_fail
        self.ip_mc_snoop_lookup_miss = ip_mc_snoop_lookup_miss
        self.ip_multicast_not_found = ip_multicast_not_found
        self.ip_mc_s_g_punt_member = ip_mc_s_g_punt_member
        self.ip_mc_g_punt_member = ip_mc_g_punt_member
        self.ip_mc_egress_punt = ip_mc_egress_punt
        self.isis_over_l3 = isis_over_l3
        self.isis_drain = isis_drain
        self.no_hbm_access_dip = no_hbm_access_dip
        self.no_hbm_access_sip = no_hbm_access_sip
        self.lpm_error = lpm_error
        self.lpm_drop = lpm_drop
        self.local_subnet = local_subnet
        self.icmp_redirect = icmp_redirect
        self.no_lp_over_lag_mapping = no_lp_over_lag_mapping
        self.ingress_monitor = ingress_monitor
        self.egress_monitor = egress_monitor
        self.acl_drop = acl_drop
        self.acl_force_punt = acl_force_punt
        self.acl_force_punt1 = acl_force_punt1
        self.acl_force_punt2 = acl_force_punt2
        self.acl_force_punt3 = acl_force_punt3
        self.acl_force_punt4 = acl_force_punt4
        self.acl_force_punt5 = acl_force_punt5
        self.acl_force_punt6 = acl_force_punt6
        self.acl_force_punt7 = acl_force_punt7
        self.glean_adj = glean_adj
        self.drop_adj = drop_adj
        self.drop_adj_non_inject = drop_adj_non_inject
        self.null_adj = null_adj
        self.user_trap1 = user_trap1
        self.user_trap2 = user_trap2
        self.lpm_default_drop = lpm_default_drop
        self.lpm_incomplete0 = lpm_incomplete0
        self.lpm_incomplete2 = lpm_incomplete2
        self.bfd_micro_ip_disabled = bfd_micro_ip_disabled
        self.no_vni_mapping = no_vni_mapping
        self.no_hbm_access_og_sip = no_hbm_access_og_sip
        self.no_hbm_access_og_dip = no_hbm_access_og_dip
        self.no_l3_dlp_mapping = no_l3_dlp_mapping
        self.l3_dlp_disabled = l3_dlp_disabled
        self.split_horizon = split_horizon
        self.mc_same_interface = mc_same_interface
        self.no_vpn_label_found = no_vpn_label_found
        self.ttl_or_hop_limit_is_one = ttl_or_hop_limit_is_one
        self.tx_mtu_failure = tx_mtu_failure
        self.tx_frr_drop = tx_frr_drop

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_traps_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ip_unicast_rpf(self):
        return self._get_field_value(52, 1)
    @ip_unicast_rpf.setter
    def ip_unicast_rpf(self, value):
        self._set_field_value('field ip_unicast_rpf', 52, 1, int, value)
    @property
    def ip_multicast_rpf(self):
        return self._get_field_value(51, 1)
    @ip_multicast_rpf.setter
    def ip_multicast_rpf(self, value):
        self._set_field_value('field ip_multicast_rpf', 51, 1, int, value)
    @property
    def ip_mc_drop(self):
        return self._get_field_value(50, 1)
    @ip_mc_drop.setter
    def ip_mc_drop(self, value):
        self._set_field_value('field ip_mc_drop', 50, 1, int, value)
    @property
    def ip_mc_punt_dc_pass(self):
        return self._get_field_value(49, 1)
    @ip_mc_punt_dc_pass.setter
    def ip_mc_punt_dc_pass(self, value):
        self._set_field_value('field ip_mc_punt_dc_pass', 49, 1, int, value)
    @property
    def ip_mc_snoop_dc_pass(self):
        return self._get_field_value(48, 1)
    @ip_mc_snoop_dc_pass.setter
    def ip_mc_snoop_dc_pass(self, value):
        self._set_field_value('field ip_mc_snoop_dc_pass', 48, 1, int, value)
    @property
    def ip_mc_snoop_rpf_fail(self):
        return self._get_field_value(47, 1)
    @ip_mc_snoop_rpf_fail.setter
    def ip_mc_snoop_rpf_fail(self, value):
        self._set_field_value('field ip_mc_snoop_rpf_fail', 47, 1, int, value)
    @property
    def ip_mc_punt_rpf_fail(self):
        return self._get_field_value(46, 1)
    @ip_mc_punt_rpf_fail.setter
    def ip_mc_punt_rpf_fail(self, value):
        self._set_field_value('field ip_mc_punt_rpf_fail', 46, 1, int, value)
    @property
    def ip_mc_snoop_lookup_miss(self):
        return self._get_field_value(45, 1)
    @ip_mc_snoop_lookup_miss.setter
    def ip_mc_snoop_lookup_miss(self, value):
        self._set_field_value('field ip_mc_snoop_lookup_miss', 45, 1, int, value)
    @property
    def ip_multicast_not_found(self):
        return self._get_field_value(44, 1)
    @ip_multicast_not_found.setter
    def ip_multicast_not_found(self, value):
        self._set_field_value('field ip_multicast_not_found', 44, 1, int, value)
    @property
    def ip_mc_s_g_punt_member(self):
        return self._get_field_value(43, 1)
    @ip_mc_s_g_punt_member.setter
    def ip_mc_s_g_punt_member(self, value):
        self._set_field_value('field ip_mc_s_g_punt_member', 43, 1, int, value)
    @property
    def ip_mc_g_punt_member(self):
        return self._get_field_value(42, 1)
    @ip_mc_g_punt_member.setter
    def ip_mc_g_punt_member(self, value):
        self._set_field_value('field ip_mc_g_punt_member', 42, 1, int, value)
    @property
    def ip_mc_egress_punt(self):
        return self._get_field_value(41, 1)
    @ip_mc_egress_punt.setter
    def ip_mc_egress_punt(self, value):
        self._set_field_value('field ip_mc_egress_punt', 41, 1, int, value)
    @property
    def isis_over_l3(self):
        return self._get_field_value(40, 1)
    @isis_over_l3.setter
    def isis_over_l3(self, value):
        self._set_field_value('field isis_over_l3', 40, 1, int, value)
    @property
    def isis_drain(self):
        return self._get_field_value(39, 1)
    @isis_drain.setter
    def isis_drain(self, value):
        self._set_field_value('field isis_drain', 39, 1, int, value)
    @property
    def no_hbm_access_dip(self):
        return self._get_field_value(38, 1)
    @no_hbm_access_dip.setter
    def no_hbm_access_dip(self, value):
        self._set_field_value('field no_hbm_access_dip', 38, 1, int, value)
    @property
    def no_hbm_access_sip(self):
        return self._get_field_value(37, 1)
    @no_hbm_access_sip.setter
    def no_hbm_access_sip(self, value):
        self._set_field_value('field no_hbm_access_sip', 37, 1, int, value)
    @property
    def lpm_error(self):
        return self._get_field_value(36, 1)
    @lpm_error.setter
    def lpm_error(self, value):
        self._set_field_value('field lpm_error', 36, 1, int, value)
    @property
    def lpm_drop(self):
        return self._get_field_value(35, 1)
    @lpm_drop.setter
    def lpm_drop(self, value):
        self._set_field_value('field lpm_drop', 35, 1, int, value)
    @property
    def local_subnet(self):
        return self._get_field_value(34, 1)
    @local_subnet.setter
    def local_subnet(self, value):
        self._set_field_value('field local_subnet', 34, 1, int, value)
    @property
    def icmp_redirect(self):
        return self._get_field_value(33, 1)
    @icmp_redirect.setter
    def icmp_redirect(self, value):
        self._set_field_value('field icmp_redirect', 33, 1, int, value)
    @property
    def no_lp_over_lag_mapping(self):
        return self._get_field_value(32, 1)
    @no_lp_over_lag_mapping.setter
    def no_lp_over_lag_mapping(self, value):
        self._set_field_value('field no_lp_over_lag_mapping', 32, 1, int, value)
    @property
    def ingress_monitor(self):
        return self._get_field_value(31, 1)
    @ingress_monitor.setter
    def ingress_monitor(self, value):
        self._set_field_value('field ingress_monitor', 31, 1, int, value)
    @property
    def egress_monitor(self):
        return self._get_field_value(30, 1)
    @egress_monitor.setter
    def egress_monitor(self, value):
        self._set_field_value('field egress_monitor', 30, 1, int, value)
    @property
    def acl_drop(self):
        return self._get_field_value(29, 1)
    @acl_drop.setter
    def acl_drop(self, value):
        self._set_field_value('field acl_drop', 29, 1, int, value)
    @property
    def acl_force_punt(self):
        return self._get_field_value(28, 1)
    @acl_force_punt.setter
    def acl_force_punt(self, value):
        self._set_field_value('field acl_force_punt', 28, 1, int, value)
    @property
    def acl_force_punt1(self):
        return self._get_field_value(27, 1)
    @acl_force_punt1.setter
    def acl_force_punt1(self, value):
        self._set_field_value('field acl_force_punt1', 27, 1, int, value)
    @property
    def acl_force_punt2(self):
        return self._get_field_value(26, 1)
    @acl_force_punt2.setter
    def acl_force_punt2(self, value):
        self._set_field_value('field acl_force_punt2', 26, 1, int, value)
    @property
    def acl_force_punt3(self):
        return self._get_field_value(25, 1)
    @acl_force_punt3.setter
    def acl_force_punt3(self, value):
        self._set_field_value('field acl_force_punt3', 25, 1, int, value)
    @property
    def acl_force_punt4(self):
        return self._get_field_value(24, 1)
    @acl_force_punt4.setter
    def acl_force_punt4(self, value):
        self._set_field_value('field acl_force_punt4', 24, 1, int, value)
    @property
    def acl_force_punt5(self):
        return self._get_field_value(23, 1)
    @acl_force_punt5.setter
    def acl_force_punt5(self, value):
        self._set_field_value('field acl_force_punt5', 23, 1, int, value)
    @property
    def acl_force_punt6(self):
        return self._get_field_value(22, 1)
    @acl_force_punt6.setter
    def acl_force_punt6(self, value):
        self._set_field_value('field acl_force_punt6', 22, 1, int, value)
    @property
    def acl_force_punt7(self):
        return self._get_field_value(21, 1)
    @acl_force_punt7.setter
    def acl_force_punt7(self, value):
        self._set_field_value('field acl_force_punt7', 21, 1, int, value)
    @property
    def glean_adj(self):
        return self._get_field_value(20, 1)
    @glean_adj.setter
    def glean_adj(self, value):
        self._set_field_value('field glean_adj', 20, 1, int, value)
    @property
    def drop_adj(self):
        return self._get_field_value(19, 1)
    @drop_adj.setter
    def drop_adj(self, value):
        self._set_field_value('field drop_adj', 19, 1, int, value)
    @property
    def drop_adj_non_inject(self):
        return self._get_field_value(18, 1)
    @drop_adj_non_inject.setter
    def drop_adj_non_inject(self, value):
        self._set_field_value('field drop_adj_non_inject', 18, 1, int, value)
    @property
    def null_adj(self):
        return self._get_field_value(17, 1)
    @null_adj.setter
    def null_adj(self, value):
        self._set_field_value('field null_adj', 17, 1, int, value)
    @property
    def user_trap1(self):
        return self._get_field_value(16, 1)
    @user_trap1.setter
    def user_trap1(self, value):
        self._set_field_value('field user_trap1', 16, 1, int, value)
    @property
    def user_trap2(self):
        return self._get_field_value(15, 1)
    @user_trap2.setter
    def user_trap2(self, value):
        self._set_field_value('field user_trap2', 15, 1, int, value)
    @property
    def lpm_default_drop(self):
        return self._get_field_value(14, 1)
    @lpm_default_drop.setter
    def lpm_default_drop(self, value):
        self._set_field_value('field lpm_default_drop', 14, 1, int, value)
    @property
    def lpm_incomplete0(self):
        return self._get_field_value(13, 1)
    @lpm_incomplete0.setter
    def lpm_incomplete0(self, value):
        self._set_field_value('field lpm_incomplete0', 13, 1, int, value)
    @property
    def lpm_incomplete2(self):
        return self._get_field_value(12, 1)
    @lpm_incomplete2.setter
    def lpm_incomplete2(self, value):
        self._set_field_value('field lpm_incomplete2', 12, 1, int, value)
    @property
    def bfd_micro_ip_disabled(self):
        return self._get_field_value(11, 1)
    @bfd_micro_ip_disabled.setter
    def bfd_micro_ip_disabled(self, value):
        self._set_field_value('field bfd_micro_ip_disabled', 11, 1, int, value)
    @property
    def no_vni_mapping(self):
        return self._get_field_value(10, 1)
    @no_vni_mapping.setter
    def no_vni_mapping(self, value):
        self._set_field_value('field no_vni_mapping', 10, 1, int, value)
    @property
    def no_hbm_access_og_sip(self):
        return self._get_field_value(9, 1)
    @no_hbm_access_og_sip.setter
    def no_hbm_access_og_sip(self, value):
        self._set_field_value('field no_hbm_access_og_sip', 9, 1, int, value)
    @property
    def no_hbm_access_og_dip(self):
        return self._get_field_value(8, 1)
    @no_hbm_access_og_dip.setter
    def no_hbm_access_og_dip(self, value):
        self._set_field_value('field no_hbm_access_og_dip', 8, 1, int, value)
    @property
    def no_l3_dlp_mapping(self):
        return self._get_field_value(7, 1)
    @no_l3_dlp_mapping.setter
    def no_l3_dlp_mapping(self, value):
        self._set_field_value('field no_l3_dlp_mapping', 7, 1, int, value)
    @property
    def l3_dlp_disabled(self):
        return self._get_field_value(6, 1)
    @l3_dlp_disabled.setter
    def l3_dlp_disabled(self, value):
        self._set_field_value('field l3_dlp_disabled', 6, 1, int, value)
    @property
    def split_horizon(self):
        return self._get_field_value(5, 1)
    @split_horizon.setter
    def split_horizon(self, value):
        self._set_field_value('field split_horizon', 5, 1, int, value)
    @property
    def mc_same_interface(self):
        return self._get_field_value(4, 1)
    @mc_same_interface.setter
    def mc_same_interface(self, value):
        self._set_field_value('field mc_same_interface', 4, 1, int, value)
    @property
    def no_vpn_label_found(self):
        return self._get_field_value(3, 1)
    @no_vpn_label_found.setter
    def no_vpn_label_found(self, value):
        self._set_field_value('field no_vpn_label_found', 3, 1, int, value)
    @property
    def ttl_or_hop_limit_is_one(self):
        return self._get_field_value(2, 1)
    @ttl_or_hop_limit_is_one.setter
    def ttl_or_hop_limit_is_one(self, value):
        self._set_field_value('field ttl_or_hop_limit_is_one', 2, 1, int, value)
    @property
    def tx_mtu_failure(self):
        return self._get_field_value(1, 1)
    @tx_mtu_failure.setter
    def tx_mtu_failure(self, value):
        self._set_field_value('field tx_mtu_failure', 1, 1, int, value)
    @property
    def tx_frr_drop(self):
        return self._get_field_value(0, 1)
    @tx_frr_drop.setter
    def tx_frr_drop(self, value):
        self._set_field_value('field tx_frr_drop', 0, 1, int, value)



class npl_l4_ports_header_t(basic_npl_struct):
    def __init__(self, src_port=0, dst_port=0):
        super().__init__(32)
        self.src_port = src_port
        self.dst_port = dst_port

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l4_ports_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def src_port(self):
        return self._get_field_value(16, 16)
    @src_port.setter
    def src_port(self, value):
        self._set_field_value('field src_port', 16, 16, int, value)
    @property
    def dst_port(self):
        return self._get_field_value(0, 16)
    @dst_port.setter
    def dst_port(self, value):
        self._set_field_value('field dst_port', 0, 16, int, value)



class npl_large_em_label_encap_data_and_counter_ptr_t(basic_npl_struct):
    def __init__(self, num_labels=0, label_encap=0, counter_ptr=0):
        super().__init__(45)
        self.num_labels = num_labels
        self.label_encap = label_encap
        self.counter_ptr = counter_ptr

    def _get_as_sub_field(data, offset_in_data):
        result = npl_large_em_label_encap_data_and_counter_ptr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def num_labels(self):
        return self._get_field_value(44, 1)
    @num_labels.setter
    def num_labels(self, value):
        self._set_field_value('field num_labels', 44, 1, int, value)
    @property
    def label_encap(self):
        return npl_exp_bos_and_label_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @label_encap.setter
    def label_encap(self, value):
        self._set_field_value('field label_encap', 20, 24, npl_exp_bos_and_label_t, value)
    @property
    def counter_ptr(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @counter_ptr.setter
    def counter_ptr(self, value):
        self._set_field_value('field counter_ptr', 0, 20, npl_counter_ptr_t, value)



class npl_lb_group_size_table_result_t(basic_npl_struct):
    def __init__(self, curr_group_size=0, consistency_mode=0):
        super().__init__(10)
        self.curr_group_size = curr_group_size
        self.consistency_mode = consistency_mode

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lb_group_size_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def curr_group_size(self):
        return self._get_field_value(1, 9)
    @curr_group_size.setter
    def curr_group_size(self, value):
        self._set_field_value('field curr_group_size', 1, 9, int, value)
    @property
    def consistency_mode(self):
        return self._get_field_value(0, 1)
    @consistency_mode.setter
    def consistency_mode(self, value):
        self._set_field_value('field consistency_mode', 0, 1, int, value)



class npl_lb_key_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(16)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lb_key_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 16)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 16, int, value)



class npl_learn_manager_cfg_max_learn_type_t(basic_npl_struct):
    def __init__(self, lr_type=0):
        super().__init__(2)
        self.lr_type = lr_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_learn_manager_cfg_max_learn_type_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lr_type(self):
        return self._get_field_value(0, 2)
    @lr_type.setter
    def lr_type(self, value):
        self._set_field_value('field lr_type', 0, 2, int, value)



class npl_light_fi_stage_cfg_t(basic_npl_struct):
    def __init__(self, update_current_header_info=0, size_width=0, size_offset=0, next_protocol_or_type_width=0, next_protocol_or_type_offset=0):
        super().__init__(20)
        self.update_current_header_info = update_current_header_info
        self.size_width = size_width
        self.size_offset = size_offset
        self.next_protocol_or_type_width = next_protocol_or_type_width
        self.next_protocol_or_type_offset = next_protocol_or_type_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_light_fi_stage_cfg_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def update_current_header_info(self):
        return self._get_field_value(19, 1)
    @update_current_header_info.setter
    def update_current_header_info(self, value):
        self._set_field_value('field update_current_header_info', 19, 1, int, value)
    @property
    def size_width(self):
        return self._get_field_value(15, 4)
    @size_width.setter
    def size_width(self, value):
        self._set_field_value('field size_width', 15, 4, int, value)
    @property
    def size_offset(self):
        return self._get_field_value(9, 6)
    @size_offset.setter
    def size_offset(self, value):
        self._set_field_value('field size_offset', 9, 6, int, value)
    @property
    def next_protocol_or_type_width(self):
        return self._get_field_value(6, 3)
    @next_protocol_or_type_width.setter
    def next_protocol_or_type_width(self, value):
        self._set_field_value('field next_protocol_or_type_width', 6, 3, int, value)
    @property
    def next_protocol_or_type_offset(self):
        return self._get_field_value(0, 6)
    @next_protocol_or_type_offset.setter
    def next_protocol_or_type_offset(self, value):
        self._set_field_value('field next_protocol_or_type_offset', 0, 6, int, value)



class npl_link_up_vector_result_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(108)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_link_up_vector_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def link_up(self):
        return basic_npl_array(108, 108, int, self._data, self._offset_in_data + 0)
    @link_up.setter
    def link_up(self, value):
        field = basic_npl_array(108, 108, int, self._data, self._offset_in_data + 0)
        field._set_field_value('field link_up', 0, 108, basic_npl_array, value)



class npl_lm_command_t(basic_npl_struct):
    def __init__(self, op=0, offset=0):
        super().__init__(12)
        self.op = op
        self.offset = offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lm_command_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def op(self):
        return self._get_field_value(8, 4)
    @op.setter
    def op(self, value):
        self._set_field_value('field op', 8, 4, int, value)
    @property
    def offset(self):
        return self._get_field_value(0, 7)
    @offset.setter
    def offset(self, value):
        self._set_field_value('field offset', 0, 7, int, value)



class npl_local_tx_ip_mapping_t(basic_npl_struct):
    def __init__(self, is_mpls_fwd=0, is_underlying_ip_proto=0, is_mapped_v4=0):
        super().__init__(3)
        self.is_mpls_fwd = is_mpls_fwd
        self.is_underlying_ip_proto = is_underlying_ip_proto
        self.is_mapped_v4 = is_mapped_v4

    def _get_as_sub_field(data, offset_in_data):
        result = npl_local_tx_ip_mapping_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_mpls_fwd(self):
        return self._get_field_value(2, 1)
    @is_mpls_fwd.setter
    def is_mpls_fwd(self, value):
        self._set_field_value('field is_mpls_fwd', 2, 1, int, value)
    @property
    def is_underlying_ip_proto(self):
        return self._get_field_value(1, 1)
    @is_underlying_ip_proto.setter
    def is_underlying_ip_proto(self, value):
        self._set_field_value('field is_underlying_ip_proto', 1, 1, int, value)
    @property
    def is_mapped_v4(self):
        return self._get_field_value(0, 1)
    @is_mapped_v4.setter
    def is_mapped_v4(self, value):
        self._set_field_value('field is_mapped_v4', 0, 1, int, value)



class npl_lp_attr_update_raw_bits_t(basic_npl_struct):
    def __init__(self, update_12_bits=0, update_3_bits=0, update_65_bits=0, update_q_m_counters=0):
        super().__init__(120)
        self.update_12_bits = update_12_bits
        self.update_3_bits = update_3_bits
        self.update_65_bits = update_65_bits
        self.update_q_m_counters = update_q_m_counters

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lp_attr_update_raw_bits_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def update_12_bits(self):
        return self._get_field_value(108, 12)
    @update_12_bits.setter
    def update_12_bits(self, value):
        self._set_field_value('field update_12_bits', 108, 12, int, value)
    @property
    def update_3_bits(self):
        return self._get_field_value(105, 3)
    @update_3_bits.setter
    def update_3_bits(self, value):
        self._set_field_value('field update_3_bits', 105, 3, int, value)
    @property
    def update_65_bits(self):
        return self._get_field_value(40, 65)
    @update_65_bits.setter
    def update_65_bits(self, value):
        self._set_field_value('field update_65_bits', 40, 65, int, value)
    @property
    def update_q_m_counters(self):
        return self._get_field_value(0, 40)
    @update_q_m_counters.setter
    def update_q_m_counters(self, value):
        self._set_field_value('field update_q_m_counters', 0, 40, int, value)



class npl_lp_id_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(16)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lp_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 16)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 16, int, value)



class npl_lp_rtf_conf_set_t(basic_npl_struct):
    def __init__(self, val=0):
        super().__init__(8)
        self.val = val

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lp_rtf_conf_set_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def val(self):
        return self._get_field_value(0, 8)
    @val.setter
    def val(self, value):
        self._set_field_value('field val', 0, 8, int, value)



class npl_lpm_payload_t(basic_npl_struct):
    def __init__(self, destination=0):
        super().__init__(20)
        self.destination = destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lpm_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 20, npl_destination_t, value)



class npl_lpm_prefix_fec_access_map_output_t(basic_npl_struct):
    def __init__(self, access_fec_table=0):
        super().__init__(1)
        self.access_fec_table = access_fec_table

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lpm_prefix_fec_access_map_output_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def access_fec_table(self):
        return self._get_field_value(0, 1)
    @access_fec_table.setter
    def access_fec_table(self, value):
        self._set_field_value('field access_fec_table', 0, 1, int, value)



class npl_lpm_prefix_map_output_t(basic_npl_struct):
    def __init__(self, prefix=0, is_default=0):
        super().__init__(7)
        self.prefix = prefix
        self.is_default = is_default

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lpm_prefix_map_output_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def prefix(self):
        return self._get_field_value(1, 6)
    @prefix.setter
    def prefix(self, value):
        self._set_field_value('field prefix', 1, 6, int, value)
    @property
    def is_default(self):
        return self._get_field_value(0, 1)
    @is_default.setter
    def is_default(self, value):
        self._set_field_value('field is_default', 0, 1, int, value)



class npl_lpts_cntr_and_lookup_index_t(basic_npl_struct):
    def __init__(self, meter_index_lsb=0, lpts_second_lookup_index=0, lpts_counter_ptr=0):
        super().__init__(32)
        self.meter_index_lsb = meter_index_lsb
        self.lpts_second_lookup_index = lpts_second_lookup_index
        self.lpts_counter_ptr = lpts_counter_ptr

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lpts_cntr_and_lookup_index_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def meter_index_lsb(self):
        return self._get_field_value(25, 7)
    @meter_index_lsb.setter
    def meter_index_lsb(self, value):
        self._set_field_value('field meter_index_lsb', 25, 7, int, value)
    @property
    def lpts_second_lookup_index(self):
        return self._get_field_value(20, 5)
    @lpts_second_lookup_index.setter
    def lpts_second_lookup_index(self, value):
        self._set_field_value('field lpts_second_lookup_index', 20, 5, int, value)
    @property
    def lpts_counter_ptr(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @lpts_counter_ptr.setter
    def lpts_counter_ptr(self, value):
        self._set_field_value('field lpts_counter_ptr', 0, 20, npl_counter_ptr_t, value)



class npl_lpts_flow_type_t(basic_npl_struct):
    def __init__(self, lpts_flow=0):
        super().__init__(4)
        self.lpts_flow = lpts_flow

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lpts_flow_type_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lpts_flow(self):
        return self._get_field_value(0, 4)
    @lpts_flow.setter
    def lpts_flow(self, value):
        self._set_field_value('field lpts_flow', 0, 4, int, value)



class npl_lpts_packet_flags_t(basic_npl_struct):
    def __init__(self, established=0, skip_bfd_or_ttl_255=0):
        super().__init__(2)
        self.established = established
        self.skip_bfd_or_ttl_255 = skip_bfd_or_ttl_255

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lpts_packet_flags_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def established(self):
        return self._get_field_value(1, 1)
    @established.setter
    def established(self, value):
        self._set_field_value('field established', 1, 1, int, value)
    @property
    def skip_bfd_or_ttl_255(self):
        return self._get_field_value(0, 1)
    @skip_bfd_or_ttl_255.setter
    def skip_bfd_or_ttl_255(self, value):
        self._set_field_value('field skip_bfd_or_ttl_255', 0, 1, int, value)



class npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t(basic_npl_struct):
    def __init__(self):
        super().__init__(8)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mirror_or_redirect_code(self):
        return self._get_field_value(0, 8)
    @mirror_or_redirect_code.setter
    def mirror_or_redirect_code(self, value):
        self._set_field_value('field mirror_or_redirect_code', 0, 8, int, value)
    @property
    def fabric_ibm_cmd(self):
        return npl_fabric_ibm_cmd_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @fabric_ibm_cmd.setter
    def fabric_ibm_cmd(self, value):
        self._set_field_value('field fabric_ibm_cmd', 0, 8, npl_fabric_ibm_cmd_t, value)
    @property
    def lpts_reason(self):
        return self._get_field_value(0, 8)
    @lpts_reason.setter
    def lpts_reason(self, value):
        self._set_field_value('field lpts_reason', 0, 8, int, value)



class npl_lr_fifo_register_t(basic_npl_struct):
    def __init__(self, address=0):
        super().__init__(4)
        self.address = address

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lr_fifo_register_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def address(self):
        return self._get_field_value(0, 4)
    @address.setter
    def address(self, value):
        self._set_field_value('field address', 0, 4, int, value)



class npl_lr_filter_fifo_register_t(basic_npl_struct):
    def __init__(self, address=0):
        super().__init__(5)
        self.address = address

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lr_filter_fifo_register_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def address(self):
        return self._get_field_value(0, 5)
    @address.setter
    def address(self, value):
        self._set_field_value('field address', 0, 5, int, value)



class npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def counter_flag(self):
        return npl_counter_flag_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @counter_flag.setter
    def counter_flag(self, value):
        self._set_field_value('field counter_flag', 0, 20, npl_counter_flag_t, value)
    @property
    def lsp_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @lsp_counter.setter
    def lsp_counter(self, value):
        self._set_field_value('field lsp_counter', 0, 20, npl_counter_ptr_t, value)



class npl_lsp_impose_2_mpls_labels_ene_offset_t(basic_npl_struct):
    def __init__(self, lsp_two_labels_ene_jump_offset=0, lsp_one_label_ene_jump_offset=0):
        super().__init__(8)
        self.lsp_two_labels_ene_jump_offset = lsp_two_labels_ene_jump_offset
        self.lsp_one_label_ene_jump_offset = lsp_one_label_ene_jump_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lsp_impose_2_mpls_labels_ene_offset_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lsp_two_labels_ene_jump_offset(self):
        return self._get_field_value(4, 4)
    @lsp_two_labels_ene_jump_offset.setter
    def lsp_two_labels_ene_jump_offset(self, value):
        self._set_field_value('field lsp_two_labels_ene_jump_offset', 4, 4, int, value)
    @property
    def lsp_one_label_ene_jump_offset(self):
        return self._get_field_value(0, 4)
    @lsp_one_label_ene_jump_offset.setter
    def lsp_one_label_ene_jump_offset(self, value):
        self._set_field_value('field lsp_one_label_ene_jump_offset', 0, 4, int, value)



class npl_lsp_impose_mpls_labels_ene_offset_t(basic_npl_struct):
    def __init__(self, lsp_impose_2_mpls_labels_ene_offset=0):
        super().__init__(8)
        self.lsp_impose_2_mpls_labels_ene_offset = lsp_impose_2_mpls_labels_ene_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lsp_impose_mpls_labels_ene_offset_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lsp_impose_2_mpls_labels_ene_offset(self):
        return npl_lsp_impose_2_mpls_labels_ene_offset_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @lsp_impose_2_mpls_labels_ene_offset.setter
    def lsp_impose_2_mpls_labels_ene_offset(self, value):
        self._set_field_value('field lsp_impose_2_mpls_labels_ene_offset', 0, 8, npl_lsp_impose_2_mpls_labels_ene_offset_t, value)



class npl_lsp_labels_opt3_t(basic_npl_struct):
    def __init__(self, label_0=0, label_1=0, label_2=0):
        super().__init__(60)
        self.label_0 = label_0
        self.label_1 = label_1
        self.label_2 = label_2

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lsp_labels_opt3_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def label_0(self):
        return self._get_field_value(40, 20)
    @label_0.setter
    def label_0(self, value):
        self._set_field_value('field label_0', 40, 20, int, value)
    @property
    def label_1(self):
        return self._get_field_value(20, 20)
    @label_1.setter
    def label_1(self, value):
        self._set_field_value('field label_1', 20, 20, int, value)
    @property
    def label_2(self):
        return self._get_field_value(0, 20)
    @label_2.setter
    def label_2(self, value):
        self._set_field_value('field label_2', 0, 20, int, value)



class npl_lsp_labels_t(basic_npl_struct):
    def __init__(self, label_0=0, label_1=0):
        super().__init__(40)
        self.label_0 = label_0
        self.label_1 = label_1

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lsp_labels_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def label_0(self):
        return self._get_field_value(20, 20)
    @label_0.setter
    def label_0(self, value):
        self._set_field_value('field label_0', 20, 20, int, value)
    @property
    def label_1(self):
        return self._get_field_value(0, 20)
    @label_1.setter
    def label_1(self, value):
        self._set_field_value('field label_1', 0, 20, int, value)



class npl_lsp_type_t(basic_npl_struct):
    def __init__(self, destination_encoding=0, vpn=0, inter_as=0):
        super().__init__(4)
        self.destination_encoding = destination_encoding
        self.vpn = vpn
        self.inter_as = inter_as

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lsp_type_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination_encoding(self):
        return self._get_field_value(2, 2)
    @destination_encoding.setter
    def destination_encoding(self, value):
        self._set_field_value('field destination_encoding', 2, 2, int, value)
    @property
    def vpn(self):
        return self._get_field_value(1, 1)
    @vpn.setter
    def vpn(self, value):
        self._set_field_value('field vpn', 1, 1, int, value)
    @property
    def inter_as(self):
        return self._get_field_value(0, 1)
    @inter_as.setter
    def inter_as(self, value):
        self._set_field_value('field inter_as', 0, 1, int, value)



class npl_lsr_encap_t_anonymous_union_lsp_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_lsr_encap_t_anonymous_union_lsp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def swap_label(self):
        return self._get_field_value(0, 20)
    @swap_label.setter
    def swap_label(self, value):
        self._set_field_value('field swap_label', 0, 20, int, value)
    @property
    def lsp_id(self):
        return self._get_field_value(0, 20)
    @lsp_id.setter
    def lsp_id(self, value):
        self._set_field_value('field lsp_id', 0, 20, int, value)



class npl_mac_addr_t(basic_npl_struct):
    def __init__(self, mac_address=0):
        super().__init__(48)
        self.mac_address = mac_address

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_addr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mac_address(self):
        return self._get_field_value(0, 48)
    @mac_address.setter
    def mac_address(self, value):
        self._set_field_value('field mac_address', 0, 48, int, value)



class npl_mac_da_t(basic_npl_struct):
    def __init__(self, is_vrrp=0, mac_l2_lpts_lkup=0, use_l2_lpts=0, prefix=0, compound_termination_control=0, is_ipv4_mc=0, is_ipv6_mc=0, type=0):
        super().__init__(16)
        self.is_vrrp = is_vrrp
        self.mac_l2_lpts_lkup = mac_l2_lpts_lkup
        self.use_l2_lpts = use_l2_lpts
        self.prefix = prefix
        self.compound_termination_control = compound_termination_control
        self.is_ipv4_mc = is_ipv4_mc
        self.is_ipv6_mc = is_ipv6_mc
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_da_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_vrrp(self):
        return self._get_field_value(15, 1)
    @is_vrrp.setter
    def is_vrrp(self, value):
        self._set_field_value('field is_vrrp', 15, 1, int, value)
    @property
    def mac_l2_lpts_lkup(self):
        return self._get_field_value(14, 1)
    @mac_l2_lpts_lkup.setter
    def mac_l2_lpts_lkup(self, value):
        self._set_field_value('field mac_l2_lpts_lkup', 14, 1, int, value)
    @property
    def use_l2_lpts(self):
        return self._get_field_value(13, 1)
    @use_l2_lpts.setter
    def use_l2_lpts(self, value):
        self._set_field_value('field use_l2_lpts', 13, 1, int, value)
    @property
    def prefix(self):
        return self._get_field_value(8, 5)
    @prefix.setter
    def prefix(self, value):
        self._set_field_value('field prefix', 8, 5, int, value)
    @property
    def compound_termination_control(self):
        return npl_compound_termination_control_t._get_as_sub_field(self._data, self._offset_in_data + 6)
    @compound_termination_control.setter
    def compound_termination_control(self, value):
        self._set_field_value('field compound_termination_control', 6, 2, npl_compound_termination_control_t, value)
    @property
    def is_ipv4_mc(self):
        return self._get_field_value(5, 1)
    @is_ipv4_mc.setter
    def is_ipv4_mc(self, value):
        self._set_field_value('field is_ipv4_mc', 5, 1, int, value)
    @property
    def is_ipv6_mc(self):
        return self._get_field_value(4, 1)
    @is_ipv6_mc.setter
    def is_ipv6_mc(self, value):
        self._set_field_value('field is_ipv6_mc', 4, 1, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_mac_da_tos_pack_payload_t(basic_npl_struct):
    def __init__(self, dscp=0, v4_ttl=0, v6_ttl=0, hln=0, tos=0):
        super().__init__(34)
        self.dscp = dscp
        self.v4_ttl = v4_ttl
        self.v6_ttl = v6_ttl
        self.hln = hln
        self.tos = tos

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_da_tos_pack_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dscp(self):
        return self._get_field_value(28, 6)
    @dscp.setter
    def dscp(self, value):
        self._set_field_value('field dscp', 28, 6, int, value)
    @property
    def v4_ttl(self):
        return self._get_field_value(20, 8)
    @v4_ttl.setter
    def v4_ttl(self, value):
        self._set_field_value('field v4_ttl', 20, 8, int, value)
    @property
    def v6_ttl(self):
        return self._get_field_value(12, 8)
    @v6_ttl.setter
    def v6_ttl(self, value):
        self._set_field_value('field v6_ttl', 12, 8, int, value)
    @property
    def hln(self):
        return self._get_field_value(8, 4)
    @hln.setter
    def hln(self, value):
        self._set_field_value('field hln', 8, 4, int, value)
    @property
    def tos(self):
        return self._get_field_value(0, 8)
    @tos.setter
    def tos(self, value):
        self._set_field_value('field tos', 0, 8, int, value)



class npl_mac_l2_relay_attributes_t(basic_npl_struct):
    def __init__(self, bd_attributes=0, flood_destination=0, drop_unknown_bc=0, drop_unknown_mc=0, drop_unknown_uc=0, mld_snooping=0, igmp_snooping=0, is_svi=0):
        super().__init__(34)
        self.bd_attributes = bd_attributes
        self.flood_destination = flood_destination
        self.drop_unknown_bc = drop_unknown_bc
        self.drop_unknown_mc = drop_unknown_mc
        self.drop_unknown_uc = drop_unknown_uc
        self.mld_snooping = mld_snooping
        self.igmp_snooping = igmp_snooping
        self.is_svi = is_svi

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_l2_relay_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def bd_attributes(self):
        return npl_bd_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 26)
    @bd_attributes.setter
    def bd_attributes(self, value):
        self._set_field_value('field bd_attributes', 26, 8, npl_bd_attributes_t, value)
    @property
    def flood_destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 6)
    @flood_destination.setter
    def flood_destination(self, value):
        self._set_field_value('field flood_destination', 6, 20, npl_destination_t, value)
    @property
    def drop_unknown_bc(self):
        return self._get_field_value(5, 1)
    @drop_unknown_bc.setter
    def drop_unknown_bc(self, value):
        self._set_field_value('field drop_unknown_bc', 5, 1, int, value)
    @property
    def drop_unknown_mc(self):
        return self._get_field_value(4, 1)
    @drop_unknown_mc.setter
    def drop_unknown_mc(self, value):
        self._set_field_value('field drop_unknown_mc', 4, 1, int, value)
    @property
    def drop_unknown_uc(self):
        return self._get_field_value(3, 1)
    @drop_unknown_uc.setter
    def drop_unknown_uc(self, value):
        self._set_field_value('field drop_unknown_uc', 3, 1, int, value)
    @property
    def mld_snooping(self):
        return self._get_field_value(2, 1)
    @mld_snooping.setter
    def mld_snooping(self, value):
        self._set_field_value('field mld_snooping', 2, 1, int, value)
    @property
    def igmp_snooping(self):
        return self._get_field_value(1, 1)
    @igmp_snooping.setter
    def igmp_snooping(self, value):
        self._set_field_value('field igmp_snooping', 1, 1, int, value)
    @property
    def is_svi(self):
        return self._get_field_value(0, 1)
    @is_svi.setter
    def is_svi(self, value):
        self._set_field_value('field is_svi', 0, 1, int, value)



class npl_mac_l3_remark_pack_payload_t(basic_npl_struct):
    def __init__(self, ipv6_tos=0, ipv4_tos=0, mpls_exp_bos=0):
        super().__init__(20)
        self.ipv6_tos = ipv6_tos
        self.ipv4_tos = ipv4_tos
        self.mpls_exp_bos = mpls_exp_bos

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_l3_remark_pack_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ipv6_tos(self):
        return self._get_field_value(12, 8)
    @ipv6_tos.setter
    def ipv6_tos(self, value):
        self._set_field_value('field ipv6_tos', 12, 8, int, value)
    @property
    def ipv4_tos(self):
        return self._get_field_value(4, 8)
    @ipv4_tos.setter
    def ipv4_tos(self, value):
        self._set_field_value('field ipv4_tos', 4, 8, int, value)
    @property
    def mpls_exp_bos(self):
        return self._get_field_value(0, 4)
    @mpls_exp_bos.setter
    def mpls_exp_bos(self, value):
        self._set_field_value('field mpls_exp_bos', 0, 4, int, value)



class npl_mac_relay_g_destination_pad_t(basic_npl_struct):
    def __init__(self, dest=0):
        super().__init__(20)
        self.dest = dest

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_relay_g_destination_pad_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dest(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dest.setter
    def dest(self, value):
        self._set_field_value('field dest', 0, 20, npl_destination_t, value)



class npl_mac_relay_g_destination_t(basic_npl_struct):
    def __init__(self, destination=0):
        super().__init__(20)
        self.destination = destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_relay_g_destination_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 20, npl_destination_t, value)



class npl_mact_result_t(basic_npl_struct):
    def __init__(self, application_specific_fields=0, destination=0):
        super().__init__(32)
        self.application_specific_fields = application_specific_fields
        self.destination = destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mact_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def application_specific_fields(self):
        return self._get_field_value(20, 12)
    @application_specific_fields.setter
    def application_specific_fields(self, value):
        self._set_field_value('field application_specific_fields', 20, 12, int, value)
    @property
    def destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 20, npl_destination_t, value)



class npl_mapping_qos_tag_packed_result_t(basic_npl_struct):
    def __init__(self, fwd_hdr_type_v6=0, mapping_qos_tag=0, eth_ene_macro_id=0, el_label_exp_bos_inner_label_bos_1=0, el_label_exp_bos_inner_label_bos_0=0):
        super().__init__(32)
        self.fwd_hdr_type_v6 = fwd_hdr_type_v6
        self.mapping_qos_tag = mapping_qos_tag
        self.eth_ene_macro_id = eth_ene_macro_id
        self.el_label_exp_bos_inner_label_bos_1 = el_label_exp_bos_inner_label_bos_1
        self.el_label_exp_bos_inner_label_bos_0 = el_label_exp_bos_inner_label_bos_0

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mapping_qos_tag_packed_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def fwd_hdr_type_v6(self):
        return self._get_field_value(31, 1)
    @fwd_hdr_type_v6.setter
    def fwd_hdr_type_v6(self, value):
        self._set_field_value('field fwd_hdr_type_v6', 31, 1, int, value)
    @property
    def mapping_qos_tag(self):
        return self._get_field_value(24, 7)
    @mapping_qos_tag.setter
    def mapping_qos_tag(self, value):
        self._set_field_value('field mapping_qos_tag', 24, 7, int, value)
    @property
    def eth_ene_macro_id(self):
        return npl_ene_macro_id_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @eth_ene_macro_id.setter
    def eth_ene_macro_id(self, value):
        self._set_field_value('field eth_ene_macro_id', 16, 8, npl_ene_macro_id_t, value)
    @property
    def el_label_exp_bos_inner_label_bos_1(self):
        return self._get_field_value(8, 8)
    @el_label_exp_bos_inner_label_bos_1.setter
    def el_label_exp_bos_inner_label_bos_1(self, value):
        self._set_field_value('field el_label_exp_bos_inner_label_bos_1', 8, 8, int, value)
    @property
    def el_label_exp_bos_inner_label_bos_0(self):
        return self._get_field_value(0, 8)
    @el_label_exp_bos_inner_label_bos_0.setter
    def el_label_exp_bos_inner_label_bos_0(self, value):
        self._set_field_value('field el_label_exp_bos_inner_label_bos_0', 0, 8, int, value)



class npl_mc_bitmap_base_voq_lookup_table_result_t(basic_npl_struct):
    def __init__(self, tc_map_profile=0, base_voq=0):
        super().__init__(18)
        self.tc_map_profile = tc_map_profile
        self.base_voq = base_voq

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_bitmap_base_voq_lookup_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tc_map_profile(self):
        return self._get_field_value(16, 2)
    @tc_map_profile.setter
    def tc_map_profile(self, value):
        self._set_field_value('field tc_map_profile', 16, 2, int, value)
    @property
    def base_voq(self):
        return self._get_field_value(0, 16)
    @base_voq.setter
    def base_voq(self, value):
        self._set_field_value('field base_voq', 0, 16, int, value)



class npl_mc_bitmap_t(basic_npl_struct):
    def __init__(self, bitmap_indicator=0, bitmap=0):
        super().__init__(11)
        self.bitmap_indicator = bitmap_indicator
        self.bitmap = bitmap

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_bitmap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def bitmap_indicator(self):
        return self._get_field_value(6, 5)
    @bitmap_indicator.setter
    def bitmap_indicator(self, value):
        self._set_field_value('field bitmap_indicator', 6, 5, int, value)
    @property
    def bitmap(self):
        return self._get_field_value(0, 6)
    @bitmap.setter
    def bitmap(self, value):
        self._set_field_value('field bitmap', 0, 6, int, value)



class npl_mc_copy_id_t(basic_npl_struct):
    def __init__(self, val=0):
        super().__init__(18)
        self.val = val

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_copy_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def val(self):
        return self._get_field_value(0, 18)
    @val.setter
    def val(self, value):
        self._set_field_value('field val', 0, 18, int, value)



class npl_mc_em_db__key_t(basic_npl_struct):
    def __init__(self, is_tx=0, slice_or_is_fabric=0, is_rcy=0, mcid=0, entry_index=0):
        super().__init__(32)
        self.is_tx = is_tx
        self.slice_or_is_fabric = slice_or_is_fabric
        self.is_rcy = is_rcy
        self.mcid = mcid
        self.entry_index = entry_index

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_em_db__key_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_tx(self):
        return self._get_field_value(31, 1)
    @is_tx.setter
    def is_tx(self, value):
        self._set_field_value('field is_tx', 31, 1, int, value)
    @property
    def slice_or_is_fabric(self):
        return self._get_field_value(28, 3)
    @slice_or_is_fabric.setter
    def slice_or_is_fabric(self, value):
        self._set_field_value('field slice_or_is_fabric', 28, 3, int, value)
    @property
    def is_rcy(self):
        return self._get_field_value(27, 1)
    @is_rcy.setter
    def is_rcy(self, value):
        self._set_field_value('field is_rcy', 27, 1, int, value)
    @property
    def mcid(self):
        return self._get_field_value(11, 16)
    @mcid.setter
    def mcid(self, value):
        self._set_field_value('field mcid', 11, 16, int, value)
    @property
    def entry_index(self):
        return self._get_field_value(0, 11)
    @entry_index.setter
    def entry_index(self, value):
        self._set_field_value('field entry_index', 0, 11, int, value)



class npl_mc_em_db_result_tx_format_1_t(basic_npl_struct):
    def __init__(self, copy_bitmap=0, bmp_map_profile=0, tc_map_profile=0, mc_copy_id=0):
        super().__init__(71)
        self.copy_bitmap = copy_bitmap
        self.bmp_map_profile = bmp_map_profile
        self.tc_map_profile = tc_map_profile
        self.mc_copy_id = mc_copy_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_em_db_result_tx_format_1_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def copy_bitmap(self):
        return self._get_field_value(23, 48)
    @copy_bitmap.setter
    def copy_bitmap(self, value):
        self._set_field_value('field copy_bitmap', 23, 48, int, value)
    @property
    def bmp_map_profile(self):
        return self._get_field_value(21, 2)
    @bmp_map_profile.setter
    def bmp_map_profile(self, value):
        self._set_field_value('field bmp_map_profile', 21, 2, int, value)
    @property
    def tc_map_profile(self):
        return self._get_field_value(18, 3)
    @tc_map_profile.setter
    def tc_map_profile(self, value):
        self._set_field_value('field tc_map_profile', 18, 3, int, value)
    @property
    def mc_copy_id(self):
        return self._get_field_value(0, 18)
    @mc_copy_id.setter
    def mc_copy_id(self, value):
        self._set_field_value('field mc_copy_id', 0, 18, int, value)



class npl_mc_fe_links_bmp_db_result_t(basic_npl_struct):
    def __init__(self, use_bitmap_directly=0, fe_links_bmp=0):
        super().__init__(109)
        self.use_bitmap_directly = use_bitmap_directly
        self.fe_links_bmp = fe_links_bmp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_fe_links_bmp_db_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def use_bitmap_directly(self):
        return self._get_field_value(108, 1)
    @use_bitmap_directly.setter
    def use_bitmap_directly(self, value):
        self._set_field_value('field use_bitmap_directly', 108, 1, int, value)
    @property
    def fe_links_bmp(self):
        return self._get_field_value(0, 108)
    @fe_links_bmp.setter
    def fe_links_bmp(self, value):
        self._set_field_value('field fe_links_bmp', 0, 108, int, value)



class npl_mc_macro_compressed_fields_t(basic_npl_struct):
    def __init__(self, is_inject_up=0, not_comp_single_src=0, curr_proto_type=0, q_m_counter_ptr=0):
        super().__init__(28)
        self.is_inject_up = is_inject_up
        self.not_comp_single_src = not_comp_single_src
        self.curr_proto_type = curr_proto_type
        self.q_m_counter_ptr = q_m_counter_ptr

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_macro_compressed_fields_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_inject_up(self):
        return self._get_field_value(26, 1)
    @is_inject_up.setter
    def is_inject_up(self, value):
        self._set_field_value('field is_inject_up', 26, 1, int, value)
    @property
    def not_comp_single_src(self):
        return self._get_field_value(25, 1)
    @not_comp_single_src.setter
    def not_comp_single_src(self, value):
        self._set_field_value('field not_comp_single_src', 25, 1, int, value)
    @property
    def curr_proto_type(self):
        return self._get_field_value(20, 5)
    @curr_proto_type.setter
    def curr_proto_type(self, value):
        self._set_field_value('field curr_proto_type', 20, 5, int, value)
    @property
    def q_m_counter_ptr(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @q_m_counter_ptr.setter
    def q_m_counter_ptr(self, value):
        self._set_field_value('field q_m_counter_ptr', 0, 20, npl_counter_ptr_t, value)



class npl_mc_rx_tc_map_profile_t(basic_npl_struct):
    def __init__(self, val=0):
        super().__init__(2)
        self.val = val

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_rx_tc_map_profile_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def val(self):
        return self._get_field_value(0, 2)
    @val.setter
    def val(self, value):
        self._set_field_value('field val', 0, 2, int, value)



class npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t(basic_npl_struct):
    def __init__(self):
        super().__init__(11)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def group_size(self):
        return self._get_field_value(0, 11)
    @group_size.setter
    def group_size(self, value):
        self._set_field_value('field group_size', 0, 11, int, value)
    @property
    def mc_bitmap(self):
        return npl_mc_bitmap_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mc_bitmap.setter
    def mc_bitmap(self, value):
        self._set_field_value('field mc_bitmap', 0, 11, npl_mc_bitmap_t, value)



class npl_mc_tx_tc_map_profile_t(basic_npl_struct):
    def __init__(self, val=0):
        super().__init__(3)
        self.val = val

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_tx_tc_map_profile_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def val(self):
        return self._get_field_value(0, 3)
    @val.setter
    def val(self, value):
        self._set_field_value('field val', 0, 3, int, value)



class npl_mcid_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(16)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mcid_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 16)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 16, int, value)



class npl_meg_id_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(120)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_meg_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 120)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 120, int, value)



class npl_meter_action_profile_len_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(2)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_meter_action_profile_len_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 2)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 2, int, value)



class npl_meter_count_mode_len_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(1)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_meter_count_mode_len_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 1)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 1, int, value)



class npl_meter_mode_len_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(1)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_meter_mode_len_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 1)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 1, int, value)



class npl_meter_profile_len_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(4)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_meter_profile_len_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 4)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 4, int, value)



class npl_meter_weight_t(basic_npl_struct):
    def __init__(self, weight_factor=0, weight=0):
        super().__init__(10)
        self.weight_factor = weight_factor
        self.weight = weight

    def _get_as_sub_field(data, offset_in_data):
        result = npl_meter_weight_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def weight_factor(self):
        return self._get_field_value(5, 5)
    @weight_factor.setter
    def weight_factor(self, value):
        self._set_field_value('field weight_factor', 5, 5, int, value)
    @property
    def weight(self):
        return self._get_field_value(0, 5)
    @weight.setter
    def weight(self, value):
        self._set_field_value('field weight', 0, 5, int, value)



class npl_mii_loopback_data_t(basic_npl_struct):
    def __init__(self, mode=0):
        super().__init__(2)
        self.mode = mode

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mii_loopback_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mode(self):
        return self._get_field_value(0, 2)
    @mode.setter
    def mode(self, value):
        self._set_field_value('field mode', 0, 2, int, value)



class npl_mismatch_indications_t(basic_npl_struct):
    def __init__(self, issu_codespace=0, first_packet_size=0, is_single_fragment=0):
        super().__init__(3)
        self.issu_codespace = issu_codespace
        self.first_packet_size = first_packet_size
        self.is_single_fragment = is_single_fragment

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mismatch_indications_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def issu_codespace(self):
        return self._get_field_value(2, 1)
    @issu_codespace.setter
    def issu_codespace(self, value):
        self._set_field_value('field issu_codespace', 2, 1, int, value)
    @property
    def first_packet_size(self):
        return self._get_field_value(1, 1)
    @first_packet_size.setter
    def first_packet_size(self, value):
        self._set_field_value('field first_packet_size', 1, 1, int, value)
    @property
    def is_single_fragment(self):
        return self._get_field_value(0, 1)
    @is_single_fragment.setter
    def is_single_fragment(self, value):
        self._set_field_value('field is_single_fragment', 0, 1, int, value)



class npl_mldp_protection_entry_t(basic_npl_struct):
    def __init__(self, drop_protect=0, drop_primary=0):
        super().__init__(2)
        self.drop_protect = drop_protect
        self.drop_primary = drop_primary

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mldp_protection_entry_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def drop_protect(self):
        return npl_bool_t._get_as_sub_field(self._data, self._offset_in_data + 1)
    @drop_protect.setter
    def drop_protect(self, value):
        self._set_field_value('field drop_protect', 1, 1, npl_bool_t, value)
    @property
    def drop_primary(self):
        return npl_bool_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @drop_primary.setter
    def drop_primary(self, value):
        self._set_field_value('field drop_primary', 0, 1, npl_bool_t, value)



class npl_mldp_protection_id_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(9)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mldp_protection_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 9)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 9, int, value)



class npl_mldp_protection_t(basic_npl_struct):
    def __init__(self, id=0, sel=0):
        super().__init__(10)
        self.id = id
        self.sel = sel

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mldp_protection_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return npl_mldp_protection_id_t._get_as_sub_field(self._data, self._offset_in_data + 1)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 1, 9, npl_mldp_protection_id_t, value)
    @property
    def sel(self):
        return self._get_field_value(0, 1)
    @sel.setter
    def sel(self, value):
        self._set_field_value('field sel', 0, 1, int, value)



class npl_more_labels_index_t(basic_npl_struct):
    def __init__(self, more_labels_index=0):
        super().__init__(12)
        self.more_labels_index = more_labels_index

    def _get_as_sub_field(data, offset_in_data):
        result = npl_more_labels_index_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def more_labels_index(self):
        return self._get_field_value(0, 12)
    @more_labels_index.setter
    def more_labels_index(self, value):
        self._set_field_value('field more_labels_index', 0, 12, int, value)



class npl_mp_table_app_t_anonymous_union_mp2_data_union_t(basic_npl_struct):
    def __init__(self):
        super().__init__(16)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_mp_table_app_t_anonymous_union_mp2_data_union_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def transmit_b(self):
        return npl_eth_mp_table_transmit_b_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @transmit_b.setter
    def transmit_b(self, value):
        self._set_field_value('field transmit_b', 0, 16, npl_eth_mp_table_transmit_b_payload_t, value)
    @property
    def bfd2(self):
        return npl_bfd_mp_table_transmit_b_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @bfd2.setter
    def bfd2(self, value):
        self._set_field_value('field bfd2', 0, 16, npl_bfd_mp_table_transmit_b_payload_t, value)
    @property
    def hw(self):
        return npl_hw_mp_table_app_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @hw.setter
    def hw(self, value):
        self._set_field_value('field hw', 0, 16, npl_hw_mp_table_app_t, value)



class npl_mpls_encap_control_bits_t(basic_npl_struct):
    def __init__(self, is_midpoint=0, mpls_labels_lookup=0, is_asbr_or_ldpote=0):
        super().__init__(3)
        self.is_midpoint = is_midpoint
        self.mpls_labels_lookup = mpls_labels_lookup
        self.is_asbr_or_ldpote = is_asbr_or_ldpote

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mpls_encap_control_bits_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_midpoint(self):
        return self._get_field_value(2, 1)
    @is_midpoint.setter
    def is_midpoint(self, value):
        self._set_field_value('field is_midpoint', 2, 1, int, value)
    @property
    def mpls_labels_lookup(self):
        return self._get_field_value(1, 1)
    @mpls_labels_lookup.setter
    def mpls_labels_lookup(self, value):
        self._set_field_value('field mpls_labels_lookup', 1, 1, int, value)
    @property
    def is_asbr_or_ldpote(self):
        return self._get_field_value(0, 1)
    @is_asbr_or_ldpote.setter
    def is_asbr_or_ldpote(self, value):
        self._set_field_value('field is_asbr_or_ldpote', 0, 1, int, value)



class npl_mpls_first_ene_macro_control_t(basic_npl_struct):
    def __init__(self, no_first_ene_macro=0, vpn_label_lookup=0, qos_first_macro_code=0):
        super().__init__(5)
        self.no_first_ene_macro = no_first_ene_macro
        self.vpn_label_lookup = vpn_label_lookup
        self.qos_first_macro_code = qos_first_macro_code

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mpls_first_ene_macro_control_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def no_first_ene_macro(self):
        return self._get_field_value(4, 1)
    @no_first_ene_macro.setter
    def no_first_ene_macro(self, value):
        self._set_field_value('field no_first_ene_macro', 4, 1, int, value)
    @property
    def vpn_label_lookup(self):
        return self._get_field_value(3, 1)
    @vpn_label_lookup.setter
    def vpn_label_lookup(self, value):
        self._set_field_value('field vpn_label_lookup', 3, 1, int, value)
    @property
    def qos_first_macro_code(self):
        return self._get_field_value(0, 3)
    @qos_first_macro_code.setter
    def qos_first_macro_code(self, value):
        self._set_field_value('field qos_first_macro_code', 0, 3, int, value)



class npl_mpls_header_flags_t(basic_npl_struct):
    def __init__(self, illegal_ipv4=0, is_null_labels=0, is_bos=0):
        super().__init__(3)
        self.illegal_ipv4 = illegal_ipv4
        self.is_null_labels = is_null_labels
        self.is_bos = is_bos

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mpls_header_flags_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def illegal_ipv4(self):
        return self._get_field_value(2, 1)
    @illegal_ipv4.setter
    def illegal_ipv4(self, value):
        self._set_field_value('field illegal_ipv4', 2, 1, int, value)
    @property
    def is_null_labels(self):
        return self._get_field_value(1, 1)
    @is_null_labels.setter
    def is_null_labels(self, value):
        self._set_field_value('field is_null_labels', 1, 1, int, value)
    @property
    def is_bos(self):
        return self._get_field_value(0, 1)
    @is_bos.setter
    def is_bos(self, value):
        self._set_field_value('field is_bos', 0, 1, int, value)



class npl_mpls_header_t(basic_npl_struct):
    def __init__(self, label=0, exp=0, bos=0, ttl=0):
        super().__init__(32)
        self.label = label
        self.exp = exp
        self.bos = bos
        self.ttl = ttl

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mpls_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def label(self):
        return self._get_field_value(12, 20)
    @label.setter
    def label(self, value):
        self._set_field_value('field label', 12, 20, int, value)
    @property
    def exp(self):
        return self._get_field_value(9, 3)
    @exp.setter
    def exp(self, value):
        self._set_field_value('field exp', 9, 3, int, value)
    @property
    def bos(self):
        return self._get_field_value(8, 1)
    @bos.setter
    def bos(self, value):
        self._set_field_value('field bos', 8, 1, int, value)
    @property
    def ttl(self):
        return self._get_field_value(0, 8)
    @ttl.setter
    def ttl(self, value):
        self._set_field_value('field ttl', 0, 8, int, value)



class npl_mpls_relay_packed_labels_t(basic_npl_struct):
    def __init__(self, adjust_next_hdr_offset=0, label_above_null=0, next_label_above_null=0):
        super().__init__(56)
        self.adjust_next_hdr_offset = adjust_next_hdr_offset
        self.label_above_null = label_above_null
        self.next_label_above_null = next_label_above_null

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mpls_relay_packed_labels_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def adjust_next_hdr_offset(self):
        return self._get_field_value(48, 8)
    @adjust_next_hdr_offset.setter
    def adjust_next_hdr_offset(self, value):
        self._set_field_value('field adjust_next_hdr_offset', 48, 8, int, value)
    @property
    def label_above_null(self):
        return npl_mpls_header_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @label_above_null.setter
    def label_above_null(self, value):
        self._set_field_value('field label_above_null', 16, 32, npl_mpls_header_t, value)
    @property
    def next_label_above_null(self):
        return self._get_field_value(0, 16)
    @next_label_above_null.setter
    def next_label_above_null(self, value):
        self._set_field_value('field next_label_above_null', 0, 16, int, value)



class npl_mpls_termination_mldp_t(basic_npl_struct):
    def __init__(self, rpf_id=0):
        super().__init__(16)
        self.rpf_id = rpf_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mpls_termination_mldp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rpf_id(self):
        return self._get_field_value(0, 16)
    @rpf_id.setter
    def rpf_id(self, value):
        self._set_field_value('field rpf_id', 0, 16, int, value)



class npl_mpls_tp_em_t(basic_npl_struct):
    def __init__(self, dummy=0):
        super().__init__(40)
        self.dummy = dummy

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mpls_tp_em_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dummy(self):
        return self._get_field_value(0, 40)
    @dummy.setter
    def dummy(self, value):
        self._set_field_value('field dummy', 0, 40, int, value)



class npl_mpls_traps_t(basic_npl_struct):
    def __init__(self, unknown_protocol_after_bos=0, ttl_is_zero=0, bfd_over_pwe_ttl=0, bfd_over_pwe_raw=0, bfd_over_pwe_ipv4=0, bfd_over_pwe_ipv6=0, unknown_bfd_g_ach_channel_type=0, bfd_over_pwe_ra=0, mpls_tp_over_pwe=0, unknown_g_ach=0, mpls_tp_over_lsp=0, oam_alert_label=0, extension_label=0, router_alert_label=0, unexpected_reserved_label=0, forwarding_disabled=0, ilm_miss=0, ipv4_over_ipv6_explicit_null=0, invalid_ttl=0, te_midpopint_ldp_labels_miss=0, asbr_label_miss=0, ilm_vrf_label_miss=0, pwe_pwach=0, vpn_ttl_one=0, missing_fwd_label_after_pop=0):
        super().__init__(25)
        self.unknown_protocol_after_bos = unknown_protocol_after_bos
        self.ttl_is_zero = ttl_is_zero
        self.bfd_over_pwe_ttl = bfd_over_pwe_ttl
        self.bfd_over_pwe_raw = bfd_over_pwe_raw
        self.bfd_over_pwe_ipv4 = bfd_over_pwe_ipv4
        self.bfd_over_pwe_ipv6 = bfd_over_pwe_ipv6
        self.unknown_bfd_g_ach_channel_type = unknown_bfd_g_ach_channel_type
        self.bfd_over_pwe_ra = bfd_over_pwe_ra
        self.mpls_tp_over_pwe = mpls_tp_over_pwe
        self.unknown_g_ach = unknown_g_ach
        self.mpls_tp_over_lsp = mpls_tp_over_lsp
        self.oam_alert_label = oam_alert_label
        self.extension_label = extension_label
        self.router_alert_label = router_alert_label
        self.unexpected_reserved_label = unexpected_reserved_label
        self.forwarding_disabled = forwarding_disabled
        self.ilm_miss = ilm_miss
        self.ipv4_over_ipv6_explicit_null = ipv4_over_ipv6_explicit_null
        self.invalid_ttl = invalid_ttl
        self.te_midpopint_ldp_labels_miss = te_midpopint_ldp_labels_miss
        self.asbr_label_miss = asbr_label_miss
        self.ilm_vrf_label_miss = ilm_vrf_label_miss
        self.pwe_pwach = pwe_pwach
        self.vpn_ttl_one = vpn_ttl_one
        self.missing_fwd_label_after_pop = missing_fwd_label_after_pop

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mpls_traps_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def unknown_protocol_after_bos(self):
        return self._get_field_value(24, 1)
    @unknown_protocol_after_bos.setter
    def unknown_protocol_after_bos(self, value):
        self._set_field_value('field unknown_protocol_after_bos', 24, 1, int, value)
    @property
    def ttl_is_zero(self):
        return self._get_field_value(23, 1)
    @ttl_is_zero.setter
    def ttl_is_zero(self, value):
        self._set_field_value('field ttl_is_zero', 23, 1, int, value)
    @property
    def bfd_over_pwe_ttl(self):
        return self._get_field_value(22, 1)
    @bfd_over_pwe_ttl.setter
    def bfd_over_pwe_ttl(self, value):
        self._set_field_value('field bfd_over_pwe_ttl', 22, 1, int, value)
    @property
    def bfd_over_pwe_raw(self):
        return self._get_field_value(21, 1)
    @bfd_over_pwe_raw.setter
    def bfd_over_pwe_raw(self, value):
        self._set_field_value('field bfd_over_pwe_raw', 21, 1, int, value)
    @property
    def bfd_over_pwe_ipv4(self):
        return self._get_field_value(20, 1)
    @bfd_over_pwe_ipv4.setter
    def bfd_over_pwe_ipv4(self, value):
        self._set_field_value('field bfd_over_pwe_ipv4', 20, 1, int, value)
    @property
    def bfd_over_pwe_ipv6(self):
        return self._get_field_value(19, 1)
    @bfd_over_pwe_ipv6.setter
    def bfd_over_pwe_ipv6(self, value):
        self._set_field_value('field bfd_over_pwe_ipv6', 19, 1, int, value)
    @property
    def unknown_bfd_g_ach_channel_type(self):
        return self._get_field_value(18, 1)
    @unknown_bfd_g_ach_channel_type.setter
    def unknown_bfd_g_ach_channel_type(self, value):
        self._set_field_value('field unknown_bfd_g_ach_channel_type', 18, 1, int, value)
    @property
    def bfd_over_pwe_ra(self):
        return self._get_field_value(17, 1)
    @bfd_over_pwe_ra.setter
    def bfd_over_pwe_ra(self, value):
        self._set_field_value('field bfd_over_pwe_ra', 17, 1, int, value)
    @property
    def mpls_tp_over_pwe(self):
        return self._get_field_value(16, 1)
    @mpls_tp_over_pwe.setter
    def mpls_tp_over_pwe(self, value):
        self._set_field_value('field mpls_tp_over_pwe', 16, 1, int, value)
    @property
    def unknown_g_ach(self):
        return self._get_field_value(15, 1)
    @unknown_g_ach.setter
    def unknown_g_ach(self, value):
        self._set_field_value('field unknown_g_ach', 15, 1, int, value)
    @property
    def mpls_tp_over_lsp(self):
        return self._get_field_value(14, 1)
    @mpls_tp_over_lsp.setter
    def mpls_tp_over_lsp(self, value):
        self._set_field_value('field mpls_tp_over_lsp', 14, 1, int, value)
    @property
    def oam_alert_label(self):
        return self._get_field_value(13, 1)
    @oam_alert_label.setter
    def oam_alert_label(self, value):
        self._set_field_value('field oam_alert_label', 13, 1, int, value)
    @property
    def extension_label(self):
        return self._get_field_value(12, 1)
    @extension_label.setter
    def extension_label(self, value):
        self._set_field_value('field extension_label', 12, 1, int, value)
    @property
    def router_alert_label(self):
        return self._get_field_value(11, 1)
    @router_alert_label.setter
    def router_alert_label(self, value):
        self._set_field_value('field router_alert_label', 11, 1, int, value)
    @property
    def unexpected_reserved_label(self):
        return self._get_field_value(10, 1)
    @unexpected_reserved_label.setter
    def unexpected_reserved_label(self, value):
        self._set_field_value('field unexpected_reserved_label', 10, 1, int, value)
    @property
    def forwarding_disabled(self):
        return self._get_field_value(9, 1)
    @forwarding_disabled.setter
    def forwarding_disabled(self, value):
        self._set_field_value('field forwarding_disabled', 9, 1, int, value)
    @property
    def ilm_miss(self):
        return self._get_field_value(8, 1)
    @ilm_miss.setter
    def ilm_miss(self, value):
        self._set_field_value('field ilm_miss', 8, 1, int, value)
    @property
    def ipv4_over_ipv6_explicit_null(self):
        return self._get_field_value(7, 1)
    @ipv4_over_ipv6_explicit_null.setter
    def ipv4_over_ipv6_explicit_null(self, value):
        self._set_field_value('field ipv4_over_ipv6_explicit_null', 7, 1, int, value)
    @property
    def invalid_ttl(self):
        return self._get_field_value(6, 1)
    @invalid_ttl.setter
    def invalid_ttl(self, value):
        self._set_field_value('field invalid_ttl', 6, 1, int, value)
    @property
    def te_midpopint_ldp_labels_miss(self):
        return self._get_field_value(5, 1)
    @te_midpopint_ldp_labels_miss.setter
    def te_midpopint_ldp_labels_miss(self, value):
        self._set_field_value('field te_midpopint_ldp_labels_miss', 5, 1, int, value)
    @property
    def asbr_label_miss(self):
        return self._get_field_value(4, 1)
    @asbr_label_miss.setter
    def asbr_label_miss(self, value):
        self._set_field_value('field asbr_label_miss', 4, 1, int, value)
    @property
    def ilm_vrf_label_miss(self):
        return self._get_field_value(3, 1)
    @ilm_vrf_label_miss.setter
    def ilm_vrf_label_miss(self, value):
        self._set_field_value('field ilm_vrf_label_miss', 3, 1, int, value)
    @property
    def pwe_pwach(self):
        return self._get_field_value(2, 1)
    @pwe_pwach.setter
    def pwe_pwach(self, value):
        self._set_field_value('field pwe_pwach', 2, 1, int, value)
    @property
    def vpn_ttl_one(self):
        return self._get_field_value(1, 1)
    @vpn_ttl_one.setter
    def vpn_ttl_one(self, value):
        self._set_field_value('field vpn_ttl_one', 1, 1, int, value)
    @property
    def missing_fwd_label_after_pop(self):
        return self._get_field_value(0, 1)
    @missing_fwd_label_after_pop.setter
    def missing_fwd_label_after_pop(self, value):
        self._set_field_value('field missing_fwd_label_after_pop', 0, 1, int, value)



class npl_ms_voq_fabric_context_offset_table_result_t(basic_npl_struct):
    def __init__(self, ms_voq_fabric_context_offset=0):
        super().__init__(16)
        self.ms_voq_fabric_context_offset = ms_voq_fabric_context_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ms_voq_fabric_context_offset_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ms_voq_fabric_context_offset(self):
        return self._get_field_value(0, 16)
    @ms_voq_fabric_context_offset.setter
    def ms_voq_fabric_context_offset(self, value):
        self._set_field_value('field ms_voq_fabric_context_offset', 0, 16, int, value)



class npl_mtu_and_pkt_size_t(basic_npl_struct):
    def __init__(self, muxed_pad_constant=0, dsp_mtu=0, pd_pkt_size=0):
        super().__init__(46)
        self.muxed_pad_constant = muxed_pad_constant
        self.dsp_mtu = dsp_mtu
        self.pd_pkt_size = pd_pkt_size

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mtu_and_pkt_size_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def muxed_pad_constant(self):
        return self._get_field_value(32, 14)
    @muxed_pad_constant.setter
    def muxed_pad_constant(self, value):
        self._set_field_value('field muxed_pad_constant', 32, 14, int, value)
    @property
    def dsp_mtu(self):
        return self._get_field_value(16, 14)
    @dsp_mtu.setter
    def dsp_mtu(self, value):
        self._set_field_value('field dsp_mtu', 16, 14, int, value)
    @property
    def pd_pkt_size(self):
        return self._get_field_value(0, 14)
    @pd_pkt_size.setter
    def pd_pkt_size(self, value):
        self._set_field_value('field pd_pkt_size', 0, 14, int, value)



class npl_native_fec_destination1_t(basic_npl_struct):
    def __init__(self, enc_type=0, destination=0, type=0):
        super().__init__(56)
        self.enc_type = enc_type
        self.destination = destination
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_fec_destination1_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enc_type(self):
        return self._get_field_value(52, 4)
    @enc_type.setter
    def enc_type(self, value):
        self._set_field_value('field enc_type', 52, 4, int, value)
    @property
    def destination(self):
        return self._get_field_value(4, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 4, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_fec_destination_t(basic_npl_struct):
    def __init__(self, destination=0, type=0):
        super().__init__(56)
        self.destination = destination
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_fec_destination_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return self._get_field_value(4, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 4, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_fec_raw_t(basic_npl_struct):
    def __init__(self, payload=0, type=0):
        super().__init__(56)
        self.payload = payload
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_fec_raw_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return self._get_field_value(4, 52)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 4, 52, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_fec_table_result_t(basic_npl_struct):
    def __init__(self):
        super().__init__(56)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_fec_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return npl_native_fec_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 56, npl_native_fec_destination_t, value)
    @property
    def destination1(self):
        return npl_native_fec_destination1_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination1.setter
    def destination1(self, value):
        self._set_field_value('field destination1', 0, 56, npl_native_fec_destination1_t, value)
    @property
    def raw(self):
        return npl_native_fec_raw_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 56, npl_native_fec_raw_t, value)



class npl_native_frr_destination_frr_protection_t(basic_npl_struct):
    def __init__(self, frr_protection=0, destination=0, type=0):
        super().__init__(52)
        self.frr_protection = frr_protection
        self.destination = destination
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_frr_destination_frr_protection_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def frr_protection(self):
        return self._get_field_value(24, 8)
    @frr_protection.setter
    def frr_protection(self, value):
        self._set_field_value('field frr_protection', 24, 8, int, value)
    @property
    def destination(self):
        return self._get_field_value(4, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 4, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_frr_protected_raw_t(basic_npl_struct):
    def __init__(self, payload=0, type=0):
        super().__init__(52)
        self.payload = payload
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_frr_protected_raw_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return self._get_field_value(4, 48)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 4, 48, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_frr_table_protection_entry_t(basic_npl_struct):
    def __init__(self):
        super().__init__(52)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_frr_table_protection_entry_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination_frr_protection(self):
        return npl_native_frr_destination_frr_protection_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination_frr_protection.setter
    def destination_frr_protection(self, value):
        self._set_field_value('field destination_frr_protection', 0, 52, npl_native_frr_destination_frr_protection_t, value)
    @property
    def raw(self):
        return npl_native_frr_protected_raw_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 52, npl_native_frr_protected_raw_t, value)



class npl_native_l2_lp_bvn_l2_dlp_t(basic_npl_struct):
    def __init__(self, l2_dlp=0, bvn=0, type=0):
        super().__init__(41)
        self.l2_dlp = l2_dlp
        self.bvn = bvn
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_bvn_l2_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2_dlp(self):
        return self._get_field_value(20, 18)
    @l2_dlp.setter
    def l2_dlp(self, value):
        self._set_field_value('field l2_dlp', 20, 18, int, value)
    @property
    def bvn(self):
        return self._get_field_value(4, 16)
    @bvn.setter
    def bvn(self, value):
        self._set_field_value('field bvn', 4, 16, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_l2_lp_destination1_t(basic_npl_struct):
    def __init__(self, destination=0, type=0):
        super().__init__(24)
        self.destination = destination
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_destination1_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return self._get_field_value(4, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 4, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_l2_lp_destination2_t(basic_npl_struct):
    def __init__(self, destination=0, type=0):
        super().__init__(24)
        self.destination = destination
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_destination2_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return self._get_field_value(4, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 4, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_l2_lp_destination_ip_tunnel_t(basic_npl_struct):
    def __init__(self, enc_type=0, ip_tunnel=0, destination=0, type=0):
        super().__init__(48)
        self.enc_type = enc_type
        self.ip_tunnel = ip_tunnel
        self.destination = destination
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_destination_ip_tunnel_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enc_type(self):
        return self._get_field_value(44, 4)
    @enc_type.setter
    def enc_type(self, value):
        self._set_field_value('field enc_type', 44, 4, int, value)
    @property
    def ip_tunnel(self):
        return self._get_field_value(24, 16)
    @ip_tunnel.setter
    def ip_tunnel(self, value):
        self._set_field_value('field ip_tunnel', 24, 16, int, value)
    @property
    def destination(self):
        return self._get_field_value(4, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 4, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_l2_lp_destination_overlay_nh_t(basic_npl_struct):
    def __init__(self, enc_type=0, overlay_nh=0, destination=0, type=0):
        super().__init__(48)
        self.enc_type = enc_type
        self.overlay_nh = overlay_nh
        self.destination = destination
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_destination_overlay_nh_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enc_type(self):
        return self._get_field_value(44, 4)
    @enc_type.setter
    def enc_type(self, value):
        self._set_field_value('field enc_type', 44, 4, int, value)
    @property
    def overlay_nh(self):
        return self._get_field_value(24, 10)
    @overlay_nh.setter
    def overlay_nh(self, value):
        self._set_field_value('field overlay_nh', 24, 10, int, value)
    @property
    def destination(self):
        return self._get_field_value(4, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 4, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_l2_lp_destination_t(basic_npl_struct):
    def __init__(self, destination=0, type=0):
        super().__init__(24)
        self.destination = destination
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_destination_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return self._get_field_value(4, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 4, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_l2_lp_destination_te_tunnel16b_t(basic_npl_struct):
    def __init__(self, enc_type=0, te_tunnel16b=0, destination=0, type=0):
        super().__init__(48)
        self.enc_type = enc_type
        self.te_tunnel16b = te_tunnel16b
        self.destination = destination
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_destination_te_tunnel16b_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enc_type(self):
        return self._get_field_value(44, 4)
    @enc_type.setter
    def enc_type(self, value):
        self._set_field_value('field enc_type', 44, 4, int, value)
    @property
    def te_tunnel16b(self):
        return self._get_field_value(24, 16)
    @te_tunnel16b.setter
    def te_tunnel16b(self, value):
        self._set_field_value('field te_tunnel16b', 24, 16, int, value)
    @property
    def destination(self):
        return self._get_field_value(4, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 4, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_l2_lp_dsp_l2_dlp_t(basic_npl_struct):
    def __init__(self, enc_type=0, l2_dlp=0, dsp=0, type=0):
        super().__init__(41)
        self.enc_type = enc_type
        self.l2_dlp = l2_dlp
        self.dsp = dsp
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_dsp_l2_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enc_type(self):
        return self._get_field_value(37, 4)
    @enc_type.setter
    def enc_type(self, value):
        self._set_field_value('field enc_type', 37, 4, int, value)
    @property
    def l2_dlp(self):
        return self._get_field_value(16, 18)
    @l2_dlp.setter
    def l2_dlp(self, value):
        self._set_field_value('field l2_dlp', 16, 18, int, value)
    @property
    def dsp(self):
        return self._get_field_value(4, 12)
    @dsp.setter
    def dsp(self, value):
        self._set_field_value('field dsp', 4, 12, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_l2_lp_dspa_l2_dlp_t(basic_npl_struct):
    def __init__(self, enc_type=0, l2_dlp=0, dspa=0, type=0):
        super().__init__(41)
        self.enc_type = enc_type
        self.l2_dlp = l2_dlp
        self.dspa = dspa
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_dspa_l2_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enc_type(self):
        return self._get_field_value(37, 4)
    @enc_type.setter
    def enc_type(self, value):
        self._set_field_value('field enc_type', 37, 4, int, value)
    @property
    def l2_dlp(self):
        return self._get_field_value(17, 18)
    @l2_dlp.setter
    def l2_dlp(self, value):
        self._set_field_value('field l2_dlp', 17, 18, int, value)
    @property
    def dspa(self):
        return self._get_field_value(4, 13)
    @dspa.setter
    def dspa(self, value):
        self._set_field_value('field dspa', 4, 13, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_l2_lp_narrow_raw_t(basic_npl_struct):
    def __init__(self, payload=0, type=0):
        super().__init__(24)
        self.payload = payload
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_narrow_raw_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return self._get_field_value(4, 20)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 4, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_l2_lp_protected_raw_t(basic_npl_struct):
    def __init__(self, payload=0, type=0):
        super().__init__(41)
        self.payload = payload
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_protected_raw_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return self._get_field_value(4, 37)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 4, 37, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_l2_lp_stage2_ecmp_ce_ptr_t(basic_npl_struct):
    def __init__(self, ce_ptr=0, stage2_ecmp=0, type=0):
        super().__init__(41)
        self.ce_ptr = ce_ptr
        self.stage2_ecmp = stage2_ecmp
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_stage2_ecmp_ce_ptr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ce_ptr(self):
        return self._get_field_value(17, 18)
    @ce_ptr.setter
    def ce_ptr(self, value):
        self._set_field_value('field ce_ptr', 17, 18, int, value)
    @property
    def stage2_ecmp(self):
        return self._get_field_value(4, 13)
    @stage2_ecmp.setter
    def stage2_ecmp(self, value):
        self._set_field_value('field stage2_ecmp', 4, 13, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t(basic_npl_struct):
    def __init__(self, vpn_inter_as=0, stage2_ecmp=0, type=0):
        super().__init__(24)
        self.vpn_inter_as = vpn_inter_as
        self.stage2_ecmp = stage2_ecmp
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def vpn_inter_as(self):
        return self._get_field_value(17, 2)
    @vpn_inter_as.setter
    def vpn_inter_as(self, value):
        self._set_field_value('field vpn_inter_as', 17, 2, int, value)
    @property
    def stage2_ecmp(self):
        return self._get_field_value(4, 13)
    @stage2_ecmp.setter
    def stage2_ecmp(self, value):
        self._set_field_value('field stage2_ecmp', 4, 13, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_l2_lp_stage2_p_nh_ce_ptr_t(basic_npl_struct):
    def __init__(self, enc_type=0, ce_ptr=0, stage2_p_nh=0, type=0):
        super().__init__(41)
        self.enc_type = enc_type
        self.ce_ptr = ce_ptr
        self.stage2_p_nh = stage2_p_nh
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_stage2_p_nh_ce_ptr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enc_type(self):
        return self._get_field_value(37, 4)
    @enc_type.setter
    def enc_type(self, value):
        self._set_field_value('field enc_type', 37, 4, int, value)
    @property
    def ce_ptr(self):
        return self._get_field_value(16, 18)
    @ce_ptr.setter
    def ce_ptr(self, value):
        self._set_field_value('field ce_ptr', 16, 18, int, value)
    @property
    def stage2_p_nh(self):
        return self._get_field_value(4, 12)
    @stage2_p_nh.setter
    def stage2_p_nh(self, value):
        self._set_field_value('field stage2_p_nh', 4, 12, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_l2_lp_stage3_nh_ce_ptr_t(basic_npl_struct):
    def __init__(self, enc_type=0, ce_ptr=0, stage3_nh=0, type=0):
        super().__init__(41)
        self.enc_type = enc_type
        self.ce_ptr = ce_ptr
        self.stage3_nh = stage3_nh
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_stage3_nh_ce_ptr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enc_type(self):
        return self._get_field_value(37, 4)
    @enc_type.setter
    def enc_type(self, value):
        self._set_field_value('field enc_type', 37, 4, int, value)
    @property
    def ce_ptr(self):
        return self._get_field_value(16, 18)
    @ce_ptr.setter
    def ce_ptr(self, value):
        self._set_field_value('field ce_ptr', 16, 18, int, value)
    @property
    def stage3_nh(self):
        return self._get_field_value(4, 12)
    @stage3_nh.setter
    def stage3_nh(self, value):
        self._set_field_value('field stage3_nh', 4, 12, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_l2_lp_table_protection_entry_t(basic_npl_struct):
    def __init__(self):
        super().__init__(41)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_table_protection_entry_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dsp_l2_dlp(self):
        return npl_native_l2_lp_dsp_l2_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dsp_l2_dlp.setter
    def dsp_l2_dlp(self, value):
        self._set_field_value('field dsp_l2_dlp', 0, 41, npl_native_l2_lp_dsp_l2_dlp_t, value)
    @property
    def dspa_l2_dlp(self):
        return npl_native_l2_lp_dspa_l2_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dspa_l2_dlp.setter
    def dspa_l2_dlp(self, value):
        self._set_field_value('field dspa_l2_dlp', 0, 41, npl_native_l2_lp_dspa_l2_dlp_t, value)
    @property
    def bvn_l2_dlp(self):
        return npl_native_l2_lp_bvn_l2_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @bvn_l2_dlp.setter
    def bvn_l2_dlp(self, value):
        self._set_field_value('field bvn_l2_dlp', 0, 41, npl_native_l2_lp_bvn_l2_dlp_t, value)
    @property
    def raw(self):
        return npl_native_l2_lp_protected_raw_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 41, npl_native_l2_lp_protected_raw_t, value)



class npl_native_l2_lp_table_result_narrow_t(basic_npl_struct):
    def __init__(self):
        super().__init__(24)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_table_result_narrow_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return npl_native_l2_lp_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 24, npl_native_l2_lp_destination_t, value)
    @property
    def destination1(self):
        return npl_native_l2_lp_destination1_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination1.setter
    def destination1(self, value):
        self._set_field_value('field destination1', 0, 24, npl_native_l2_lp_destination1_t, value)
    @property
    def destination2(self):
        return npl_native_l2_lp_destination2_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination2.setter
    def destination2(self, value):
        self._set_field_value('field destination2', 0, 24, npl_native_l2_lp_destination2_t, value)
    @property
    def stage2_ecmp_vpn_inter_as(self):
        return npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @stage2_ecmp_vpn_inter_as.setter
    def stage2_ecmp_vpn_inter_as(self, value):
        self._set_field_value('field stage2_ecmp_vpn_inter_as', 0, 24, npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t, value)
    @property
    def raw(self):
        return npl_native_l2_lp_narrow_raw_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 24, npl_native_l2_lp_narrow_raw_t, value)



class npl_native_l2_lp_wide_raw_t(basic_npl_struct):
    def __init__(self, payload=0, type=0):
        super().__init__(48)
        self.payload = payload
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_wide_raw_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return self._get_field_value(4, 44)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 4, 44, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_lb_destination1_t(basic_npl_struct):
    def __init__(self, destination=0, type=0):
        super().__init__(49)
        self.destination = destination
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_lb_destination1_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return self._get_field_value(4, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 4, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_lb_destination2_t(basic_npl_struct):
    def __init__(self, enc_type=0, destination=0, type=0):
        super().__init__(49)
        self.enc_type = enc_type
        self.destination = destination
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_lb_destination2_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enc_type(self):
        return self._get_field_value(45, 4)
    @enc_type.setter
    def enc_type(self, value):
        self._set_field_value('field enc_type', 45, 4, int, value)
    @property
    def destination(self):
        return self._get_field_value(4, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 4, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_lb_destination_t(basic_npl_struct):
    def __init__(self, destination=0, type=0):
        super().__init__(49)
        self.destination = destination
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_lb_destination_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return self._get_field_value(4, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 4, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_lb_raw_t(basic_npl_struct):
    def __init__(self, payload=0, type=0):
        super().__init__(49)
        self.payload = payload
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_lb_raw_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return self._get_field_value(4, 45)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 4, 45, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 4, int, value)



class npl_native_lb_table_result_t(basic_npl_struct):
    def __init__(self):
        super().__init__(49)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_lb_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return npl_native_lb_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 49, npl_native_lb_destination_t, value)
    @property
    def destination1(self):
        return npl_native_lb_destination1_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination1.setter
    def destination1(self, value):
        self._set_field_value('field destination1', 0, 49, npl_native_lb_destination1_t, value)
    @property
    def destination2(self):
        return npl_native_lb_destination2_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination2.setter
    def destination2(self, value):
        self._set_field_value('field destination2', 0, 49, npl_native_lb_destination2_t, value)
    @property
    def raw(self):
        return npl_native_lb_raw_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 49, npl_native_lb_raw_t, value)



class npl_native_protection_id_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(13)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_protection_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 13)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 13, int, value)



class npl_next_header_and_hop_limit_t(basic_npl_struct):
    def __init__(self, next_header=0, hop_limit=0):
        super().__init__(16)
        self.next_header = next_header
        self.hop_limit = hop_limit

    def _get_as_sub_field(data, offset_in_data):
        result = npl_next_header_and_hop_limit_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def next_header(self):
        return self._get_field_value(8, 8)
    @next_header.setter
    def next_header(self, value):
        self._set_field_value('field next_header', 8, 8, int, value)
    @property
    def hop_limit(self):
        return self._get_field_value(0, 8)
    @hop_limit.setter
    def hop_limit(self, value):
        self._set_field_value('field hop_limit', 0, 8, int, value)



class npl_nhlfe_type_attributes_t(basic_npl_struct):
    def __init__(self, encap_type=0, midpoint_nh_destination_encoding=0):
        super().__init__(24)
        self.encap_type = encap_type
        self.midpoint_nh_destination_encoding = midpoint_nh_destination_encoding

    def _get_as_sub_field(data, offset_in_data):
        result = npl_nhlfe_type_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def encap_type(self):
        return self._get_field_value(20, 4)
    @encap_type.setter
    def encap_type(self, value):
        self._set_field_value('field encap_type', 20, 4, int, value)
    @property
    def midpoint_nh_destination_encoding(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @midpoint_nh_destination_encoding.setter
    def midpoint_nh_destination_encoding(self, value):
        self._set_field_value('field midpoint_nh_destination_encoding', 0, 20, npl_destination_t, value)



class npl_no_acls_t(basic_npl_struct):
    def __init__(self, no_acls=0):
        super().__init__(2)
        self.no_acls = no_acls

    def _get_as_sub_field(data, offset_in_data):
        result = npl_no_acls_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def no_acls(self):
        return self._get_field_value(0, 1)
    @no_acls.setter
    def no_acls(self, value):
        self._set_field_value('field no_acls', 0, 1, int, value)



class npl_npl_internal_info_t(basic_npl_struct):
    def __init__(self):
        super().__init__(8)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_npl_internal_info_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tx_redirect_code(self):
        return self._get_field_value(0, 8)
    @tx_redirect_code.setter
    def tx_redirect_code(self, value):
        self._set_field_value('field tx_redirect_code', 0, 8, int, value)



class npl_npp_protection_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(10)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_npp_protection_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 10)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 10, int, value)



class npl_npu_app_pack_fields_t(basic_npl_struct):
    def __init__(self, force_pipe_ttl=0, is_inject_up_and_ip_first_fragment=0, ttl=0):
        super().__init__(12)
        self.force_pipe_ttl = force_pipe_ttl
        self.is_inject_up_and_ip_first_fragment = is_inject_up_and_ip_first_fragment
        self.ttl = ttl

    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_app_pack_fields_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def force_pipe_ttl(self):
        return self._get_field_value(11, 1)
    @force_pipe_ttl.setter
    def force_pipe_ttl(self, value):
        self._set_field_value('field force_pipe_ttl', 11, 1, int, value)
    @property
    def is_inject_up_and_ip_first_fragment(self):
        return npl_is_inject_up_and_ip_first_fragment_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @is_inject_up_and_ip_first_fragment.setter
    def is_inject_up_and_ip_first_fragment(self, value):
        self._set_field_value('field is_inject_up_and_ip_first_fragment', 8, 3, npl_is_inject_up_and_ip_first_fragment_t, value)
    @property
    def ttl(self):
        return self._get_field_value(0, 8)
    @ttl.setter
    def ttl(self, value):
        self._set_field_value('field ttl', 0, 8, int, value)



class npl_npu_encap_header_l2_dlp_t(basic_npl_struct):
    def __init__(self, l2_dlp=0):
        super().__init__(20)
        self.l2_dlp = l2_dlp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_encap_header_l2_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2_dlp(self):
        return npl_l2_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_dlp.setter
    def l2_dlp(self, value):
        self._set_field_value('field l2_dlp', 0, 18, npl_l2_dlp_t, value)



class npl_npu_host_data_result_count_phase_t(basic_npl_struct):
    def __init__(self, mp_data=0, dm_count_phase=0, dm_period=0, lm_count_phase=0, lm_period=0, ccm_count_phase=0):
        super().__init__(181)
        self.mp_data = mp_data
        self.dm_count_phase = dm_count_phase
        self.dm_period = dm_period
        self.lm_count_phase = lm_count_phase
        self.lm_period = lm_period
        self.ccm_count_phase = ccm_count_phase

    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_host_data_result_count_phase_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mp_data(self):
        return self._get_field_value(42, 139)
    @mp_data.setter
    def mp_data(self, value):
        self._set_field_value('field mp_data', 42, 139, int, value)
    @property
    def dm_count_phase(self):
        return self._get_field_value(30, 12)
    @dm_count_phase.setter
    def dm_count_phase(self, value):
        self._set_field_value('field dm_count_phase', 30, 12, int, value)
    @property
    def dm_period(self):
        return self._get_field_value(27, 3)
    @dm_period.setter
    def dm_period(self, value):
        self._set_field_value('field dm_period', 27, 3, int, value)
    @property
    def lm_count_phase(self):
        return self._get_field_value(15, 12)
    @lm_count_phase.setter
    def lm_count_phase(self, value):
        self._set_field_value('field lm_count_phase', 15, 12, int, value)
    @property
    def lm_period(self):
        return self._get_field_value(12, 3)
    @lm_period.setter
    def lm_period(self, value):
        self._set_field_value('field lm_period', 12, 3, int, value)
    @property
    def ccm_count_phase(self):
        return self._get_field_value(0, 12)
    @ccm_count_phase.setter
    def ccm_count_phase(self, value):
        self._set_field_value('field ccm_count_phase', 0, 12, int, value)



class npl_npu_l3_mc_accounting_encap_data_t(basic_npl_struct):
    def __init__(self, mcg_counter_ptr=0):
        super().__init__(20)
        self.mcg_counter_ptr = mcg_counter_ptr

    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_l3_mc_accounting_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mcg_counter_ptr(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mcg_counter_ptr.setter
    def mcg_counter_ptr(self, value):
        self._set_field_value('field mcg_counter_ptr', 0, 20, npl_counter_ptr_t, value)



class npl_num_labels_t(basic_npl_struct):
    def __init__(self, total_num_labels=0):
        super().__init__(20)
        self.total_num_labels = total_num_labels

    def _get_as_sub_field(data, offset_in_data):
        result = npl_num_labels_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def total_num_labels(self):
        return self._get_field_value(0, 4)
    @total_num_labels.setter
    def total_num_labels(self, value):
        self._set_field_value('field total_num_labels', 0, 4, int, value)



class npl_num_outer_transport_labels_t(basic_npl_struct):
    def __init__(self, total_num_labels=0, num_labels_is_3=0):
        super().__init__(5)
        self.total_num_labels = total_num_labels
        self.num_labels_is_3 = num_labels_is_3

    def _get_as_sub_field(data, offset_in_data):
        result = npl_num_outer_transport_labels_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def total_num_labels(self):
        return self._get_field_value(1, 4)
    @total_num_labels.setter
    def total_num_labels(self, value):
        self._set_field_value('field total_num_labels', 1, 4, int, value)
    @property
    def num_labels_is_3(self):
        return self._get_field_value(0, 1)
    @num_labels_is_3.setter
    def num_labels_is_3(self, value):
        self._set_field_value('field num_labels_is_3', 0, 1, int, value)



class npl_oamp_traps_t(basic_npl_struct):
    def __init__(self, eth_unknown_punt_reason=0, eth_mep_mapping_failed=0, eth_mp_type_mismatch=0, eth_meg_level_mismatch=0, eth_bad_md_name_format=0, eth_unicast_da_no_match=0, eth_multicast_da_no_match=0, eth_wrong_meg_id_format=0, eth_meg_id_no_match=0, eth_ccm_period_no_match=0, eth_ccm_tlv_no_match=0, eth_lmm_tlv_no_match=0, eth_not_supported_oam_opcode=0, bfd_transport_not_supported=0, bfd_session_lookup_failed=0, bfd_incorrect_ttl=0, bfd_invalid_protocol=0, bfd_invalid_udp_port=0, bfd_incorrect_version=0, bfd_incorrect_address=0, bfd_mismatch_discr=0, bfd_state_flag_change=0, bfd_session_received=0, pfc_lookup_failed=0, pfc_drop_invalid_rx=0):
        super().__init__(25)
        self.eth_unknown_punt_reason = eth_unknown_punt_reason
        self.eth_mep_mapping_failed = eth_mep_mapping_failed
        self.eth_mp_type_mismatch = eth_mp_type_mismatch
        self.eth_meg_level_mismatch = eth_meg_level_mismatch
        self.eth_bad_md_name_format = eth_bad_md_name_format
        self.eth_unicast_da_no_match = eth_unicast_da_no_match
        self.eth_multicast_da_no_match = eth_multicast_da_no_match
        self.eth_wrong_meg_id_format = eth_wrong_meg_id_format
        self.eth_meg_id_no_match = eth_meg_id_no_match
        self.eth_ccm_period_no_match = eth_ccm_period_no_match
        self.eth_ccm_tlv_no_match = eth_ccm_tlv_no_match
        self.eth_lmm_tlv_no_match = eth_lmm_tlv_no_match
        self.eth_not_supported_oam_opcode = eth_not_supported_oam_opcode
        self.bfd_transport_not_supported = bfd_transport_not_supported
        self.bfd_session_lookup_failed = bfd_session_lookup_failed
        self.bfd_incorrect_ttl = bfd_incorrect_ttl
        self.bfd_invalid_protocol = bfd_invalid_protocol
        self.bfd_invalid_udp_port = bfd_invalid_udp_port
        self.bfd_incorrect_version = bfd_incorrect_version
        self.bfd_incorrect_address = bfd_incorrect_address
        self.bfd_mismatch_discr = bfd_mismatch_discr
        self.bfd_state_flag_change = bfd_state_flag_change
        self.bfd_session_received = bfd_session_received
        self.pfc_lookup_failed = pfc_lookup_failed
        self.pfc_drop_invalid_rx = pfc_drop_invalid_rx

    def _get_as_sub_field(data, offset_in_data):
        result = npl_oamp_traps_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def eth_unknown_punt_reason(self):
        return self._get_field_value(24, 1)
    @eth_unknown_punt_reason.setter
    def eth_unknown_punt_reason(self, value):
        self._set_field_value('field eth_unknown_punt_reason', 24, 1, int, value)
    @property
    def eth_mep_mapping_failed(self):
        return self._get_field_value(23, 1)
    @eth_mep_mapping_failed.setter
    def eth_mep_mapping_failed(self, value):
        self._set_field_value('field eth_mep_mapping_failed', 23, 1, int, value)
    @property
    def eth_mp_type_mismatch(self):
        return self._get_field_value(22, 1)
    @eth_mp_type_mismatch.setter
    def eth_mp_type_mismatch(self, value):
        self._set_field_value('field eth_mp_type_mismatch', 22, 1, int, value)
    @property
    def eth_meg_level_mismatch(self):
        return self._get_field_value(21, 1)
    @eth_meg_level_mismatch.setter
    def eth_meg_level_mismatch(self, value):
        self._set_field_value('field eth_meg_level_mismatch', 21, 1, int, value)
    @property
    def eth_bad_md_name_format(self):
        return self._get_field_value(20, 1)
    @eth_bad_md_name_format.setter
    def eth_bad_md_name_format(self, value):
        self._set_field_value('field eth_bad_md_name_format', 20, 1, int, value)
    @property
    def eth_unicast_da_no_match(self):
        return self._get_field_value(19, 1)
    @eth_unicast_da_no_match.setter
    def eth_unicast_da_no_match(self, value):
        self._set_field_value('field eth_unicast_da_no_match', 19, 1, int, value)
    @property
    def eth_multicast_da_no_match(self):
        return self._get_field_value(18, 1)
    @eth_multicast_da_no_match.setter
    def eth_multicast_da_no_match(self, value):
        self._set_field_value('field eth_multicast_da_no_match', 18, 1, int, value)
    @property
    def eth_wrong_meg_id_format(self):
        return self._get_field_value(17, 1)
    @eth_wrong_meg_id_format.setter
    def eth_wrong_meg_id_format(self, value):
        self._set_field_value('field eth_wrong_meg_id_format', 17, 1, int, value)
    @property
    def eth_meg_id_no_match(self):
        return self._get_field_value(16, 1)
    @eth_meg_id_no_match.setter
    def eth_meg_id_no_match(self, value):
        self._set_field_value('field eth_meg_id_no_match', 16, 1, int, value)
    @property
    def eth_ccm_period_no_match(self):
        return self._get_field_value(15, 1)
    @eth_ccm_period_no_match.setter
    def eth_ccm_period_no_match(self, value):
        self._set_field_value('field eth_ccm_period_no_match', 15, 1, int, value)
    @property
    def eth_ccm_tlv_no_match(self):
        return self._get_field_value(14, 1)
    @eth_ccm_tlv_no_match.setter
    def eth_ccm_tlv_no_match(self, value):
        self._set_field_value('field eth_ccm_tlv_no_match', 14, 1, int, value)
    @property
    def eth_lmm_tlv_no_match(self):
        return self._get_field_value(13, 1)
    @eth_lmm_tlv_no_match.setter
    def eth_lmm_tlv_no_match(self, value):
        self._set_field_value('field eth_lmm_tlv_no_match', 13, 1, int, value)
    @property
    def eth_not_supported_oam_opcode(self):
        return self._get_field_value(12, 1)
    @eth_not_supported_oam_opcode.setter
    def eth_not_supported_oam_opcode(self, value):
        self._set_field_value('field eth_not_supported_oam_opcode', 12, 1, int, value)
    @property
    def bfd_transport_not_supported(self):
        return self._get_field_value(11, 1)
    @bfd_transport_not_supported.setter
    def bfd_transport_not_supported(self, value):
        self._set_field_value('field bfd_transport_not_supported', 11, 1, int, value)
    @property
    def bfd_session_lookup_failed(self):
        return self._get_field_value(10, 1)
    @bfd_session_lookup_failed.setter
    def bfd_session_lookup_failed(self, value):
        self._set_field_value('field bfd_session_lookup_failed', 10, 1, int, value)
    @property
    def bfd_incorrect_ttl(self):
        return self._get_field_value(9, 1)
    @bfd_incorrect_ttl.setter
    def bfd_incorrect_ttl(self, value):
        self._set_field_value('field bfd_incorrect_ttl', 9, 1, int, value)
    @property
    def bfd_invalid_protocol(self):
        return self._get_field_value(8, 1)
    @bfd_invalid_protocol.setter
    def bfd_invalid_protocol(self, value):
        self._set_field_value('field bfd_invalid_protocol', 8, 1, int, value)
    @property
    def bfd_invalid_udp_port(self):
        return self._get_field_value(7, 1)
    @bfd_invalid_udp_port.setter
    def bfd_invalid_udp_port(self, value):
        self._set_field_value('field bfd_invalid_udp_port', 7, 1, int, value)
    @property
    def bfd_incorrect_version(self):
        return self._get_field_value(6, 1)
    @bfd_incorrect_version.setter
    def bfd_incorrect_version(self, value):
        self._set_field_value('field bfd_incorrect_version', 6, 1, int, value)
    @property
    def bfd_incorrect_address(self):
        return self._get_field_value(5, 1)
    @bfd_incorrect_address.setter
    def bfd_incorrect_address(self, value):
        self._set_field_value('field bfd_incorrect_address', 5, 1, int, value)
    @property
    def bfd_mismatch_discr(self):
        return self._get_field_value(4, 1)
    @bfd_mismatch_discr.setter
    def bfd_mismatch_discr(self, value):
        self._set_field_value('field bfd_mismatch_discr', 4, 1, int, value)
    @property
    def bfd_state_flag_change(self):
        return self._get_field_value(3, 1)
    @bfd_state_flag_change.setter
    def bfd_state_flag_change(self, value):
        self._set_field_value('field bfd_state_flag_change', 3, 1, int, value)
    @property
    def bfd_session_received(self):
        return self._get_field_value(2, 1)
    @bfd_session_received.setter
    def bfd_session_received(self, value):
        self._set_field_value('field bfd_session_received', 2, 1, int, value)
    @property
    def pfc_lookup_failed(self):
        return self._get_field_value(1, 1)
    @pfc_lookup_failed.setter
    def pfc_lookup_failed(self, value):
        self._set_field_value('field pfc_lookup_failed', 1, 1, int, value)
    @property
    def pfc_drop_invalid_rx(self):
        return self._get_field_value(0, 1)
    @pfc_drop_invalid_rx.setter
    def pfc_drop_invalid_rx(self, value):
        self._set_field_value('field pfc_drop_invalid_rx', 0, 1, int, value)



class npl_obm_to_inject_packed_vars_t(basic_npl_struct):
    def __init__(self, redirect_code=0, l2_slp=0):
        super().__init__(28)
        self.redirect_code = redirect_code
        self.l2_slp = l2_slp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_obm_to_inject_packed_vars_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def redirect_code(self):
        return self._get_field_value(20, 8)
    @redirect_code.setter
    def redirect_code(self, value):
        self._set_field_value('field redirect_code', 20, 8, int, value)
    @property
    def l2_slp(self):
        return self._get_field_value(0, 20)
    @l2_slp.setter
    def l2_slp(self, value):
        self._set_field_value('field l2_slp', 0, 20, int, value)



class npl_og_lpm_compression_code_t(basic_npl_struct):
    def __init__(self, bits_n_18=0, zero=0, bits_17_0=0):
        super().__init__(20)
        self.bits_n_18 = bits_n_18
        self.zero = zero
        self.bits_17_0 = bits_17_0

    def _get_as_sub_field(data, offset_in_data):
        result = npl_og_lpm_compression_code_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def bits_n_18(self):
        return self._get_field_value(19, 1)
    @bits_n_18.setter
    def bits_n_18(self, value):
        self._set_field_value('field bits_n_18', 19, 1, int, value)
    @property
    def zero(self):
        return self._get_field_value(18, 1)
    @zero.setter
    def zero(self, value):
        self._set_field_value('field zero', 18, 1, int, value)
    @property
    def bits_17_0(self):
        return self._get_field_value(0, 18)
    @bits_17_0.setter
    def bits_17_0(self, value):
        self._set_field_value('field bits_17_0', 0, 18, int, value)



class npl_og_lpts_compression_code_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(16)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_og_lpts_compression_code_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 16)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 16, int, value)



class npl_og_pcl_compress_t(basic_npl_struct):
    def __init__(self, src_compress=0, dest_compress=0):
        super().__init__(2)
        self.src_compress = src_compress
        self.dest_compress = dest_compress

    def _get_as_sub_field(data, offset_in_data):
        result = npl_og_pcl_compress_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def src_compress(self):
        return self._get_field_value(1, 1)
    @src_compress.setter
    def src_compress(self, value):
        self._set_field_value('field src_compress', 1, 1, int, value)
    @property
    def dest_compress(self):
        return self._get_field_value(0, 1)
    @dest_compress.setter
    def dest_compress(self, value):
        self._set_field_value('field dest_compress', 0, 1, int, value)



class npl_og_pcl_id_t(basic_npl_struct):
    def __init__(self, val=0):
        super().__init__(8)
        self.val = val

    def _get_as_sub_field(data, offset_in_data):
        result = npl_og_pcl_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def val(self):
        return self._get_field_value(0, 8)
    @val.setter
    def val(self, value):
        self._set_field_value('field val', 0, 8, int, value)



class npl_og_pcl_ids_t(basic_npl_struct):
    def __init__(self, src_pcl_id=0, dest_pcl_id=0):
        super().__init__(16)
        self.src_pcl_id = src_pcl_id
        self.dest_pcl_id = dest_pcl_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_og_pcl_ids_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def src_pcl_id(self):
        return npl_og_pcl_id_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @src_pcl_id.setter
    def src_pcl_id(self, value):
        self._set_field_value('field src_pcl_id', 8, 8, npl_og_pcl_id_t, value)
    @property
    def dest_pcl_id(self):
        return npl_og_pcl_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dest_pcl_id.setter
    def dest_pcl_id(self, value):
        self._set_field_value('field dest_pcl_id', 0, 8, npl_og_pcl_id_t, value)



class npl_og_pd_compression_code_t(basic_npl_struct):
    def __init__(self, bits_n_18=0, pad=0, bits_17_0=0):
        super().__init__(20)
        self.bits_n_18 = bits_n_18
        self.pad = pad
        self.bits_17_0 = bits_17_0

    def _get_as_sub_field(data, offset_in_data):
        result = npl_og_pd_compression_code_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def bits_n_18(self):
        return self._get_field_value(19, 1)
    @bits_n_18.setter
    def bits_n_18(self, value):
        self._set_field_value('field bits_n_18', 19, 1, int, value)
    @property
    def pad(self):
        return self._get_field_value(18, 1)
    @pad.setter
    def pad(self, value):
        self._set_field_value('field pad', 18, 1, int, value)
    @property
    def bits_17_0(self):
        return self._get_field_value(0, 18)
    @bits_17_0.setter
    def bits_17_0(self, value):
        self._set_field_value('field bits_17_0', 0, 18, int, value)



class npl_omd_txpp_parsed_t(basic_npl_struct):
    def __init__(self, oq_pair=0, pif=0, ifg=0):
        super().__init__(8)
        self.oq_pair = oq_pair
        self.pif = pif
        self.ifg = ifg

    def _get_as_sub_field(data, offset_in_data):
        result = npl_omd_txpp_parsed_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def oq_pair(self):
        return self._get_field_value(6, 2)
    @oq_pair.setter
    def oq_pair(self, value):
        self._set_field_value('field oq_pair', 6, 2, int, value)
    @property
    def pif(self):
        return self._get_field_value(1, 5)
    @pif.setter
    def pif(self, value):
        self._set_field_value('field pif', 1, 5, int, value)
    @property
    def ifg(self):
        return self._get_field_value(0, 1)
    @ifg.setter
    def ifg(self, value):
        self._set_field_value('field ifg', 0, 1, int, value)



class npl_oq_group_t(basic_npl_struct):
    def __init__(self, val=0):
        super().__init__(8)
        self.val = val

    def _get_as_sub_field(data, offset_in_data):
        result = npl_oq_group_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def val(self):
        return self._get_field_value(0, 8)
    @val.setter
    def val(self, value):
        self._set_field_value('field val', 0, 8, int, value)



class npl_oqse_pair_t(basic_npl_struct):
    def __init__(self, index=0):
        super().__init__(8)
        self.index = index

    def _get_as_sub_field(data, offset_in_data):
        result = npl_oqse_pair_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def index(self):
        return self._get_field_value(0, 8)
    @index.setter
    def index(self, value):
        self._set_field_value('field index', 0, 8, int, value)



class npl_oqse_topology_4p_t(basic_npl_struct):
    def __init__(self):
        super().__init__(2)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_oqse_topology_4p_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lpse_tpse_4p(self):
        return self._get_field_value(0, 2)
    @lpse_tpse_4p.setter
    def lpse_tpse_4p(self, value):
        self._set_field_value('field lpse_tpse_4p', 0, 2, int, value)
    @property
    def lpse_2p(self):
        return self._get_field_value(0, 2)
    @lpse_2p.setter
    def lpse_2p(self, value):
        self._set_field_value('field lpse_2p', 0, 2, int, value)



class npl_overlay_nh_data_t(basic_npl_struct):
    def __init__(self, mac_da=0, sa_prefix_index=0, sa_lsb=0):
        super().__init__(68)
        self.mac_da = mac_da
        self.sa_prefix_index = sa_prefix_index
        self.sa_lsb = sa_lsb

    def _get_as_sub_field(data, offset_in_data):
        result = npl_overlay_nh_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mac_da(self):
        return self._get_field_value(20, 48)
    @mac_da.setter
    def mac_da(self, value):
        self._set_field_value('field mac_da', 20, 48, int, value)
    @property
    def sa_prefix_index(self):
        return self._get_field_value(16, 4)
    @sa_prefix_index.setter
    def sa_prefix_index(self, value):
        self._set_field_value('field sa_prefix_index', 16, 4, int, value)
    @property
    def sa_lsb(self):
        return self._get_field_value(0, 16)
    @sa_lsb.setter
    def sa_lsb(self, value):
        self._set_field_value('field sa_lsb', 0, 16, int, value)



class npl_override_enable_ipv4_ipv6_uc_bits_t(basic_npl_struct):
    def __init__(self, override_enable_ipv4_uc=0, override_enable_ipv6_uc=0):
        super().__init__(2)
        self.override_enable_ipv4_uc = override_enable_ipv4_uc
        self.override_enable_ipv6_uc = override_enable_ipv6_uc

    def _get_as_sub_field(data, offset_in_data):
        result = npl_override_enable_ipv4_ipv6_uc_bits_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def override_enable_ipv4_uc(self):
        return self._get_field_value(1, 1)
    @override_enable_ipv4_uc.setter
    def override_enable_ipv4_uc(self, value):
        self._set_field_value('field override_enable_ipv4_uc', 1, 1, int, value)
    @property
    def override_enable_ipv6_uc(self):
        return self._get_field_value(0, 1)
    @override_enable_ipv6_uc.setter
    def override_enable_ipv6_uc(self, value):
        self._set_field_value('field override_enable_ipv6_uc', 0, 1, int, value)



class npl_packed_ud_160_key_t(basic_npl_struct):
    def __init__(self, key=0):
        super().__init__(160)
        self.key = key

    def _get_as_sub_field(data, offset_in_data):
        result = npl_packed_ud_160_key_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def key(self):
        return self._get_field_value(0, 160)
    @key.setter
    def key(self, value):
        self._set_field_value('field key', 0, 160, int, value)



class npl_packed_ud_320_key_t(basic_npl_struct):
    def __init__(self, key_part1=0, key_part0=0):
        super().__init__(320)
        self.key_part1 = key_part1
        self.key_part0 = key_part0

    def _get_as_sub_field(data, offset_in_data):
        result = npl_packed_ud_320_key_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def key_part1(self):
        return npl_packed_ud_160_key_t._get_as_sub_field(self._data, self._offset_in_data + 160)
    @key_part1.setter
    def key_part1(self, value):
        self._set_field_value('field key_part1', 160, 160, npl_packed_ud_160_key_t, value)
    @property
    def key_part0(self):
        return npl_packed_ud_160_key_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @key_part0.setter
    def key_part0(self, value):
        self._set_field_value('field key_part0', 0, 160, npl_packed_ud_160_key_t, value)



class npl_path_lb_destination1_t(basic_npl_struct):
    def __init__(self, destination=0, type=0):
        super().__init__(29)
        self.destination = destination
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lb_destination1_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return self._get_field_value(3, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 3, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 3)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 3, int, value)



class npl_path_lb_destination_t(basic_npl_struct):
    def __init__(self, enc_type=0, destination=0, type=0):
        super().__init__(29)
        self.enc_type = enc_type
        self.destination = destination
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lb_destination_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enc_type(self):
        return self._get_field_value(25, 4)
    @enc_type.setter
    def enc_type(self, value):
        self._set_field_value('field enc_type', 25, 4, int, value)
    @property
    def destination(self):
        return self._get_field_value(3, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 3, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 3)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 3, int, value)



class npl_path_lb_raw_t(basic_npl_struct):
    def __init__(self, payload=0, type=0):
        super().__init__(29)
        self.payload = payload
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lb_raw_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return self._get_field_value(3, 26)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 3, 26, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 3)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 3, int, value)



class npl_path_lb_stage2_p_nh_11b_asbr_t(basic_npl_struct):
    def __init__(self, asbr=0, stage2_p_nh_11b=0, type=0):
        super().__init__(29)
        self.asbr = asbr
        self.stage2_p_nh_11b = stage2_p_nh_11b
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lb_stage2_p_nh_11b_asbr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def asbr(self):
        return self._get_field_value(14, 15)
    @asbr.setter
    def asbr(self, value):
        self._set_field_value('field asbr', 14, 15, int, value)
    @property
    def stage2_p_nh_11b(self):
        return self._get_field_value(3, 11)
    @stage2_p_nh_11b.setter
    def stage2_p_nh_11b(self, value):
        self._set_field_value('field stage2_p_nh_11b', 3, 11, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 3)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 3, int, value)



class npl_path_lb_stage2_p_nh_te_tunnel14b1_t(basic_npl_struct):
    def __init__(self, te_tunnel14b=0, stage2_p_nh=0, type=0):
        super().__init__(29)
        self.te_tunnel14b = te_tunnel14b
        self.stage2_p_nh = stage2_p_nh
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lb_stage2_p_nh_te_tunnel14b1_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def te_tunnel14b(self):
        return self._get_field_value(15, 14)
    @te_tunnel14b.setter
    def te_tunnel14b(self, value):
        self._set_field_value('field te_tunnel14b', 15, 14, int, value)
    @property
    def stage2_p_nh(self):
        return self._get_field_value(3, 12)
    @stage2_p_nh.setter
    def stage2_p_nh(self, value):
        self._set_field_value('field stage2_p_nh', 3, 12, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 3)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 3, int, value)



class npl_path_lb_stage2_p_nh_te_tunnel14b_t(basic_npl_struct):
    def __init__(self, te_tunnel14b=0, stage2_p_nh=0, type=0):
        super().__init__(29)
        self.te_tunnel14b = te_tunnel14b
        self.stage2_p_nh = stage2_p_nh
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lb_stage2_p_nh_te_tunnel14b_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def te_tunnel14b(self):
        return self._get_field_value(15, 14)
    @te_tunnel14b.setter
    def te_tunnel14b(self, value):
        self._set_field_value('field te_tunnel14b', 15, 14, int, value)
    @property
    def stage2_p_nh(self):
        return self._get_field_value(3, 12)
    @stage2_p_nh.setter
    def stage2_p_nh(self, value):
        self._set_field_value('field stage2_p_nh', 3, 12, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 3)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 3, int, value)



class npl_path_lb_stage3_nh_11b_asbr_t(basic_npl_struct):
    def __init__(self, asbr=0, stage3_nh_11b=0, type=0):
        super().__init__(29)
        self.asbr = asbr
        self.stage3_nh_11b = stage3_nh_11b
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lb_stage3_nh_11b_asbr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def asbr(self):
        return self._get_field_value(14, 15)
    @asbr.setter
    def asbr(self, value):
        self._set_field_value('field asbr', 14, 15, int, value)
    @property
    def stage3_nh_11b(self):
        return self._get_field_value(3, 11)
    @stage3_nh_11b.setter
    def stage3_nh_11b(self, value):
        self._set_field_value('field stage3_nh_11b', 3, 11, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 3)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 3, int, value)



class npl_path_lb_stage3_nh_te_tunnel14b1_t(basic_npl_struct):
    def __init__(self, te_tunnel14b=0, stage3_nh=0, type=0):
        super().__init__(29)
        self.te_tunnel14b = te_tunnel14b
        self.stage3_nh = stage3_nh
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lb_stage3_nh_te_tunnel14b1_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def te_tunnel14b(self):
        return self._get_field_value(15, 14)
    @te_tunnel14b.setter
    def te_tunnel14b(self, value):
        self._set_field_value('field te_tunnel14b', 15, 14, int, value)
    @property
    def stage3_nh(self):
        return self._get_field_value(3, 12)
    @stage3_nh.setter
    def stage3_nh(self, value):
        self._set_field_value('field stage3_nh', 3, 12, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 3)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 3, int, value)



class npl_path_lb_stage3_nh_te_tunnel14b_t(basic_npl_struct):
    def __init__(self, te_tunnel14b=0, stage3_nh=0, type=0):
        super().__init__(29)
        self.te_tunnel14b = te_tunnel14b
        self.stage3_nh = stage3_nh
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lb_stage3_nh_te_tunnel14b_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def te_tunnel14b(self):
        return self._get_field_value(15, 14)
    @te_tunnel14b.setter
    def te_tunnel14b(self, value):
        self._set_field_value('field te_tunnel14b', 15, 14, int, value)
    @property
    def stage3_nh(self):
        return self._get_field_value(3, 12)
    @stage3_nh.setter
    def stage3_nh(self, value):
        self._set_field_value('field stage3_nh', 3, 12, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 3)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 3, int, value)



class npl_path_lp_narrow_raw_t(basic_npl_struct):
    def __init__(self, payload=0, type=0):
        super().__init__(20)
        self.payload = payload
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lp_narrow_raw_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return self._get_field_value(3, 17)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 3, 17, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 3)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 3, int, value)



class npl_path_lp_protected_raw_t(basic_npl_struct):
    def __init__(self, payload=0, type=0):
        super().__init__(34)
        self.payload = payload
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lp_protected_raw_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return self._get_field_value(3, 31)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 3, 31, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 3)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 3, int, value)



class npl_path_lp_stage3_nh1_t(basic_npl_struct):
    def __init__(self, stage3_nh=0, type=0):
        super().__init__(34)
        self.stage3_nh = stage3_nh
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lp_stage3_nh1_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def stage3_nh(self):
        return self._get_field_value(3, 12)
    @stage3_nh.setter
    def stage3_nh(self, value):
        self._set_field_value('field stage3_nh', 3, 12, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 3)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 3, int, value)



class npl_path_lp_stage3_nh_te_tunnel16b_t(basic_npl_struct):
    def __init__(self, te_tunnel16b=0, stage3_nh=0, type=0):
        super().__init__(34)
        self.te_tunnel16b = te_tunnel16b
        self.stage3_nh = stage3_nh
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lp_stage3_nh_te_tunnel16b_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def te_tunnel16b(self):
        return self._get_field_value(15, 16)
    @te_tunnel16b.setter
    def te_tunnel16b(self, value):
        self._set_field_value('field te_tunnel16b', 15, 16, int, value)
    @property
    def stage3_nh(self):
        return self._get_field_value(3, 12)
    @stage3_nh.setter
    def stage3_nh(self, value):
        self._set_field_value('field stage3_nh', 3, 12, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 3)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 3, int, value)



class npl_path_lp_table_protection_entry_t(basic_npl_struct):
    def __init__(self):
        super().__init__(34)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lp_table_protection_entry_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def stage3_nh1(self):
        return npl_path_lp_stage3_nh1_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @stage3_nh1.setter
    def stage3_nh1(self, value):
        self._set_field_value('field stage3_nh1', 0, 34, npl_path_lp_stage3_nh1_t, value)
    @property
    def stage3_nh_te_tunnel16b(self):
        return npl_path_lp_stage3_nh_te_tunnel16b_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @stage3_nh_te_tunnel16b.setter
    def stage3_nh_te_tunnel16b(self, value):
        self._set_field_value('field stage3_nh_te_tunnel16b', 0, 34, npl_path_lp_stage3_nh_te_tunnel16b_t, value)
    @property
    def raw(self):
        return npl_path_lp_protected_raw_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 34, npl_path_lp_protected_raw_t, value)



class npl_path_lp_table_result_narrow_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lp_table_result_narrow_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def raw(self):
        return npl_path_lp_narrow_raw_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 20, npl_path_lp_narrow_raw_t, value)



class npl_path_lp_wide_raw_t(basic_npl_struct):
    def __init__(self, payload=0, type=0):
        super().__init__(40)
        self.payload = payload
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lp_wide_raw_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return self._get_field_value(3, 37)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 3, 37, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 3)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 3, int, value)



class npl_path_protection_id_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(13)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_protection_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 13)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 13, int, value)



class npl_pbts_map_table_key_t(basic_npl_struct):
    def __init__(self, qos=0, profile=0):
        super().__init__(5)
        self.qos = qos
        self.profile = profile

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pbts_map_table_key_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def qos(self):
        return self._get_field_value(2, 3)
    @qos.setter
    def qos(self, value):
        self._set_field_value('field qos', 2, 3, int, value)
    @property
    def profile(self):
        return self._get_field_value(0, 2)
    @profile.setter
    def profile(self, value):
        self._set_field_value('field profile', 0, 2, int, value)



class npl_pbts_map_table_result_t(basic_npl_struct):
    def __init__(self, pbts_offset=0, destination_shift=0, and_mask=0):
        super().__init__(8)
        self.pbts_offset = pbts_offset
        self.destination_shift = destination_shift
        self.and_mask = and_mask

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pbts_map_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def pbts_offset(self):
        return self._get_field_value(5, 3)
    @pbts_offset.setter
    def pbts_offset(self, value):
        self._set_field_value('field pbts_offset', 5, 3, int, value)
    @property
    def destination_shift(self):
        return self._get_field_value(3, 2)
    @destination_shift.setter
    def destination_shift(self, value):
        self._set_field_value('field destination_shift', 3, 2, int, value)
    @property
    def and_mask(self):
        return self._get_field_value(0, 3)
    @and_mask.setter
    def and_mask(self, value):
        self._set_field_value('field and_mask', 0, 3, int, value)



class npl_pcp_dei_t(basic_npl_struct):
    def __init__(self, pcp=0, dei=0):
        super().__init__(4)
        self.pcp = pcp
        self.dei = dei

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pcp_dei_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def pcp(self):
        return self._get_field_value(1, 3)
    @pcp.setter
    def pcp(self, value):
        self._set_field_value('field pcp', 1, 3, int, value)
    @property
    def dei(self):
        return self._get_field_value(0, 1)
    @dei.setter
    def dei(self, value):
        self._set_field_value('field dei', 0, 1, int, value)



class npl_pd_lp_attributes_t(basic_npl_struct):
    def __init__(self, update=0):
        super().__init__(142)
        self.update = update

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pd_lp_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def update(self):
        return npl_lp_attr_update_raw_bits_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @update.setter
    def update(self, value):
        self._set_field_value('field update', 0, 120, npl_lp_attr_update_raw_bits_t, value)



class npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t(basic_npl_struct):
    def __init__(self):
        super().__init__(8)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def parsed(self):
        return npl_omd_txpp_parsed_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @parsed.setter
    def parsed(self, value):
        self._set_field_value('field parsed', 0, 8, npl_omd_txpp_parsed_t, value)
    @property
    def raw(self):
        return self._get_field_value(0, 8)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 8, int, value)



class npl_pdvoq_bank_pair_offset_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(1)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pdvoq_bank_pair_offset_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 1)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 1, int, value)



class npl_per_rtf_step_og_pcl_compress_bits_t(basic_npl_struct):
    def __init__(self, ipv4_compress_bits=0, ipv6_compress_bits=0):
        super().__init__(4)
        self.ipv4_compress_bits = ipv4_compress_bits
        self.ipv6_compress_bits = ipv6_compress_bits

    def _get_as_sub_field(data, offset_in_data):
        result = npl_per_rtf_step_og_pcl_compress_bits_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ipv4_compress_bits(self):
        return npl_og_pcl_compress_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @ipv4_compress_bits.setter
    def ipv4_compress_bits(self, value):
        self._set_field_value('field ipv4_compress_bits', 2, 2, npl_og_pcl_compress_t, value)
    @property
    def ipv6_compress_bits(self):
        return npl_og_pcl_compress_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ipv6_compress_bits.setter
    def ipv6_compress_bits(self, value):
        self._set_field_value('field ipv6_compress_bits', 0, 2, npl_og_pcl_compress_t, value)



class npl_per_rtf_step_og_pcl_ids_t(basic_npl_struct):
    def __init__(self, ipv4_og_pcl_ids=0, ipv6_og_pcl_ids=0):
        super().__init__(32)
        self.ipv4_og_pcl_ids = ipv4_og_pcl_ids
        self.ipv6_og_pcl_ids = ipv6_og_pcl_ids

    def _get_as_sub_field(data, offset_in_data):
        result = npl_per_rtf_step_og_pcl_ids_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ipv4_og_pcl_ids(self):
        return npl_og_pcl_ids_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @ipv4_og_pcl_ids.setter
    def ipv4_og_pcl_ids(self, value):
        self._set_field_value('field ipv4_og_pcl_ids', 16, 16, npl_og_pcl_ids_t, value)
    @property
    def ipv6_og_pcl_ids(self):
        return npl_og_pcl_ids_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ipv6_og_pcl_ids.setter
    def ipv6_og_pcl_ids(self, value):
        self._set_field_value('field ipv6_og_pcl_ids', 0, 16, npl_og_pcl_ids_t, value)



class npl_pfc_aux_payload_t(basic_npl_struct):
    def __init__(self, rx_counter=0):
        super().__init__(160)
        self.rx_counter = rx_counter

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pfc_aux_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rx_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 140)
    @rx_counter.setter
    def rx_counter(self, value):
        self._set_field_value('field rx_counter', 140, 20, npl_counter_ptr_t, value)



class npl_pfc_em_lookup_t(basic_npl_struct):
    def __init__(self, destination=0, some_padding=0):
        super().__init__(40)
        self.destination = destination
        self.some_padding = some_padding

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pfc_em_lookup_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return self._get_field_value(20, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 20, 20, int, value)
    @property
    def some_padding(self):
        return self._get_field_value(0, 20)
    @some_padding.setter
    def some_padding(self, value):
        self._set_field_value('field some_padding', 0, 20, int, value)



class npl_pfc_em_t(basic_npl_struct):
    def __init__(self, rmep_id=0, mep_id=0, access_rmep=0, mp_data_select=0, access_mp=0):
        super().__init__(40)
        self.rmep_id = rmep_id
        self.mep_id = mep_id
        self.access_rmep = access_rmep
        self.mp_data_select = mp_data_select
        self.access_mp = access_mp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pfc_em_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rmep_id(self):
        return self._get_field_value(16, 13)
    @rmep_id.setter
    def rmep_id(self, value):
        self._set_field_value('field rmep_id', 16, 13, int, value)
    @property
    def mep_id(self):
        return self._get_field_value(3, 13)
    @mep_id.setter
    def mep_id(self, value):
        self._set_field_value('field mep_id', 3, 13, int, value)
    @property
    def access_rmep(self):
        return self._get_field_value(2, 1)
    @access_rmep.setter
    def access_rmep(self, value):
        self._set_field_value('field access_rmep', 2, 1, int, value)
    @property
    def mp_data_select(self):
        return self._get_field_value(1, 1)
    @mp_data_select.setter
    def mp_data_select(self, value):
        self._set_field_value('field mp_data_select', 1, 1, int, value)
    @property
    def access_mp(self):
        return self._get_field_value(0, 1)
    @access_mp.setter
    def access_mp(self, value):
        self._set_field_value('field access_mp', 0, 1, int, value)



class npl_pfc_latency_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(16)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pfc_latency_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 16)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 16, int, value)



class npl_pfc_quanta_table_result_t(basic_npl_struct):
    def __init__(self, dual_entry=0):
        super().__init__(32)
        self.dual_entry = dual_entry

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pfc_quanta_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dual_entry(self):
        return self._get_field_value(0, 32)
    @dual_entry.setter
    def dual_entry(self, value):
        self._set_field_value('field dual_entry', 0, 32, int, value)



class npl_pfc_rx_counter_offset_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(4)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pfc_rx_counter_offset_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 4)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 4, int, value)



class npl_pfc_ssp_info_table_t(basic_npl_struct):
    def __init__(self, slice=0, mp_id=0):
        super().__init__(16)
        self.slice = slice
        self.mp_id = mp_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pfc_ssp_info_table_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def slice(self):
        return self._get_field_value(13, 3)
    @slice.setter
    def slice(self, value):
        self._set_field_value('field slice', 13, 3, int, value)
    @property
    def mp_id(self):
        return self._get_field_value(0, 13)
    @mp_id.setter
    def mp_id(self, value):
        self._set_field_value('field mp_id', 0, 13, int, value)



class npl_phb_t(basic_npl_struct):
    def __init__(self, tc=0, dp=0):
        super().__init__(5)
        self.tc = tc
        self.dp = dp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_phb_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tc(self):
        return self._get_field_value(2, 3)
    @tc.setter
    def tc(self, value):
        self._set_field_value('field tc', 2, 3, int, value)
    @property
    def dp(self):
        return self._get_field_value(0, 2)
    @dp.setter
    def dp(self, value):
        self._set_field_value('field dp', 0, 2, int, value)



class npl_pif_ifg_base_t(basic_npl_struct):
    def __init__(self, pif=0, ifg=0):
        super().__init__(6)
        self.pif = pif
        self.ifg = ifg

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pif_ifg_base_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def pif(self):
        return self._get_field_value(1, 5)
    @pif.setter
    def pif(self, value):
        self._set_field_value('field pif', 1, 5, int, value)
    @property
    def ifg(self):
        return self._get_field_value(0, 1)
    @ifg.setter
    def ifg(self, value):
        self._set_field_value('field ifg', 0, 1, int, value)



class npl_pma_loopback_data_t(basic_npl_struct):
    def __init__(self, mode=0):
        super().__init__(2)
        self.mode = mode

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pma_loopback_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mode(self):
        return self._get_field_value(0, 2)
    @mode.setter
    def mode(self, value):
        self._set_field_value('field mode', 0, 2, int, value)



class npl_port_dspa_dsp_t(basic_npl_struct):
    def __init__(self, dsp=0, type=0):
        super().__init__(15)
        self.dsp = dsp
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_port_dspa_dsp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dsp(self):
        return self._get_field_value(1, 12)
    @dsp.setter
    def dsp(self, value):
        self._set_field_value('field dsp', 1, 12, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 1)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 1, int, value)



class npl_port_dspa_raw_t(basic_npl_struct):
    def __init__(self, payload=0, type=0):
        super().__init__(15)
        self.payload = payload
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_port_dspa_raw_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return self._get_field_value(1, 14)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 1, 14, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 1)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 1, int, value)



class npl_port_dspa_table_result_t(basic_npl_struct):
    def __init__(self):
        super().__init__(15)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_port_dspa_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dsp(self):
        return npl_port_dspa_dsp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dsp.setter
    def dsp(self, value):
        self._set_field_value('field dsp', 0, 15, npl_port_dspa_dsp_t, value)
    @property
    def raw(self):
        return npl_port_dspa_raw_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 15, npl_port_dspa_raw_t, value)



class npl_port_npp_protection_protected_raw_t(basic_npl_struct):
    def __init__(self, payload=0, type=0):
        super().__init__(40)
        self.payload = payload
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_port_npp_protection_protected_raw_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return self._get_field_value(2, 38)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 2, 38, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 2)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 2, int, value)



class npl_port_npp_protection_table_protection_entry_t(basic_npl_struct):
    def __init__(self):
        super().__init__(40)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_port_npp_protection_table_protection_entry_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def raw(self):
        return npl_port_npp_protection_protected_raw_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 40, npl_port_npp_protection_protected_raw_t, value)



class npl_port_protection_id_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(10)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_port_protection_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 10)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 10, int, value)



class npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t(basic_npl_struct):
    def __init__(self):
        super().__init__(1)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_dlp_ip_type(self):
        return self._get_field_value(0, 1)
    @l3_dlp_ip_type.setter
    def l3_dlp_ip_type(self, value):
        self._set_field_value('field l3_dlp_ip_type', 0, 1, int, value)
    @property
    def enable_monitor(self):
        return npl_bool_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @enable_monitor.setter
    def enable_monitor(self, value):
        self._set_field_value('field enable_monitor', 0, 1, npl_bool_t, value)



class npl_protection_selector_t(basic_npl_struct):
    def __init__(self, sel=0):
        super().__init__(1)
        self.sel = sel

    def _get_as_sub_field(data, offset_in_data):
        result = npl_protection_selector_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sel(self):
        return self._get_field_value(0, 1)
    @sel.setter
    def sel(self, value):
        self._set_field_value('field sel', 0, 1, int, value)



class npl_protocol_type_padded_t(basic_npl_struct):
    def __init__(self, protocol_type=0):
        super().__init__(16)
        self.protocol_type = protocol_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_protocol_type_padded_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def protocol_type(self):
        return self._get_field_value(8, 8)
    @protocol_type.setter
    def protocol_type(self, value):
        self._set_field_value('field protocol_type', 8, 8, int, value)



class npl_punt_controls_t(basic_npl_struct):
    def __init__(self, punt_format=0, mirror_local_encap_format=0):
        super().__init__(3)
        self.punt_format = punt_format
        self.mirror_local_encap_format = mirror_local_encap_format

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_controls_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def punt_format(self):
        return self._get_field_value(1, 2)
    @punt_format.setter
    def punt_format(self, value):
        self._set_field_value('field punt_format', 1, 2, int, value)
    @property
    def mirror_local_encap_format(self):
        return self._get_field_value(0, 1)
    @mirror_local_encap_format.setter
    def mirror_local_encap_format(self, value):
        self._set_field_value('field mirror_local_encap_format', 0, 1, int, value)



class npl_punt_encap_data_lsb_t_anonymous_union_extra_t(basic_npl_struct):
    def __init__(self):
        super().__init__(1)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_encap_data_lsb_t_anonymous_union_extra_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lpts_meter_index_msb(self):
        return self._get_field_value(0, 1)
    @lpts_meter_index_msb.setter
    def lpts_meter_index_msb(self, value):
        self._set_field_value('field lpts_meter_index_msb', 0, 1, int, value)



class npl_punt_eth_transport_update_t(basic_npl_struct):
    def __init__(self, update=0):
        super().__init__(124)
        self.update = update

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_eth_transport_update_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def update(self):
        return self._get_field_value(0, 124)
    @update.setter
    def update(self, value):
        self._set_field_value('field update', 0, 124, int, value)



class npl_punt_header_t_anonymous_union_pl_header_offset_t(basic_npl_struct):
    def __init__(self):
        super().__init__(8)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_header_t_anonymous_union_pl_header_offset_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ingress_next_pl_offset(self):
        return self._get_field_value(0, 8)
    @ingress_next_pl_offset.setter
    def ingress_next_pl_offset(self, value):
        self._set_field_value('field ingress_next_pl_offset', 0, 8, int, value)
    @property
    def egress_current_pl_offset(self):
        return self._get_field_value(0, 8)
    @egress_current_pl_offset.setter
    def egress_current_pl_offset(self, value):
        self._set_field_value('field egress_current_pl_offset', 0, 8, int, value)



class npl_punt_l2_lp_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(18)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_l2_lp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 18)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 18, int, value)



class npl_punt_npu_host_macro_data_t(basic_npl_struct):
    def __init__(self, first_fi_macro_id=0, first_npe_macro_id=0):
        super().__init__(16)
        self.first_fi_macro_id = first_fi_macro_id
        self.first_npe_macro_id = first_npe_macro_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_npu_host_macro_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def first_fi_macro_id(self):
        return self._get_field_value(8, 8)
    @first_fi_macro_id.setter
    def first_fi_macro_id(self, value):
        self._set_field_value('field first_fi_macro_id', 8, 8, int, value)
    @property
    def first_npe_macro_id(self):
        return self._get_field_value(0, 8)
    @first_npe_macro_id.setter
    def first_npe_macro_id(self, value):
        self._set_field_value('field first_npe_macro_id', 0, 8, int, value)



class npl_punt_nw_encap_ptr_t(basic_npl_struct):
    def __init__(self, ptr=0):
        super().__init__(8)
        self.ptr = ptr

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_nw_encap_ptr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ptr(self):
        return self._get_field_value(0, 8)
    @ptr.setter
    def ptr(self, value):
        self._set_field_value('field ptr', 0, 8, int, value)



class npl_punt_rcy_pack_table_payload_t(basic_npl_struct):
    def __init__(self, ive_reset=0, redirect_code=0):
        super().__init__(24)
        self.ive_reset = ive_reset
        self.redirect_code = redirect_code

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_rcy_pack_table_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ive_reset(self):
        return self._get_field_value(8, 16)
    @ive_reset.setter
    def ive_reset(self, value):
        self._set_field_value('field ive_reset', 8, 16, int, value)
    @property
    def redirect_code(self):
        return self._get_field_value(0, 8)
    @redirect_code.setter
    def redirect_code(self, value):
        self._set_field_value('field redirect_code', 0, 8, int, value)



class npl_punt_ssp_t(basic_npl_struct):
    def __init__(self, slice_id=0, ssp_12=0):
        super().__init__(16)
        self.slice_id = slice_id
        self.ssp_12 = ssp_12

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_ssp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def slice_id(self):
        return self._get_field_value(12, 3)
    @slice_id.setter
    def slice_id(self, value):
        self._set_field_value('field slice_id', 12, 3, int, value)
    @property
    def ssp_12(self):
        return self._get_field_value(0, 12)
    @ssp_12.setter
    def ssp_12(self, value):
        self._set_field_value('field ssp_12', 0, 12, int, value)



class npl_punt_sub_code_t_anonymous_union_sub_code_t(basic_npl_struct):
    def __init__(self):
        super().__init__(4)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_sub_code_t_anonymous_union_sub_code_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lpts_flow_type(self):
        return npl_lpts_flow_type_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @lpts_flow_type.setter
    def lpts_flow_type(self, value):
        self._set_field_value('field lpts_flow_type', 0, 4, npl_lpts_flow_type_t, value)



class npl_pwe_to_l3_lookup_result_t(basic_npl_struct):
    def __init__(self, destination=0):
        super().__init__(20)
        self.destination = destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pwe_to_l3_lookup_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return self._get_field_value(0, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 20, int, value)



class npl_qos_and_acl_ids_t(basic_npl_struct):
    def __init__(self, qos_id=0, acl_id=0):
        super().__init__(8)
        self.qos_id = qos_id
        self.acl_id = acl_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_qos_and_acl_ids_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def qos_id(self):
        return self._get_field_value(4, 4)
    @qos_id.setter
    def qos_id(self, value):
        self._set_field_value('field qos_id', 4, 4, int, value)
    @property
    def acl_id(self):
        return self._get_field_value(0, 4)
    @acl_id.setter
    def acl_id(self, value):
        self._set_field_value('field acl_id', 0, 4, int, value)



class npl_qos_attributes_t(basic_npl_struct):
    def __init__(self, demux_count=0, is_group_qos=0, q_counter=0, p_counter=0, qos_id=0):
        super().__init__(46)
        self.demux_count = demux_count
        self.is_group_qos = is_group_qos
        self.q_counter = q_counter
        self.p_counter = p_counter
        self.qos_id = qos_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_qos_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def demux_count(self):
        return self._get_field_value(45, 1)
    @demux_count.setter
    def demux_count(self, value):
        self._set_field_value('field demux_count', 45, 1, int, value)
    @property
    def is_group_qos(self):
        return self._get_field_value(44, 1)
    @is_group_qos.setter
    def is_group_qos(self, value):
        self._set_field_value('field is_group_qos', 44, 1, int, value)
    @property
    def q_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 24)
    @q_counter.setter
    def q_counter(self, value):
        self._set_field_value('field q_counter', 24, 20, npl_counter_ptr_t, value)
    @property
    def p_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @p_counter.setter
    def p_counter(self, value):
        self._set_field_value('field p_counter', 4, 20, npl_counter_ptr_t, value)
    @property
    def qos_id(self):
        return self._get_field_value(0, 4)
    @qos_id.setter
    def qos_id(self, value):
        self._set_field_value('field qos_id', 0, 4, int, value)



class npl_qos_encap_t(basic_npl_struct):
    def __init__(self, tos=0, exp_no_bos=0, pcp_dei=0):
        super().__init__(16)
        self.tos = tos
        self.exp_no_bos = exp_no_bos
        self.pcp_dei = pcp_dei

    def _get_as_sub_field(data, offset_in_data):
        result = npl_qos_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tos(self):
        return self._get_field_value(8, 8)
    @tos.setter
    def tos(self, value):
        self._set_field_value('field tos', 8, 8, int, value)
    @property
    def exp_no_bos(self):
        return npl_ene_no_bos_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @exp_no_bos.setter
    def exp_no_bos(self, value):
        self._set_field_value('field exp_no_bos', 4, 4, npl_ene_no_bos_t, value)
    @property
    def pcp_dei(self):
        return self._get_field_value(0, 4)
    @pcp_dei.setter
    def pcp_dei(self, value):
        self._set_field_value('field pcp_dei', 0, 4, int, value)



class npl_qos_info_t(basic_npl_struct):
    def __init__(self, is_group_qos=0, qos_id=0):
        super().__init__(5)
        self.is_group_qos = is_group_qos
        self.qos_id = qos_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_qos_info_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_group_qos(self):
        return self._get_field_value(4, 1)
    @is_group_qos.setter
    def is_group_qos(self, value):
        self._set_field_value('field is_group_qos', 4, 1, int, value)
    @property
    def qos_id(self):
        return self._get_field_value(0, 4)
    @qos_id.setter
    def qos_id(self, value):
        self._set_field_value('field qos_id', 0, 4, int, value)



class npl_qos_tag_t(basic_npl_struct):
    def __init__(self, val=0):
        super().__init__(8)
        self.val = val

    def _get_as_sub_field(data, offset_in_data):
        result = npl_qos_tag_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def val(self):
        return self._get_field_value(0, 7)
    @val.setter
    def val(self, value):
        self._set_field_value('field val', 0, 7, int, value)



class npl_qos_tags_t(basic_npl_struct):
    def __init__(self, mapping_key=0, outer=0, inner=0):
        super().__init__(24)
        self.mapping_key = mapping_key
        self.outer = outer
        self.inner = inner

    def _get_as_sub_field(data, offset_in_data):
        result = npl_qos_tags_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mapping_key(self):
        return npl_qos_tag_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @mapping_key.setter
    def mapping_key(self, value):
        self._set_field_value('field mapping_key', 16, 8, npl_qos_tag_t, value)
    @property
    def outer(self):
        return npl_qos_tag_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @outer.setter
    def outer(self, value):
        self._set_field_value('field outer', 8, 8, npl_qos_tag_t, value)
    @property
    def inner(self):
        return npl_qos_tag_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @inner.setter
    def inner(self, value):
        self._set_field_value('field inner', 0, 8, npl_qos_tag_t, value)



class npl_quan_13b(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(13)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_quan_13b()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 13)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 13, int, value)



class npl_quan_14b(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(14)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_quan_14b()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 14)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 14, int, value)



class npl_quan_15b(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(15)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_quan_15b()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 15)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 15, int, value)



class npl_quan_19b(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(19)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_quan_19b()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 19)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 19, int, value)



class npl_quan_1b(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(1)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_quan_1b()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 1)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 1, int, value)



class npl_quan_5b(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(5)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_quan_5b()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 5)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 5, int, value)



class npl_quan_8b(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(8)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_quan_8b()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 8)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 8, int, value)



class npl_random_bc_bmp_entry_t(basic_npl_struct):
    def __init__(self, rnd_entry=0):
        super().__init__(7)
        self.rnd_entry = rnd_entry

    def _get_as_sub_field(data, offset_in_data):
        result = npl_random_bc_bmp_entry_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rnd_entry(self):
        return self._get_field_value(0, 7)
    @rnd_entry.setter
    def rnd_entry(self, value):
        self._set_field_value('field rnd_entry', 0, 7, int, value)



class npl_rate_limiters_port_packet_type_index_len_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(7)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rate_limiters_port_packet_type_index_len_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 7)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 7, int, value)



class npl_raw_lp_over_lag_result_t(basic_npl_struct):
    def __init__(self, bvn_destination=0):
        super().__init__(20)
        self.bvn_destination = bvn_destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_raw_lp_over_lag_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def bvn_destination(self):
        return self._get_field_value(0, 20)
    @bvn_destination.setter
    def bvn_destination(self, value):
        self._set_field_value('field bvn_destination', 0, 20, int, value)



class npl_rcy_sm_vlans_t(basic_npl_struct):
    def __init__(self, vid1=0, vid2=0):
        super().__init__(24)
        self.vid1 = vid1
        self.vid2 = vid2

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rcy_sm_vlans_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def vid1(self):
        return self._get_field_value(12, 12)
    @vid1.setter
    def vid1(self, value):
        self._set_field_value('field vid1', 12, 12, int, value)
    @property
    def vid2(self):
        return self._get_field_value(0, 12)
    @vid2.setter
    def vid2(self, value):
        self._set_field_value('field vid2', 0, 12, int, value)



class npl_reassembly_source_port_map_key_t(basic_npl_struct):
    def __init__(self, ifg=0, pif=0):
        super().__init__(6)
        self.ifg = ifg
        self.pif = pif

    def _get_as_sub_field(data, offset_in_data):
        result = npl_reassembly_source_port_map_key_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ifg(self):
        return self._get_field_value(5, 1)
    @ifg.setter
    def ifg(self, value):
        self._set_field_value('field ifg', 5, 1, int, value)
    @property
    def pif(self):
        return self._get_field_value(0, 5)
    @pif.setter
    def pif(self, value):
        self._set_field_value('field pif', 0, 5, int, value)



class npl_reassembly_source_port_map_result_t(basic_npl_struct):
    def __init__(self, tm_ifc=0):
        super().__init__(6)
        self.tm_ifc = tm_ifc

    def _get_as_sub_field(data, offset_in_data):
        result = npl_reassembly_source_port_map_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tm_ifc(self):
        return self._get_field_value(0, 6)
    @tm_ifc.setter
    def tm_ifc(self, value):
        self._set_field_value('field tm_ifc', 0, 6, int, value)



class npl_redirect_code_t(basic_npl_struct):
    def __init__(self, val=0):
        super().__init__(8)
        self.val = val

    def _get_as_sub_field(data, offset_in_data):
        result = npl_redirect_code_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def val(self):
        return self._get_field_value(0, 8)
    @val.setter
    def val(self, value):
        self._set_field_value('field val', 0, 8, int, value)



class npl_redirect_destination_reg_t(basic_npl_struct):
    def __init__(self, port_reg=0):
        super().__init__(2)
        self.port_reg = port_reg

    def _get_as_sub_field(data, offset_in_data):
        result = npl_redirect_destination_reg_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def port_reg(self):
        return self._get_field_value(0, 2)
    @port_reg.setter
    def port_reg(self, value):
        self._set_field_value('field port_reg', 0, 2, int, value)



class npl_relay_id_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(14)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_relay_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 14)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 14, int, value)



class npl_resolution_dlp_attributes_t(basic_npl_struct):
    def __init__(self, pad=0, monitor=0, bvn_profile=0, never_use_npu_header_pif_ifg=0):
        super().__init__(8)
        self.pad = pad
        self.monitor = monitor
        self.bvn_profile = bvn_profile
        self.never_use_npu_header_pif_ifg = never_use_npu_header_pif_ifg

    def _get_as_sub_field(data, offset_in_data):
        result = npl_resolution_dlp_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def pad(self):
        return self._get_field_value(6, 2)
    @pad.setter
    def pad(self, value):
        self._set_field_value('field pad', 6, 2, int, value)
    @property
    def monitor(self):
        return self._get_field_value(5, 1)
    @monitor.setter
    def monitor(self, value):
        self._set_field_value('field monitor', 5, 1, int, value)
    @property
    def bvn_profile(self):
        return npl_bvn_profile_t._get_as_sub_field(self._data, self._offset_in_data + 1)
    @bvn_profile.setter
    def bvn_profile(self, value):
        self._set_field_value('field bvn_profile', 1, 4, npl_bvn_profile_t, value)
    @property
    def never_use_npu_header_pif_ifg(self):
        return self._get_field_value(0, 1)
    @never_use_npu_header_pif_ifg.setter
    def never_use_npu_header_pif_ifg(self, value):
        self._set_field_value('field never_use_npu_header_pif_ifg', 0, 1, int, value)



class npl_resolution_fwd_class_t(basic_npl_struct):
    def __init__(self, tag=0):
        super().__init__(3)
        self.tag = tag

    def _get_as_sub_field(data, offset_in_data):
        result = npl_resolution_fwd_class_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tag(self):
        return self._get_field_value(0, 3)
    @tag.setter
    def tag(self, value):
        self._set_field_value('field tag', 0, 3, int, value)



class npl_resolution_result_dest_data_t(basic_npl_struct):
    def __init__(self, lb_key=0, bvn_map_profile=0, destination=0):
        super().__init__(60)
        self.lb_key = lb_key
        self.bvn_map_profile = bvn_map_profile
        self.destination = destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_resolution_result_dest_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lb_key(self):
        return npl_lb_key_t._get_as_sub_field(self._data, self._offset_in_data + 44)
    @lb_key.setter
    def lb_key(self, value):
        self._set_field_value('field lb_key', 44, 16, npl_lb_key_t, value)
    @property
    def bvn_map_profile(self):
        return self._get_field_value(20, 3)
    @bvn_map_profile.setter
    def bvn_map_profile(self, value):
        self._set_field_value('field bvn_map_profile', 20, 3, int, value)
    @property
    def destination(self):
        return self._get_field_value(0, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 20, int, value)



class npl_resolution_type_decoding_table_field_t(basic_npl_struct):
    def __init__(self, destination_in_nibbles=0, size_in_bits=0, offset_in_bits=0):
        super().__init__(16)
        self.destination_in_nibbles = destination_in_nibbles
        self.size_in_bits = size_in_bits
        self.offset_in_bits = offset_in_bits

    def _get_as_sub_field(data, offset_in_data):
        result = npl_resolution_type_decoding_table_field_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination_in_nibbles(self):
        return self._get_field_value(11, 5)
    @destination_in_nibbles.setter
    def destination_in_nibbles(self, value):
        self._set_field_value('field destination_in_nibbles', 11, 5, int, value)
    @property
    def size_in_bits(self):
        return self._get_field_value(6, 5)
    @size_in_bits.setter
    def size_in_bits(self, value):
        self._set_field_value('field size_in_bits', 6, 5, int, value)
    @property
    def offset_in_bits(self):
        return self._get_field_value(0, 6)
    @offset_in_bits.setter
    def offset_in_bits(self, value):
        self._set_field_value('field offset_in_bits', 0, 6, int, value)



class npl_resolution_type_decoding_table_result_t(basic_npl_struct):
    def __init__(self, lb_key_offset=0, lb_key_overwrite=0, field_1=0, field_0=0, index_destination_in_nibbles=0, index_size_in_nibbles=0, encapsulation_type=0, encapsulation_add_type=0, encapsulation_start=0, next_destination_mask=0, next_destination_size=0):
        super().__init__(63)
        self.lb_key_offset = lb_key_offset
        self.lb_key_overwrite = lb_key_overwrite
        self.field_1 = field_1
        self.field_0 = field_0
        self.index_destination_in_nibbles = index_destination_in_nibbles
        self.index_size_in_nibbles = index_size_in_nibbles
        self.encapsulation_type = encapsulation_type
        self.encapsulation_add_type = encapsulation_add_type
        self.encapsulation_start = encapsulation_start
        self.next_destination_mask = next_destination_mask
        self.next_destination_size = next_destination_size

    def _get_as_sub_field(data, offset_in_data):
        result = npl_resolution_type_decoding_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lb_key_offset(self):
        return self._get_field_value(57, 6)
    @lb_key_offset.setter
    def lb_key_offset(self, value):
        self._set_field_value('field lb_key_offset', 57, 6, int, value)
    @property
    def lb_key_overwrite(self):
        return self._get_field_value(56, 1)
    @lb_key_overwrite.setter
    def lb_key_overwrite(self, value):
        self._set_field_value('field lb_key_overwrite', 56, 1, int, value)
    @property
    def field_1(self):
        return npl_resolution_type_decoding_table_field_t._get_as_sub_field(self._data, self._offset_in_data + 40)
    @field_1.setter
    def field_1(self, value):
        self._set_field_value('field field_1', 40, 16, npl_resolution_type_decoding_table_field_t, value)
    @property
    def field_0(self):
        return npl_resolution_type_decoding_table_field_t._get_as_sub_field(self._data, self._offset_in_data + 24)
    @field_0.setter
    def field_0(self, value):
        self._set_field_value('field field_0', 24, 16, npl_resolution_type_decoding_table_field_t, value)
    @property
    def index_destination_in_nibbles(self):
        return self._get_field_value(19, 5)
    @index_destination_in_nibbles.setter
    def index_destination_in_nibbles(self, value):
        self._set_field_value('field index_destination_in_nibbles', 19, 5, int, value)
    @property
    def index_size_in_nibbles(self):
        return self._get_field_value(16, 3)
    @index_size_in_nibbles.setter
    def index_size_in_nibbles(self, value):
        self._set_field_value('field index_size_in_nibbles', 16, 3, int, value)
    @property
    def encapsulation_type(self):
        return self._get_field_value(12, 4)
    @encapsulation_type.setter
    def encapsulation_type(self, value):
        self._set_field_value('field encapsulation_type', 12, 4, int, value)
    @property
    def encapsulation_add_type(self):
        return self._get_field_value(11, 1)
    @encapsulation_add_type.setter
    def encapsulation_add_type(self, value):
        self._set_field_value('field encapsulation_add_type', 11, 1, int, value)
    @property
    def encapsulation_start(self):
        return self._get_field_value(10, 1)
    @encapsulation_start.setter
    def encapsulation_start(self, value):
        self._set_field_value('field encapsulation_start', 10, 1, int, value)
    @property
    def next_destination_mask(self):
        return self._get_field_value(5, 5)
    @next_destination_mask.setter
    def next_destination_mask(self, value):
        self._set_field_value('field next_destination_mask', 5, 5, int, value)
    @property
    def next_destination_size(self):
        return self._get_field_value(0, 5)
    @next_destination_size.setter
    def next_destination_size(self, value):
        self._set_field_value('field next_destination_size', 0, 5, int, value)



class npl_rmep_data_t(basic_npl_struct):
    def __init__(self, rmep_data=0, rmep_profile=0, rmep_valid=0):
        super().__init__(16)
        self.rmep_data = rmep_data
        self.rmep_profile = rmep_profile
        self.rmep_valid = rmep_valid

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rmep_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rmep_data(self):
        return self._get_field_value(5, 11)
    @rmep_data.setter
    def rmep_data(self, value):
        self._set_field_value('field rmep_data', 5, 11, int, value)
    @property
    def rmep_profile(self):
        return self._get_field_value(1, 4)
    @rmep_profile.setter
    def rmep_profile(self, value):
        self._set_field_value('field rmep_profile', 1, 4, int, value)
    @property
    def rmep_valid(self):
        return self._get_field_value(0, 1)
    @rmep_valid.setter
    def rmep_valid(self, value):
        self._set_field_value('field rmep_valid', 0, 1, int, value)



class npl_rtf_compressed_fields_for_next_macro_t(basic_npl_struct):
    def __init__(self, acl_outer=0, fwd_layer_and_rtf_stage_compressed_fields=0):
        super().__init__(4)
        self.acl_outer = acl_outer
        self.fwd_layer_and_rtf_stage_compressed_fields = fwd_layer_and_rtf_stage_compressed_fields

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rtf_compressed_fields_for_next_macro_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def acl_outer(self):
        return self._get_field_value(3, 1)
    @acl_outer.setter
    def acl_outer(self, value):
        self._set_field_value('field acl_outer', 3, 1, int, value)
    @property
    def fwd_layer_and_rtf_stage_compressed_fields(self):
        return npl_fwd_layer_and_rtf_stage_compressed_fields_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @fwd_layer_and_rtf_stage_compressed_fields.setter
    def fwd_layer_and_rtf_stage_compressed_fields(self, value):
        self._set_field_value('field fwd_layer_and_rtf_stage_compressed_fields', 0, 3, npl_fwd_layer_and_rtf_stage_compressed_fields_t, value)



class npl_rtf_conf_set_and_stages_t(basic_npl_struct):
    def __init__(self, rtf_conf_set=0, ipv4_ipv6_init_rtf_stage=0):
        super().__init__(12)
        self.rtf_conf_set = rtf_conf_set
        self.ipv4_ipv6_init_rtf_stage = ipv4_ipv6_init_rtf_stage

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rtf_conf_set_and_stages_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rtf_conf_set(self):
        return npl_lp_rtf_conf_set_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @rtf_conf_set.setter
    def rtf_conf_set(self, value):
        self._set_field_value('field rtf_conf_set', 4, 8, npl_lp_rtf_conf_set_t, value)
    @property
    def ipv4_ipv6_init_rtf_stage(self):
        return npl_ipv4_ipv6_init_rtf_stage_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ipv4_ipv6_init_rtf_stage.setter
    def ipv4_ipv6_init_rtf_stage(self, value):
        self._set_field_value('field ipv4_ipv6_init_rtf_stage', 0, 4, npl_ipv4_ipv6_init_rtf_stage_t, value)



class npl_rtf_iter_prop_over_fwd0_t(basic_npl_struct):
    def __init__(self):
        super().__init__(10)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_rtf_iter_prop_over_fwd0_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ip_rtf(self):
        return npl_ip_rtf_iter_prop_over_fwd0_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ip_rtf.setter
    def ip_rtf(self, value):
        self._set_field_value('field ip_rtf', 0, 10, npl_ip_rtf_iter_prop_over_fwd0_t, value)
    @property
    def eth_rtf(self):
        return npl_eth_rtf_prop_over_fwd0_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @eth_rtf.setter
    def eth_rtf(self, value):
        self._set_field_value('field eth_rtf', 0, 8, npl_eth_rtf_prop_over_fwd0_t, value)



class npl_rtf_iter_prop_over_fwd1_t(basic_npl_struct):
    def __init__(self):
        super().__init__(9)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_rtf_iter_prop_over_fwd1_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ip_rtf(self):
        return npl_ip_rtf_iter_prop_over_fwd1_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ip_rtf.setter
    def ip_rtf(self, value):
        self._set_field_value('field ip_rtf', 0, 9, npl_ip_rtf_iter_prop_over_fwd1_t, value)
    @property
    def eth_rtf(self):
        return npl_eth_rtf_prop_over_fwd1_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @eth_rtf.setter
    def eth_rtf(self, value):
        self._set_field_value('field eth_rtf', 0, 8, npl_eth_rtf_prop_over_fwd1_t, value)



class npl_rtf_result_profile_0_t_anonymous_union_force_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_rtf_result_profile_0_t_anonymous_union_force_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 20, npl_destination_t, value)
    @property
    def drop_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @drop_counter.setter
    def drop_counter(self, value):
        self._set_field_value('field drop_counter', 0, 20, npl_counter_ptr_t, value)
    @property
    def permit_ace_cntr(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @permit_ace_cntr.setter
    def permit_ace_cntr(self, value):
        self._set_field_value('field permit_ace_cntr', 0, 20, npl_counter_ptr_t, value)
    @property
    def meter_ptr(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @meter_ptr.setter
    def meter_ptr(self, value):
        self._set_field_value('field meter_ptr', 0, 20, npl_counter_ptr_t, value)



class npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t(basic_npl_struct):
    def __init__(self):
        super().__init__(5)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mirror_cmd(self):
        return self._get_field_value(0, 5)
    @mirror_cmd.setter
    def mirror_cmd(self, value):
        self._set_field_value('field mirror_cmd', 0, 5, int, value)
    @property
    def mirror_offset(self):
        return self._get_field_value(0, 5)
    @mirror_offset.setter
    def mirror_offset(self, value):
        self._set_field_value('field mirror_offset', 0, 5, int, value)



class npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def meter_ptr(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @meter_ptr.setter
    def meter_ptr(self, value):
        self._set_field_value('field meter_ptr', 0, 20, npl_counter_ptr_t, value)
    @property
    def counter_ptr(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @counter_ptr.setter
    def counter_ptr(self, value):
        self._set_field_value('field counter_ptr', 0, 20, npl_counter_ptr_t, value)



class npl_rtf_result_profile_2_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(62)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_rtf_result_profile_2_t()
        result._set_data_pointer(data, offset_in_data)
        return result




class npl_rtf_result_profile_3_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(62)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_rtf_result_profile_3_t()
        result._set_data_pointer(data, offset_in_data)
        return result




class npl_rtf_step_t(basic_npl_struct):
    def __init__(self, val=0):
        super().__init__(2)
        self.val = val

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rtf_step_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def val(self):
        return self._get_field_value(0, 2)
    @val.setter
    def val(self, value):
        self._set_field_value('field val', 0, 2, int, value)



class npl_rx_meter_block_meter_attribute_result_t(basic_npl_struct):
    def __init__(self, meter_decision_mapping_profile=0, commited_coupling_flag=0, profile=0):
        super().__init__(7)
        self.meter_decision_mapping_profile = meter_decision_mapping_profile
        self.commited_coupling_flag = commited_coupling_flag
        self.profile = profile

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rx_meter_block_meter_attribute_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def meter_decision_mapping_profile(self):
        return npl_meter_action_profile_len_t._get_as_sub_field(self._data, self._offset_in_data + 5)
    @meter_decision_mapping_profile.setter
    def meter_decision_mapping_profile(self, value):
        self._set_field_value('field meter_decision_mapping_profile', 5, 2, npl_meter_action_profile_len_t, value)
    @property
    def commited_coupling_flag(self):
        return self._get_field_value(4, 1)
    @commited_coupling_flag.setter
    def commited_coupling_flag(self, value):
        self._set_field_value('field commited_coupling_flag', 4, 1, int, value)
    @property
    def profile(self):
        return npl_meter_profile_len_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @profile.setter
    def profile(self, value):
        self._set_field_value('field profile', 0, 4, npl_meter_profile_len_t, value)



class npl_rx_meter_block_meter_profile_result_t(basic_npl_struct):
    def __init__(self, ebs=0, cbs=0, color_aware_mode=0, meter_mode=0, meter_count_mode=0):
        super().__init__(39)
        self.ebs = ebs
        self.cbs = cbs
        self.color_aware_mode = color_aware_mode
        self.meter_mode = meter_mode
        self.meter_count_mode = meter_count_mode

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rx_meter_block_meter_profile_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ebs(self):
        return npl_burst_size_len_t._get_as_sub_field(self._data, self._offset_in_data + 21)
    @ebs.setter
    def ebs(self, value):
        self._set_field_value('field ebs', 21, 18, npl_burst_size_len_t, value)
    @property
    def cbs(self):
        return npl_burst_size_len_t._get_as_sub_field(self._data, self._offset_in_data + 3)
    @cbs.setter
    def cbs(self, value):
        self._set_field_value('field cbs', 3, 18, npl_burst_size_len_t, value)
    @property
    def color_aware_mode(self):
        return npl_color_aware_mode_len_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @color_aware_mode.setter
    def color_aware_mode(self, value):
        self._set_field_value('field color_aware_mode', 2, 1, npl_color_aware_mode_len_t, value)
    @property
    def meter_mode(self):
        return npl_meter_mode_len_t._get_as_sub_field(self._data, self._offset_in_data + 1)
    @meter_mode.setter
    def meter_mode(self, value):
        self._set_field_value('field meter_mode', 1, 1, npl_meter_mode_len_t, value)
    @property
    def meter_count_mode(self):
        return npl_meter_count_mode_len_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @meter_count_mode.setter
    def meter_count_mode(self, value):
        self._set_field_value('field meter_count_mode', 0, 1, npl_meter_count_mode_len_t, value)



class npl_rx_meter_block_meter_shaper_configuration_result_t(basic_npl_struct):
    def __init__(self, eir_weight=0, cir_weight=0):
        super().__init__(20)
        self.eir_weight = eir_weight
        self.cir_weight = cir_weight

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rx_meter_block_meter_shaper_configuration_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def eir_weight(self):
        return npl_meter_weight_t._get_as_sub_field(self._data, self._offset_in_data + 10)
    @eir_weight.setter
    def eir_weight(self, value):
        self._set_field_value('field eir_weight', 10, 10, npl_meter_weight_t, value)
    @property
    def cir_weight(self):
        return npl_meter_weight_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @cir_weight.setter
    def cir_weight(self, value):
        self._set_field_value('field cir_weight', 0, 10, npl_meter_weight_t, value)



class npl_rx_meter_distributed_meter_profile_result_t(basic_npl_struct):
    def __init__(self, is_distributed_meter=0, tx_message_template_index=0, excess_token_release_thr=0, excess_token_grant_thr=0, committed_token_release_thr=0, committed_token_grant_thr=0, is_cascade=0):
        super().__init__(77)
        self.is_distributed_meter = is_distributed_meter
        self.tx_message_template_index = tx_message_template_index
        self.excess_token_release_thr = excess_token_release_thr
        self.excess_token_grant_thr = excess_token_grant_thr
        self.committed_token_release_thr = committed_token_release_thr
        self.committed_token_grant_thr = committed_token_grant_thr
        self.is_cascade = is_cascade

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rx_meter_distributed_meter_profile_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_distributed_meter(self):
        return self._get_field_value(76, 1)
    @is_distributed_meter.setter
    def is_distributed_meter(self, value):
        self._set_field_value('field is_distributed_meter', 76, 1, int, value)
    @property
    def tx_message_template_index(self):
        return self._get_field_value(73, 3)
    @tx_message_template_index.setter
    def tx_message_template_index(self, value):
        self._set_field_value('field tx_message_template_index', 73, 3, int, value)
    @property
    def excess_token_release_thr(self):
        return self._get_field_value(55, 18)
    @excess_token_release_thr.setter
    def excess_token_release_thr(self, value):
        self._set_field_value('field excess_token_release_thr', 55, 18, int, value)
    @property
    def excess_token_grant_thr(self):
        return self._get_field_value(37, 18)
    @excess_token_grant_thr.setter
    def excess_token_grant_thr(self, value):
        self._set_field_value('field excess_token_grant_thr', 37, 18, int, value)
    @property
    def committed_token_release_thr(self):
        return self._get_field_value(19, 18)
    @committed_token_release_thr.setter
    def committed_token_release_thr(self, value):
        self._set_field_value('field committed_token_release_thr', 19, 18, int, value)
    @property
    def committed_token_grant_thr(self):
        return self._get_field_value(1, 18)
    @committed_token_grant_thr.setter
    def committed_token_grant_thr(self, value):
        self._set_field_value('field committed_token_grant_thr', 1, 18, int, value)
    @property
    def is_cascade(self):
        return self._get_field_value(0, 1)
    @is_cascade.setter
    def is_cascade(self, value):
        self._set_field_value('field is_cascade', 0, 1, int, value)



class npl_rx_meter_exact_meter_decision_mapping_result_t(basic_npl_struct):
    def __init__(self, congestion_experienced=0, rx_counter_color=0, outgoing_color=0, cgm_rx_dp=0, meter_drop=0):
        super().__init__(7)
        self.congestion_experienced = congestion_experienced
        self.rx_counter_color = rx_counter_color
        self.outgoing_color = outgoing_color
        self.cgm_rx_dp = cgm_rx_dp
        self.meter_drop = meter_drop

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rx_meter_exact_meter_decision_mapping_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def congestion_experienced(self):
        return self._get_field_value(6, 1)
    @congestion_experienced.setter
    def congestion_experienced(self, value):
        self._set_field_value('field congestion_experienced', 6, 1, int, value)
    @property
    def rx_counter_color(self):
        return npl_color_len_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @rx_counter_color.setter
    def rx_counter_color(self, value):
        self._set_field_value('field rx_counter_color', 4, 2, npl_color_len_t, value)
    @property
    def outgoing_color(self):
        return npl_color_len_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @outgoing_color.setter
    def outgoing_color(self, value):
        self._set_field_value('field outgoing_color', 2, 2, npl_color_len_t, value)
    @property
    def cgm_rx_dp(self):
        return self._get_field_value(1, 1)
    @cgm_rx_dp.setter
    def cgm_rx_dp(self, value):
        self._set_field_value('field cgm_rx_dp', 1, 1, int, value)
    @property
    def meter_drop(self):
        return self._get_field_value(0, 1)
    @meter_drop.setter
    def meter_drop(self, value):
        self._set_field_value('field meter_drop', 0, 1, int, value)



class npl_rx_meter_meter_profile_result_t(basic_npl_struct):
    def __init__(self, ebs=0, cbs=0, color_aware_mode=0, meter_mode=0, meter_count_mode=0):
        super().__init__(39)
        self.ebs = ebs
        self.cbs = cbs
        self.color_aware_mode = color_aware_mode
        self.meter_mode = meter_mode
        self.meter_count_mode = meter_count_mode

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rx_meter_meter_profile_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ebs(self):
        return npl_burst_size_len_t._get_as_sub_field(self._data, self._offset_in_data + 21)
    @ebs.setter
    def ebs(self, value):
        self._set_field_value('field ebs', 21, 18, npl_burst_size_len_t, value)
    @property
    def cbs(self):
        return npl_burst_size_len_t._get_as_sub_field(self._data, self._offset_in_data + 3)
    @cbs.setter
    def cbs(self, value):
        self._set_field_value('field cbs', 3, 18, npl_burst_size_len_t, value)
    @property
    def color_aware_mode(self):
        return npl_color_aware_mode_len_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @color_aware_mode.setter
    def color_aware_mode(self, value):
        self._set_field_value('field color_aware_mode', 2, 1, npl_color_aware_mode_len_t, value)
    @property
    def meter_mode(self):
        return npl_meter_mode_len_t._get_as_sub_field(self._data, self._offset_in_data + 1)
    @meter_mode.setter
    def meter_mode(self, value):
        self._set_field_value('field meter_mode', 1, 1, npl_meter_mode_len_t, value)
    @property
    def meter_count_mode(self):
        return npl_meter_count_mode_len_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @meter_count_mode.setter
    def meter_count_mode(self, value):
        self._set_field_value('field meter_count_mode', 0, 1, npl_meter_count_mode_len_t, value)



class npl_rx_meter_meter_shaper_configuration_result_t(basic_npl_struct):
    def __init__(self, eir_weight=0, cir_weight=0):
        super().__init__(20)
        self.eir_weight = eir_weight
        self.cir_weight = cir_weight

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rx_meter_meter_shaper_configuration_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def eir_weight(self):
        return npl_meter_weight_t._get_as_sub_field(self._data, self._offset_in_data + 10)
    @eir_weight.setter
    def eir_weight(self, value):
        self._set_field_value('field eir_weight', 10, 10, npl_meter_weight_t, value)
    @property
    def cir_weight(self):
        return npl_meter_weight_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @cir_weight.setter
    def cir_weight(self, value):
        self._set_field_value('field cir_weight', 0, 10, npl_meter_weight_t, value)



class npl_rx_meter_meters_attribute_result_t(basic_npl_struct):
    def __init__(self, meter_decision_mapping_profile=0, commited_coupling_flag=0, profile=0):
        super().__init__(7)
        self.meter_decision_mapping_profile = meter_decision_mapping_profile
        self.commited_coupling_flag = commited_coupling_flag
        self.profile = profile

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rx_meter_meters_attribute_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def meter_decision_mapping_profile(self):
        return npl_meter_action_profile_len_t._get_as_sub_field(self._data, self._offset_in_data + 5)
    @meter_decision_mapping_profile.setter
    def meter_decision_mapping_profile(self, value):
        self._set_field_value('field meter_decision_mapping_profile', 5, 2, npl_meter_action_profile_len_t, value)
    @property
    def commited_coupling_flag(self):
        return self._get_field_value(4, 1)
    @commited_coupling_flag.setter
    def commited_coupling_flag(self, value):
        self._set_field_value('field commited_coupling_flag', 4, 1, int, value)
    @property
    def profile(self):
        return npl_meter_profile_len_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @profile.setter
    def profile(self, value):
        self._set_field_value('field profile', 0, 4, npl_meter_profile_len_t, value)



class npl_rx_meter_rate_limiter_shaper_configuration_result_t(basic_npl_struct):
    def __init__(self, cir_weight=0):
        super().__init__(10)
        self.cir_weight = cir_weight

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rx_meter_rate_limiter_shaper_configuration_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def cir_weight(self):
        return npl_meter_weight_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @cir_weight.setter
    def cir_weight(self, value):
        self._set_field_value('field cir_weight', 0, 10, npl_meter_weight_t, value)



class npl_rx_meter_stat_meter_decision_mapping_result_t(basic_npl_struct):
    def __init__(self, congestion_experienced=0, rx_counter_color=0, outgoing_color=0, cgm_rx_dp=0, meter_drop=0):
        super().__init__(7)
        self.congestion_experienced = congestion_experienced
        self.rx_counter_color = rx_counter_color
        self.outgoing_color = outgoing_color
        self.cgm_rx_dp = cgm_rx_dp
        self.meter_drop = meter_drop

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rx_meter_stat_meter_decision_mapping_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def congestion_experienced(self):
        return self._get_field_value(6, 1)
    @congestion_experienced.setter
    def congestion_experienced(self, value):
        self._set_field_value('field congestion_experienced', 6, 1, int, value)
    @property
    def rx_counter_color(self):
        return npl_color_len_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @rx_counter_color.setter
    def rx_counter_color(self, value):
        self._set_field_value('field rx_counter_color', 4, 2, npl_color_len_t, value)
    @property
    def outgoing_color(self):
        return npl_color_len_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @outgoing_color.setter
    def outgoing_color(self, value):
        self._set_field_value('field outgoing_color', 2, 2, npl_color_len_t, value)
    @property
    def cgm_rx_dp(self):
        return self._get_field_value(1, 1)
    @cgm_rx_dp.setter
    def cgm_rx_dp(self, value):
        self._set_field_value('field cgm_rx_dp', 1, 1, int, value)
    @property
    def meter_drop(self):
        return self._get_field_value(0, 1)
    @meter_drop.setter
    def meter_drop(self, value):
        self._set_field_value('field meter_drop', 0, 1, int, value)



class npl_rx_obm_punt_src_and_code_data_t(basic_npl_struct):
    def __init__(self, phb=0, meter_ptr=0, cntr_ptr=0, punt_bvn_dest=0):
        super().__init__(65)
        self.phb = phb
        self.meter_ptr = meter_ptr
        self.cntr_ptr = cntr_ptr
        self.punt_bvn_dest = punt_bvn_dest

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rx_obm_punt_src_and_code_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def phb(self):
        return npl_phb_t._get_as_sub_field(self._data, self._offset_in_data + 60)
    @phb.setter
    def phb(self, value):
        self._set_field_value('field phb', 60, 5, npl_phb_t, value)
    @property
    def meter_ptr(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 40)
    @meter_ptr.setter
    def meter_ptr(self, value):
        self._set_field_value('field meter_ptr', 40, 20, npl_counter_ptr_t, value)
    @property
    def cntr_ptr(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @cntr_ptr.setter
    def cntr_ptr(self, value):
        self._set_field_value('field cntr_ptr', 20, 20, npl_counter_ptr_t, value)
    @property
    def punt_bvn_dest(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_bvn_dest.setter
    def punt_bvn_dest(self, value):
        self._set_field_value('field punt_bvn_dest', 0, 20, npl_destination_t, value)



class npl_rxpdr_dsp_lookup_table_entry_t(basic_npl_struct):
    def __init__(self, tc_map_profile=0, base_voq_num=0, dest_device=0):
        super().__init__(28)
        self.tc_map_profile = tc_map_profile
        self.base_voq_num = base_voq_num
        self.dest_device = dest_device

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rxpdr_dsp_lookup_table_entry_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tc_map_profile(self):
        return self._get_field_value(25, 3)
    @tc_map_profile.setter
    def tc_map_profile(self, value):
        self._set_field_value('field tc_map_profile', 25, 3, int, value)
    @property
    def base_voq_num(self):
        return self._get_field_value(9, 16)
    @base_voq_num.setter
    def base_voq_num(self, value):
        self._set_field_value('field base_voq_num', 9, 16, int, value)
    @property
    def dest_device(self):
        return self._get_field_value(0, 9)
    @dest_device.setter
    def dest_device(self, value):
        self._set_field_value('field dest_device', 0, 9, int, value)



class npl_rxpdr_dsp_tc_map_result_t(basic_npl_struct):
    def __init__(self, is_flb=0, tc_offset=0):
        super().__init__(4)
        self.is_flb = is_flb
        self.tc_offset = tc_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rxpdr_dsp_tc_map_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_flb(self):
        return self._get_field_value(3, 1)
    @is_flb.setter
    def is_flb(self, value):
        self._set_field_value('field is_flb', 3, 1, int, value)
    @property
    def tc_offset(self):
        return self._get_field_value(0, 3)
    @tc_offset.setter
    def tc_offset(self, value):
        self._set_field_value('field tc_offset', 0, 3, int, value)



class npl_rxpdr_ibm_tc_map_result_t(basic_npl_struct):
    def __init__(self, is_flb=0, tc_offset=0):
        super().__init__(4)
        self.is_flb = is_flb
        self.tc_offset = tc_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rxpdr_ibm_tc_map_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_flb(self):
        return self._get_field_value(3, 1)
    @is_flb.setter
    def is_flb(self, value):
        self._set_field_value('field is_flb', 3, 1, int, value)
    @property
    def tc_offset(self):
        return self._get_field_value(0, 3)
    @tc_offset.setter
    def tc_offset(self, value):
        self._set_field_value('field tc_offset', 0, 3, int, value)



class npl_scanner_id_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(13)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_scanner_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 13)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 13, int, value)



class npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def global_dlp_id(self):
        return self._get_field_value(0, 20)
    @global_dlp_id.setter
    def global_dlp_id(self, value):
        self._set_field_value('field global_dlp_id', 0, 20, int, value)
    @property
    def global_slp_id(self):
        return self._get_field_value(0, 20)
    @global_slp_id.setter
    def global_slp_id(self, value):
        self._set_field_value('field global_slp_id', 0, 20, int, value)
    @property
    def is_l2(self):
        return self._get_field_value(19, 1)
    @is_l2.setter
    def is_l2(self, value):
        self._set_field_value('field is_l2', 19, 1, int, value)



class npl_sec_acl_ids_t(basic_npl_struct):
    def __init__(self, acl_v4_id=0, acl_v6_id=0):
        super().__init__(8)
        self.acl_v4_id = acl_v4_id
        self.acl_v6_id = acl_v6_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_sec_acl_ids_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def acl_v4_id(self):
        return self._get_field_value(4, 4)
    @acl_v4_id.setter
    def acl_v4_id(self, value):
        self._set_field_value('field acl_v4_id', 4, 4, int, value)
    @property
    def acl_v6_id(self):
        return self._get_field_value(0, 4)
    @acl_v6_id.setter
    def acl_v6_id(self, value):
        self._set_field_value('field acl_v6_id', 0, 4, int, value)



class npl_select_macros_t(basic_npl_struct):
    def __init__(self, npe_macro_offset=0, fi_macro_offset=0):
        super().__init__(4)
        self.npe_macro_offset = npe_macro_offset
        self.fi_macro_offset = fi_macro_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_select_macros_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def npe_macro_offset(self):
        return self._get_field_value(2, 2)
    @npe_macro_offset.setter
    def npe_macro_offset(self, value):
        self._set_field_value('field npe_macro_offset', 2, 2, int, value)
    @property
    def fi_macro_offset(self):
        return self._get_field_value(0, 2)
    @fi_macro_offset.setter
    def fi_macro_offset(self, value):
        self._set_field_value('field fi_macro_offset', 0, 2, int, value)



class npl_service_flags_t(basic_npl_struct):
    def __init__(self, push_entropy_label=0, add_ipv6_explicit_null=0):
        super().__init__(2)
        self.push_entropy_label = push_entropy_label
        self.add_ipv6_explicit_null = add_ipv6_explicit_null

    def _get_as_sub_field(data, offset_in_data):
        result = npl_service_flags_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def push_entropy_label(self):
        return self._get_field_value(1, 1)
    @push_entropy_label.setter
    def push_entropy_label(self, value):
        self._set_field_value('field push_entropy_label', 1, 1, int, value)
    @property
    def add_ipv6_explicit_null(self):
        return self._get_field_value(0, 1)
    @add_ipv6_explicit_null.setter
    def add_ipv6_explicit_null(self, value):
        self._set_field_value('field add_ipv6_explicit_null', 0, 1, int, value)



class npl_sgacl_payload_t(basic_npl_struct):
    def __init__(self, drop=0):
        super().__init__(64)
        self.drop = drop

    def _get_as_sub_field(data, offset_in_data):
        result = npl_sgacl_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def drop(self):
        return self._get_field_value(0, 1)
    @drop.setter
    def drop(self, value):
        self._set_field_value('field drop', 0, 1, int, value)



class npl_sip_ip_tunnel_termination_attr_t(basic_npl_struct):
    def __init__(self, my_dip_index=0, vxlan_tunnel_loopback=0):
        super().__init__(16)
        self.my_dip_index = my_dip_index
        self.vxlan_tunnel_loopback = vxlan_tunnel_loopback

    def _get_as_sub_field(data, offset_in_data):
        result = npl_sip_ip_tunnel_termination_attr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def my_dip_index(self):
        return self._get_field_value(4, 6)
    @my_dip_index.setter
    def my_dip_index(self, value):
        self._set_field_value('field my_dip_index', 4, 6, int, value)
    @property
    def vxlan_tunnel_loopback(self):
        return self._get_field_value(0, 4)
    @vxlan_tunnel_loopback.setter
    def vxlan_tunnel_loopback(self, value):
        self._set_field_value('field vxlan_tunnel_loopback', 0, 4, int, value)



class npl_slp_based_fwd_and_per_vrf_mpls_fwd_t(basic_npl_struct):
    def __init__(self, slp_based_forwarding=0, per_vrf_mpls_fwd=0):
        super().__init__(2)
        self.slp_based_forwarding = slp_based_forwarding
        self.per_vrf_mpls_fwd = per_vrf_mpls_fwd

    def _get_as_sub_field(data, offset_in_data):
        result = npl_slp_based_fwd_and_per_vrf_mpls_fwd_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def slp_based_forwarding(self):
        return self._get_field_value(1, 1)
    @slp_based_forwarding.setter
    def slp_based_forwarding(self, value):
        self._set_field_value('field slp_based_forwarding', 1, 1, int, value)
    @property
    def per_vrf_mpls_fwd(self):
        return self._get_field_value(0, 1)
    @per_vrf_mpls_fwd.setter
    def per_vrf_mpls_fwd(self, value):
        self._set_field_value('field per_vrf_mpls_fwd', 0, 1, int, value)



class npl_slp_fwd_result_t(basic_npl_struct):
    def __init__(self, mpls_label_present=0, mpls_label=0, destination=0):
        super().__init__(44)
        self.mpls_label_present = mpls_label_present
        self.mpls_label = mpls_label
        self.destination = destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_slp_fwd_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mpls_label_present(self):
        return self._get_field_value(40, 1)
    @mpls_label_present.setter
    def mpls_label_present(self, value):
        self._set_field_value('field mpls_label_present', 40, 1, int, value)
    @property
    def mpls_label(self):
        return self._get_field_value(20, 20)
    @mpls_label.setter
    def mpls_label(self, value):
        self._set_field_value('field mpls_label', 20, 20, int, value)
    @property
    def destination(self):
        return self._get_field_value(0, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 20, int, value)



class npl_snoop_code_t(basic_npl_struct):
    def __init__(self, val=0):
        super().__init__(8)
        self.val = val

    def _get_as_sub_field(data, offset_in_data):
        result = npl_snoop_code_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def val(self):
        return self._get_field_value(0, 8)
    @val.setter
    def val(self, value):
        self._set_field_value('field val', 0, 8, int, value)



class npl_soft_lb_wa_enable_t(basic_npl_struct):
    def __init__(self, is_next_header_gre=0, soft_lb_enable=0):
        super().__init__(2)
        self.is_next_header_gre = is_next_header_gre
        self.soft_lb_enable = soft_lb_enable

    def _get_as_sub_field(data, offset_in_data):
        result = npl_soft_lb_wa_enable_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_next_header_gre(self):
        return self._get_field_value(1, 1)
    @is_next_header_gre.setter
    def is_next_header_gre(self, value):
        self._set_field_value('field is_next_header_gre', 1, 1, int, value)
    @property
    def soft_lb_enable(self):
        return self._get_field_value(0, 1)
    @soft_lb_enable.setter
    def soft_lb_enable(self, value):
        self._set_field_value('field soft_lb_enable', 0, 1, int, value)



class npl_source_if_t(basic_npl_struct):
    def __init__(self, ifg=0, pif=0):
        super().__init__(8)
        self.ifg = ifg
        self.pif = pif

    def _get_as_sub_field(data, offset_in_data):
        result = npl_source_if_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ifg(self):
        return self._get_field_value(7, 1)
    @ifg.setter
    def ifg(self, value):
        self._set_field_value('field ifg', 7, 1, int, value)
    @property
    def pif(self):
        return self._get_field_value(2, 5)
    @pif.setter
    def pif(self, value):
        self._set_field_value('field pif', 2, 5, int, value)



class npl_split_voq_t(basic_npl_struct):
    def __init__(self, split_voq_enabled=0, source_group_offset=0):
        super().__init__(11)
        self.split_voq_enabled = split_voq_enabled
        self.source_group_offset = source_group_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_split_voq_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def split_voq_enabled(self):
        return self._get_field_value(10, 1)
    @split_voq_enabled.setter
    def split_voq_enabled(self, value):
        self._set_field_value('field split_voq_enabled', 10, 1, int, value)
    @property
    def source_group_offset(self):
        return self._get_field_value(0, 10)
    @source_group_offset.setter
    def source_group_offset(self, value):
        self._set_field_value('field source_group_offset', 0, 10, int, value)



class npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t(basic_npl_struct):
    def __init__(self):
        super().__init__(16)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def src_port(self):
        return self._get_field_value(0, 16)
    @src_port.setter
    def src_port(self, value):
        self._set_field_value('field src_port', 0, 16, int, value)
    @property
    def ipv4_protocol(self):
        return self._get_field_value(0, 8)
    @ipv4_protocol.setter
    def ipv4_protocol(self, value):
        self._set_field_value('field ipv4_protocol', 0, 8, int, value)
    @property
    def ipv6_next_header(self):
        return self._get_field_value(8, 8)
    @ipv6_next_header.setter
    def ipv6_next_header(self, value):
        self._set_field_value('field ipv6_next_header', 8, 8, int, value)
    @property
    def icmp_type_code(self):
        return npl_icmp_type_code_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @icmp_type_code.setter
    def icmp_type_code(self, value):
        self._set_field_value('field icmp_type_code', 0, 16, npl_icmp_type_code_t, value)



class npl_stage2_lb_table_result_t(basic_npl_struct):
    def __init__(self):
        super().__init__(29)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_stage2_lb_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def stage3_nh_11b_asbr(self):
        return npl_path_lb_stage3_nh_11b_asbr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @stage3_nh_11b_asbr.setter
    def stage3_nh_11b_asbr(self, value):
        self._set_field_value('field stage3_nh_11b_asbr', 0, 29, npl_path_lb_stage3_nh_11b_asbr_t, value)
    @property
    def stage2_p_nh_11b_asbr(self):
        return npl_path_lb_stage2_p_nh_11b_asbr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @stage2_p_nh_11b_asbr.setter
    def stage2_p_nh_11b_asbr(self, value):
        self._set_field_value('field stage2_p_nh_11b_asbr', 0, 29, npl_path_lb_stage2_p_nh_11b_asbr_t, value)
    @property
    def stage3_nh_te_tunnel14b(self):
        return npl_path_lb_stage3_nh_te_tunnel14b_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @stage3_nh_te_tunnel14b.setter
    def stage3_nh_te_tunnel14b(self, value):
        self._set_field_value('field stage3_nh_te_tunnel14b', 0, 29, npl_path_lb_stage3_nh_te_tunnel14b_t, value)
    @property
    def stage3_nh_te_tunnel14b1(self):
        return npl_path_lb_stage3_nh_te_tunnel14b1_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @stage3_nh_te_tunnel14b1.setter
    def stage3_nh_te_tunnel14b1(self, value):
        self._set_field_value('field stage3_nh_te_tunnel14b1', 0, 29, npl_path_lb_stage3_nh_te_tunnel14b1_t, value)
    @property
    def stage2_p_nh_te_tunnel14b(self):
        return npl_path_lb_stage2_p_nh_te_tunnel14b_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @stage2_p_nh_te_tunnel14b.setter
    def stage2_p_nh_te_tunnel14b(self, value):
        self._set_field_value('field stage2_p_nh_te_tunnel14b', 0, 29, npl_path_lb_stage2_p_nh_te_tunnel14b_t, value)
    @property
    def stage2_p_nh_te_tunnel14b1(self):
        return npl_path_lb_stage2_p_nh_te_tunnel14b1_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @stage2_p_nh_te_tunnel14b1.setter
    def stage2_p_nh_te_tunnel14b1(self, value):
        self._set_field_value('field stage2_p_nh_te_tunnel14b1', 0, 29, npl_path_lb_stage2_p_nh_te_tunnel14b1_t, value)
    @property
    def destination(self):
        return npl_path_lb_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 29, npl_path_lb_destination_t, value)
    @property
    def destination1(self):
        return npl_path_lb_destination1_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination1.setter
    def destination1(self, value):
        self._set_field_value('field destination1', 0, 29, npl_path_lb_destination1_t, value)
    @property
    def raw(self):
        return npl_path_lb_raw_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 29, npl_path_lb_raw_t, value)



class npl_stage3_lb_bvn_l3_dlp_dlp_attr_t(basic_npl_struct):
    def __init__(self, dlp_attr=0, l3_dlp=0, bvn=0, type=0):
        super().__init__(40)
        self.dlp_attr = dlp_attr
        self.l3_dlp = l3_dlp
        self.bvn = bvn
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_stage3_lb_bvn_l3_dlp_dlp_attr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dlp_attr(self):
        return self._get_field_value(34, 6)
    @dlp_attr.setter
    def dlp_attr(self, value):
        self._set_field_value('field dlp_attr', 34, 6, int, value)
    @property
    def l3_dlp(self):
        return self._get_field_value(18, 16)
    @l3_dlp.setter
    def l3_dlp(self, value):
        self._set_field_value('field l3_dlp', 18, 16, int, value)
    @property
    def bvn(self):
        return self._get_field_value(2, 16)
    @bvn.setter
    def bvn(self, value):
        self._set_field_value('field bvn', 2, 16, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 2)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 2, int, value)



class npl_stage3_lb_destination_l3_dlp_t(basic_npl_struct):
    def __init__(self, l3_dlp=0, destination=0, type=0):
        super().__init__(40)
        self.l3_dlp = l3_dlp
        self.destination = destination
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_stage3_lb_destination_l3_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_dlp(self):
        return self._get_field_value(22, 16)
    @l3_dlp.setter
    def l3_dlp(self, value):
        self._set_field_value('field l3_dlp', 22, 16, int, value)
    @property
    def destination(self):
        return self._get_field_value(2, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 2, 20, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 2)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 2, int, value)



class npl_stage3_lb_dsp_l3_dlp_dlp_attr_t(basic_npl_struct):
    def __init__(self, dlp_attr=0, l3_dlp=0, dsp=0, type=0):
        super().__init__(40)
        self.dlp_attr = dlp_attr
        self.l3_dlp = l3_dlp
        self.dsp = dsp
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_stage3_lb_dsp_l3_dlp_dlp_attr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dlp_attr(self):
        return self._get_field_value(30, 6)
    @dlp_attr.setter
    def dlp_attr(self, value):
        self._set_field_value('field dlp_attr', 30, 6, int, value)
    @property
    def l3_dlp(self):
        return self._get_field_value(14, 16)
    @l3_dlp.setter
    def l3_dlp(self, value):
        self._set_field_value('field l3_dlp', 14, 16, int, value)
    @property
    def dsp(self):
        return self._get_field_value(2, 12)
    @dsp.setter
    def dsp(self, value):
        self._set_field_value('field dsp', 2, 12, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 2)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 2, int, value)



class npl_stage3_lb_dspa_l3_dlp_dlp_attr_t(basic_npl_struct):
    def __init__(self, dlp_attr=0, l3_dlp=0, dspa=0, type=0):
        super().__init__(40)
        self.dlp_attr = dlp_attr
        self.l3_dlp = l3_dlp
        self.dspa = dspa
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_stage3_lb_dspa_l3_dlp_dlp_attr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dlp_attr(self):
        return self._get_field_value(31, 6)
    @dlp_attr.setter
    def dlp_attr(self, value):
        self._set_field_value('field dlp_attr', 31, 6, int, value)
    @property
    def l3_dlp(self):
        return self._get_field_value(15, 16)
    @l3_dlp.setter
    def l3_dlp(self, value):
        self._set_field_value('field l3_dlp', 15, 16, int, value)
    @property
    def dspa(self):
        return self._get_field_value(2, 13)
    @dspa.setter
    def dspa(self, value):
        self._set_field_value('field dspa', 2, 13, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 2)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 2, int, value)



class npl_stage3_lb_raw_t(basic_npl_struct):
    def __init__(self, payload=0, type=0):
        super().__init__(40)
        self.payload = payload
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_stage3_lb_raw_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return self._get_field_value(2, 38)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 2, 38, int, value)
    @property
    def type(self):
        return self._get_field_value(0, 2)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 2, int, value)



class npl_stage3_lb_table_result_t(basic_npl_struct):
    def __init__(self):
        super().__init__(40)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_stage3_lb_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def bvn_l3_dlp_dlp_attr(self):
        return npl_stage3_lb_bvn_l3_dlp_dlp_attr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @bvn_l3_dlp_dlp_attr.setter
    def bvn_l3_dlp_dlp_attr(self, value):
        self._set_field_value('field bvn_l3_dlp_dlp_attr', 0, 40, npl_stage3_lb_bvn_l3_dlp_dlp_attr_t, value)
    @property
    def dsp_l3_dlp_dlp_attr(self):
        return npl_stage3_lb_dsp_l3_dlp_dlp_attr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dsp_l3_dlp_dlp_attr.setter
    def dsp_l3_dlp_dlp_attr(self, value):
        self._set_field_value('field dsp_l3_dlp_dlp_attr', 0, 40, npl_stage3_lb_dsp_l3_dlp_dlp_attr_t, value)
    @property
    def dspa_l3_dlp_dlp_attr(self):
        return npl_stage3_lb_dspa_l3_dlp_dlp_attr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dspa_l3_dlp_dlp_attr.setter
    def dspa_l3_dlp_dlp_attr(self, value):
        self._set_field_value('field dspa_l3_dlp_dlp_attr', 0, 40, npl_stage3_lb_dspa_l3_dlp_dlp_attr_t, value)
    @property
    def destination_l3_dlp(self):
        return npl_stage3_lb_destination_l3_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination_l3_dlp.setter
    def destination_l3_dlp(self, value):
        self._set_field_value('field destination_l3_dlp', 0, 40, npl_stage3_lb_destination_l3_dlp_t, value)
    @property
    def raw(self):
        return npl_stage3_lb_raw_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 40, npl_stage3_lb_raw_t, value)



class npl_stat_bank_index_len_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(2)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_stat_bank_index_len_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 2)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 2, int, value)



class npl_stat_meter_index_len_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(11)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_stat_meter_index_len_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 11)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 11, int, value)



class npl_std_ip_em_lpm_result_destination_t(basic_npl_struct):
    def __init__(self, destination=0):
        super().__init__(84)
        self.destination = destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_std_ip_em_lpm_result_destination_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 20, npl_destination_t, value)



class npl_std_ip_em_lpm_result_destination_with_default_t(basic_npl_struct):
    def __init__(self, is_default=0, destination=0):
        super().__init__(84)
        self.is_default = is_default
        self.destination = destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_std_ip_em_lpm_result_destination_with_default_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_default(self):
        return self._get_field_value(19, 1)
    @is_default.setter
    def is_default(self, value):
        self._set_field_value('field is_default', 19, 1, int, value)
    @property
    def destination(self):
        return self._get_field_value(0, 19)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 19, int, value)



class npl_stop_on_step_and_next_stage_compressed_fields_t(basic_npl_struct):
    def __init__(self, next_rtf_stage=0, stop_on_step=0):
        super().__init__(4)
        self.next_rtf_stage = next_rtf_stage
        self.stop_on_step = stop_on_step

    def _get_as_sub_field(data, offset_in_data):
        result = npl_stop_on_step_and_next_stage_compressed_fields_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def next_rtf_stage(self):
        return self._get_field_value(1, 3)
    @next_rtf_stage.setter
    def next_rtf_stage(self, value):
        self._set_field_value('field next_rtf_stage', 1, 3, int, value)
    @property
    def stop_on_step(self):
        return self._get_field_value(0, 1)
    @stop_on_step.setter
    def stop_on_step(self, value):
        self._set_field_value('field stop_on_step', 0, 1, int, value)



class npl_svi_eve_sub_type_plus_prf_t(basic_npl_struct):
    def __init__(self, sub_type=0, prf=0):
        super().__init__(5)
        self.sub_type = sub_type
        self.prf = prf

    def _get_as_sub_field(data, offset_in_data):
        result = npl_svi_eve_sub_type_plus_prf_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sub_type(self):
        return self._get_field_value(2, 3)
    @sub_type.setter
    def sub_type(self, value):
        self._set_field_value('field sub_type', 2, 3, int, value)
    @property
    def prf(self):
        return self._get_field_value(0, 2)
    @prf.setter
    def prf(self, value):
        self._set_field_value('field prf', 0, 2, int, value)



class npl_svi_eve_vid2_plus_prf_t(basic_npl_struct):
    def __init__(self, vid2=0, prf=0):
        super().__init__(14)
        self.vid2 = vid2
        self.prf = prf

    def _get_as_sub_field(data, offset_in_data):
        result = npl_svi_eve_vid2_plus_prf_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def vid2(self):
        return self._get_field_value(2, 12)
    @vid2.setter
    def vid2(self, value):
        self._set_field_value('field vid2', 2, 12, int, value)
    @property
    def prf(self):
        return self._get_field_value(0, 2)
    @prf.setter
    def prf(self, value):
        self._set_field_value('field prf', 0, 2, int, value)



class npl_svl_traps_t(basic_npl_struct):
    def __init__(self, control_protocol=0, control_ipc=0, svl_mc_prune=0):
        super().__init__(3)
        self.control_protocol = control_protocol
        self.control_ipc = control_ipc
        self.svl_mc_prune = svl_mc_prune

    def _get_as_sub_field(data, offset_in_data):
        result = npl_svl_traps_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def control_protocol(self):
        return self._get_field_value(2, 1)
    @control_protocol.setter
    def control_protocol(self, value):
        self._set_field_value('field control_protocol', 2, 1, int, value)
    @property
    def control_ipc(self):
        return self._get_field_value(1, 1)
    @control_ipc.setter
    def control_ipc(self, value):
        self._set_field_value('field control_ipc', 1, 1, int, value)
    @property
    def svl_mc_prune(self):
        return self._get_field_value(0, 1)
    @svl_mc_prune.setter
    def svl_mc_prune(self, value):
        self._set_field_value('field svl_mc_prune', 0, 1, int, value)



class npl_system_mcid_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(18)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_system_mcid_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 18)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 18, int, value)



class npl_te_headend_nhlfe_t(basic_npl_struct):
    def __init__(self, lsp_destination=0, counter_offset=0):
        super().__init__(28)
        self.lsp_destination = lsp_destination
        self.counter_offset = counter_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_te_headend_nhlfe_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lsp_destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @lsp_destination.setter
    def lsp_destination(self, value):
        self._set_field_value('field lsp_destination', 8, 20, npl_destination_t, value)
    @property
    def counter_offset(self):
        return npl_compressed_counter_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @counter_offset.setter
    def counter_offset(self, value):
        self._set_field_value('field counter_offset', 0, 8, npl_compressed_counter_t, value)



class npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def swap_label(self):
        return self._get_field_value(0, 20)
    @swap_label.setter
    def swap_label(self, value):
        self._set_field_value('field swap_label', 0, 20, int, value)
    @property
    def lsp_id(self):
        return self._get_field_value(0, 20)
    @lsp_id.setter
    def lsp_id(self, value):
        self._set_field_value('field lsp_id', 0, 20, int, value)



class npl_tm_header_base_t(basic_npl_struct):
    def __init__(self, hdr_type=0, vce=0, tc=0, dp=0):
        super().__init__(8)
        self.hdr_type = hdr_type
        self.vce = vce
        self.tc = tc
        self.dp = dp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_tm_header_base_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def hdr_type(self):
        return self._get_field_value(6, 2)
    @hdr_type.setter
    def hdr_type(self, value):
        self._set_field_value('field hdr_type', 6, 2, int, value)
    @property
    def vce(self):
        return self._get_field_value(5, 1)
    @vce.setter
    def vce(self, value):
        self._set_field_value('field vce', 5, 1, int, value)
    @property
    def tc(self):
        return self._get_field_value(2, 3)
    @tc.setter
    def tc(self, value):
        self._set_field_value('field tc', 2, 3, int, value)
    @property
    def dp(self):
        return self._get_field_value(0, 2)
    @dp.setter
    def dp(self, value):
        self._set_field_value('field dp', 0, 2, int, value)



class npl_tos_t(basic_npl_struct):
    def __init__(self, dscp=0, ecn=0):
        super().__init__(8)
        self.dscp = dscp
        self.ecn = ecn

    def _get_as_sub_field(data, offset_in_data):
        result = npl_tos_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dscp(self):
        return self._get_field_value(2, 6)
    @dscp.setter
    def dscp(self, value):
        self._set_field_value('field dscp', 2, 6, int, value)
    @property
    def ecn(self):
        return self._get_field_value(0, 2)
    @ecn.setter
    def ecn(self, value):
        self._set_field_value('field ecn', 0, 2, int, value)



class npl_tpid_sa_lsb_t(basic_npl_struct):
    def __init__(self, sa_lsb=0, tpid=0):
        super().__init__(32)
        self.sa_lsb = sa_lsb
        self.tpid = tpid

    def _get_as_sub_field(data, offset_in_data):
        result = npl_tpid_sa_lsb_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sa_lsb(self):
        return self._get_field_value(16, 16)
    @sa_lsb.setter
    def sa_lsb(self, value):
        self._set_field_value('field sa_lsb', 16, 16, int, value)
    @property
    def tpid(self):
        return self._get_field_value(0, 16)
    @tpid.setter
    def tpid(self, value):
        self._set_field_value('field tpid', 0, 16, int, value)



class npl_trap_conditions_t(basic_npl_struct):
    def __init__(self, non_inject_up=0, skip_p2p=0):
        super().__init__(2)
        self.non_inject_up = non_inject_up
        self.skip_p2p = skip_p2p

    def _get_as_sub_field(data, offset_in_data):
        result = npl_trap_conditions_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def non_inject_up(self):
        return self._get_field_value(1, 1)
    @non_inject_up.setter
    def non_inject_up(self, value):
        self._set_field_value('field non_inject_up', 1, 1, int, value)
    @property
    def skip_p2p(self):
        return self._get_field_value(0, 1)
    @skip_p2p.setter
    def skip_p2p(self, value):
        self._set_field_value('field skip_p2p', 0, 1, int, value)



class npl_traps_t(basic_npl_struct):
    def __init__(self, ethernet=0, ipv4=0, ipv6=0, mpls=0, l3=0, oamp=0, app=0, svl=0, l2_lpts=0, internal=0):
        super().__init__(197)
        self.ethernet = ethernet
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.mpls = mpls
        self.l3 = l3
        self.oamp = oamp
        self.app = app
        self.svl = svl
        self.l2_lpts = l2_lpts
        self.internal = internal

    def _get_as_sub_field(data, offset_in_data):
        result = npl_traps_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ethernet(self):
        return npl_ethernet_traps_t._get_as_sub_field(self._data, self._offset_in_data + 142)
    @ethernet.setter
    def ethernet(self, value):
        self._set_field_value('field ethernet', 142, 55, npl_ethernet_traps_t, value)
    @property
    def ipv4(self):
        return npl_ipv4_traps_t._get_as_sub_field(self._data, self._offset_in_data + 135)
    @ipv4.setter
    def ipv4(self, value):
        self._set_field_value('field ipv4', 135, 7, npl_ipv4_traps_t, value)
    @property
    def ipv6(self):
        return npl_ipv6_traps_t._get_as_sub_field(self._data, self._offset_in_data + 126)
    @ipv6.setter
    def ipv6(self, value):
        self._set_field_value('field ipv6', 126, 9, npl_ipv6_traps_t, value)
    @property
    def mpls(self):
        return npl_mpls_traps_t._get_as_sub_field(self._data, self._offset_in_data + 101)
    @mpls.setter
    def mpls(self, value):
        self._set_field_value('field mpls', 101, 25, npl_mpls_traps_t, value)
    @property
    def l3(self):
        return npl_l3_traps_t._get_as_sub_field(self._data, self._offset_in_data + 48)
    @l3.setter
    def l3(self, value):
        self._set_field_value('field l3', 48, 53, npl_l3_traps_t, value)
    @property
    def oamp(self):
        return npl_oamp_traps_t._get_as_sub_field(self._data, self._offset_in_data + 23)
    @oamp.setter
    def oamp(self, value):
        self._set_field_value('field oamp', 23, 25, npl_oamp_traps_t, value)
    @property
    def app(self):
        return npl_app_traps_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @app.setter
    def app(self, value):
        self._set_field_value('field app', 20, 3, npl_app_traps_t, value)
    @property
    def svl(self):
        return npl_svl_traps_t._get_as_sub_field(self._data, self._offset_in_data + 17)
    @svl.setter
    def svl(self, value):
        self._set_field_value('field svl', 17, 3, npl_svl_traps_t, value)
    @property
    def l2_lpts(self):
        return npl_l2_lpts_traps_t._get_as_sub_field(self._data, self._offset_in_data + 5)
    @l2_lpts.setter
    def l2_lpts(self, value):
        self._set_field_value('field l2_lpts', 5, 12, npl_l2_lpts_traps_t, value)
    @property
    def internal(self):
        return npl_internal_traps_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @internal.setter
    def internal(self, value):
        self._set_field_value('field internal', 0, 5, npl_internal_traps_t, value)



class npl_ts_cmd_trans_t(basic_npl_struct):
    def __init__(self, op=0, update_udp_cs=0, reset_udp_cs=0, ifg_ts_cmd=0):
        super().__init__(8)
        self.op = op
        self.update_udp_cs = update_udp_cs
        self.reset_udp_cs = reset_udp_cs
        self.ifg_ts_cmd = ifg_ts_cmd

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ts_cmd_trans_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def op(self):
        return self._get_field_value(4, 4)
    @op.setter
    def op(self, value):
        self._set_field_value('field op', 4, 4, int, value)
    @property
    def update_udp_cs(self):
        return self._get_field_value(3, 1)
    @update_udp_cs.setter
    def update_udp_cs(self, value):
        self._set_field_value('field update_udp_cs', 3, 1, int, value)
    @property
    def reset_udp_cs(self):
        return self._get_field_value(2, 1)
    @reset_udp_cs.setter
    def reset_udp_cs(self, value):
        self._set_field_value('field reset_udp_cs', 2, 1, int, value)
    @property
    def ifg_ts_cmd(self):
        return self._get_field_value(0, 2)
    @ifg_ts_cmd.setter
    def ifg_ts_cmd(self, value):
        self._set_field_value('field ifg_ts_cmd', 0, 2, int, value)



class npl_ts_command_t(basic_npl_struct):
    def __init__(self, op=0, offset=0):
        super().__init__(12)
        self.op = op
        self.offset = offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ts_command_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def op(self):
        return self._get_field_value(8, 4)
    @op.setter
    def op(self, value):
        self._set_field_value('field op', 8, 4, int, value)
    @property
    def offset(self):
        return self._get_field_value(0, 7)
    @offset.setter
    def offset(self, value):
        self._set_field_value('field offset', 0, 7, int, value)



class npl_ttl_and_protocol_t(basic_npl_struct):
    def __init__(self, ttl=0, protocol=0):
        super().__init__(16)
        self.ttl = ttl
        self.protocol = protocol

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ttl_and_protocol_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ttl(self):
        return self._get_field_value(8, 8)
    @ttl.setter
    def ttl(self, value):
        self._set_field_value('field ttl', 8, 8, int, value)
    @property
    def protocol(self):
        return self._get_field_value(0, 8)
    @protocol.setter
    def protocol(self, value):
        self._set_field_value('field protocol', 0, 8, int, value)



class npl_tunnel_control_t(basic_npl_struct):
    def __init__(self, decrement_inner_ttl=0, ttl_mode=0, is_tos_from_tunnel=0, lp_set=0):
        super().__init__(4)
        self.decrement_inner_ttl = decrement_inner_ttl
        self.ttl_mode = ttl_mode
        self.is_tos_from_tunnel = is_tos_from_tunnel
        self.lp_set = lp_set

    def _get_as_sub_field(data, offset_in_data):
        result = npl_tunnel_control_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def decrement_inner_ttl(self):
        return self._get_field_value(3, 1)
    @decrement_inner_ttl.setter
    def decrement_inner_ttl(self, value):
        self._set_field_value('field decrement_inner_ttl', 3, 1, int, value)
    @property
    def ttl_mode(self):
        return self._get_field_value(2, 1)
    @ttl_mode.setter
    def ttl_mode(self, value):
        self._set_field_value('field ttl_mode', 2, 1, int, value)
    @property
    def is_tos_from_tunnel(self):
        return self._get_field_value(1, 1)
    @is_tos_from_tunnel.setter
    def is_tos_from_tunnel(self, value):
        self._set_field_value('field is_tos_from_tunnel', 1, 1, int, value)
    @property
    def lp_set(self):
        return self._get_field_value(0, 1)
    @lp_set.setter
    def lp_set(self, value):
        self._set_field_value('field lp_set', 0, 1, int, value)



class npl_tunnel_dlp_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(15)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_tunnel_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 15)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 15, int, value)



class npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t(basic_npl_struct):
    def __init__(self):
        super().__init__(16)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def te_tunnel(self):
        return self._get_field_value(0, 16)
    @te_tunnel.setter
    def te_tunnel(self, value):
        self._set_field_value('field te_tunnel', 0, 16, int, value)
    @property
    def asbr(self):
        return self._get_field_value(0, 16)
    @asbr.setter
    def asbr(self, value):
        self._set_field_value('field asbr', 0, 16, int, value)



class npl_tunnel_type_q_counter_t(basic_npl_struct):
    def __init__(self, tunnel_type=0, q_counter=0):
        super().__init__(20)
        self.tunnel_type = tunnel_type
        self.q_counter = q_counter

    def _get_as_sub_field(data, offset_in_data):
        result = npl_tunnel_type_q_counter_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tunnel_type(self):
        return self._get_field_value(19, 1)
    @tunnel_type.setter
    def tunnel_type(self, value):
        self._set_field_value('field tunnel_type', 19, 1, int, value)
    @property
    def q_counter(self):
        return self._get_field_value(0, 19)
    @q_counter.setter
    def q_counter(self, value):
        self._set_field_value('field q_counter', 0, 19, int, value)



class npl_tx_punt_nw_encap_ptr_t(basic_npl_struct):
    def __init__(self, punt_nw_encap_type=0, punt_nw_encap_ptr=0):
        super().__init__(12)
        self.punt_nw_encap_type = punt_nw_encap_type
        self.punt_nw_encap_ptr = punt_nw_encap_ptr

    def _get_as_sub_field(data, offset_in_data):
        result = npl_tx_punt_nw_encap_ptr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def punt_nw_encap_type(self):
        return self._get_field_value(8, 4)
    @punt_nw_encap_type.setter
    def punt_nw_encap_type(self, value):
        self._set_field_value('field punt_nw_encap_type', 8, 4, int, value)
    @property
    def punt_nw_encap_ptr(self):
        return npl_punt_nw_encap_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_nw_encap_ptr.setter
    def punt_nw_encap_ptr(self, value):
        self._set_field_value('field punt_nw_encap_ptr', 0, 8, npl_punt_nw_encap_ptr_t, value)



class npl_txpp_first_macro_table_key_t(basic_npl_struct):
    def __init__(self, is_mc=0, fwd_type=0, first_encap_type=0, second_encap_type=0):
        super().__init__(13)
        self.is_mc = is_mc
        self.fwd_type = fwd_type
        self.first_encap_type = first_encap_type
        self.second_encap_type = second_encap_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_txpp_first_macro_table_key_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_mc(self):
        return self._get_field_value(12, 1)
    @is_mc.setter
    def is_mc(self, value):
        self._set_field_value('field is_mc', 12, 1, int, value)
    @property
    def fwd_type(self):
        return self._get_field_value(8, 4)
    @fwd_type.setter
    def fwd_type(self, value):
        self._set_field_value('field fwd_type', 8, 4, int, value)
    @property
    def first_encap_type(self):
        return self._get_field_value(4, 4)
    @first_encap_type.setter
    def first_encap_type(self, value):
        self._set_field_value('field first_encap_type', 4, 4, int, value)
    @property
    def second_encap_type(self):
        return self._get_field_value(0, 4)
    @second_encap_type.setter
    def second_encap_type(self, value):
        self._set_field_value('field second_encap_type', 0, 4, int, value)



class npl_udf_t(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(128)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_udf_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 128)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 128, int, value)



class npl_udp_encap_data_t(basic_npl_struct):
    def __init__(self, sport=0, dport=0):
        super().__init__(32)
        self.sport = sport
        self.dport = dport

    def _get_as_sub_field(data, offset_in_data):
        result = npl_udp_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sport(self):
        return self._get_field_value(16, 16)
    @sport.setter
    def sport(self, value):
        self._set_field_value('field sport', 16, 16, int, value)
    @property
    def dport(self):
        return self._get_field_value(0, 16)
    @dport.setter
    def dport(self, value):
        self._set_field_value('field dport', 0, 16, int, value)



class npl_unicast_flb_tm_header_t(basic_npl_struct):
    def __init__(self, base=0, reserved=0, dsp=0):
        super().__init__(24)
        self.base = base
        self.reserved = reserved
        self.dsp = dsp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_unicast_flb_tm_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def base(self):
        return npl_tm_header_base_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @base.setter
    def base(self, value):
        self._set_field_value('field base', 16, 8, npl_tm_header_base_t, value)
    @property
    def reserved(self):
        return self._get_field_value(13, 3)
    @reserved.setter
    def reserved(self, value):
        self._set_field_value('field reserved', 13, 3, int, value)
    @property
    def dsp(self):
        return self._get_field_value(0, 13)
    @dsp.setter
    def dsp(self, value):
        self._set_field_value('field dsp', 0, 13, int, value)



class npl_unicast_plb_tm_header_t(basic_npl_struct):
    def __init__(self, base=0, reserved=0, destination_device=0, destination_slice=0, destination_oq=0):
        super().__init__(32)
        self.base = base
        self.reserved = reserved
        self.destination_device = destination_device
        self.destination_slice = destination_slice
        self.destination_oq = destination_oq

    def _get_as_sub_field(data, offset_in_data):
        result = npl_unicast_plb_tm_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def base(self):
        return npl_tm_header_base_t._get_as_sub_field(self._data, self._offset_in_data + 24)
    @base.setter
    def base(self, value):
        self._set_field_value('field base', 24, 8, npl_tm_header_base_t, value)
    @property
    def reserved(self):
        return self._get_field_value(21, 3)
    @reserved.setter
    def reserved(self, value):
        self._set_field_value('field reserved', 21, 3, int, value)
    @property
    def destination_device(self):
        return self._get_field_value(12, 9)
    @destination_device.setter
    def destination_device(self, value):
        self._set_field_value('field destination_device', 12, 9, int, value)
    @property
    def destination_slice(self):
        return self._get_field_value(9, 3)
    @destination_slice.setter
    def destination_slice(self, value):
        self._set_field_value('field destination_slice', 9, 3, int, value)
    @property
    def destination_oq(self):
        return self._get_field_value(0, 9)
    @destination_oq.setter
    def destination_oq(self, value):
        self._set_field_value('field destination_oq', 0, 9, int, value)



class npl_unscheduled_recycle_code_t(basic_npl_struct):
    def __init__(self, recycle_pkt=0, unscheduled_recycle_code_lsb=0):
        super().__init__(2)
        self.recycle_pkt = recycle_pkt
        self.unscheduled_recycle_code_lsb = unscheduled_recycle_code_lsb

    def _get_as_sub_field(data, offset_in_data):
        result = npl_unscheduled_recycle_code_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def recycle_pkt(self):
        return self._get_field_value(1, 1)
    @recycle_pkt.setter
    def recycle_pkt(self, value):
        self._set_field_value('field recycle_pkt', 1, 1, int, value)
    @property
    def unscheduled_recycle_code_lsb(self):
        return self._get_field_value(0, 1)
    @unscheduled_recycle_code_lsb.setter
    def unscheduled_recycle_code_lsb(self, value):
        self._set_field_value('field unscheduled_recycle_code_lsb', 0, 1, int, value)



class npl_use_metedata_table_per_packet_format_t(basic_npl_struct):
    def __init__(self, use_metadata_table_for_ip_packet=0, use_metadata_table_for_non_ip_packet=0):
        super().__init__(2)
        self.use_metadata_table_for_ip_packet = use_metadata_table_for_ip_packet
        self.use_metadata_table_for_non_ip_packet = use_metadata_table_for_non_ip_packet

    def _get_as_sub_field(data, offset_in_data):
        result = npl_use_metedata_table_per_packet_format_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def use_metadata_table_for_ip_packet(self):
        return npl_bool_t._get_as_sub_field(self._data, self._offset_in_data + 1)
    @use_metadata_table_for_ip_packet.setter
    def use_metadata_table_for_ip_packet(self, value):
        self._set_field_value('field use_metadata_table_for_ip_packet', 1, 1, npl_bool_t, value)
    @property
    def use_metadata_table_for_non_ip_packet(self):
        return npl_bool_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @use_metadata_table_for_non_ip_packet.setter
    def use_metadata_table_for_non_ip_packet(self, value):
        self._set_field_value('field use_metadata_table_for_non_ip_packet', 0, 1, npl_bool_t, value)



class npl_vid2_or_flood_rcy_sm_vlans_t(basic_npl_struct):
    def __init__(self):
        super().__init__(24)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_vid2_or_flood_rcy_sm_vlans_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def vid2(self):
        return self._get_field_value(0, 12)
    @vid2.setter
    def vid2(self, value):
        self._set_field_value('field vid2', 0, 12, int, value)
    @property
    def flood_rcy_sm_vlans(self):
        return npl_rcy_sm_vlans_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @flood_rcy_sm_vlans.setter
    def flood_rcy_sm_vlans(self, value):
        self._set_field_value('field flood_rcy_sm_vlans', 0, 24, npl_rcy_sm_vlans_t, value)



class npl_vlan_and_sa_lsb_encap_t(basic_npl_struct):
    def __init__(self, vlan_id=0, tpid_sa_lsb=0):
        super().__init__(44)
        self.vlan_id = vlan_id
        self.tpid_sa_lsb = tpid_sa_lsb

    def _get_as_sub_field(data, offset_in_data):
        result = npl_vlan_and_sa_lsb_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def vlan_id(self):
        return self._get_field_value(32, 12)
    @vlan_id.setter
    def vlan_id(self, value):
        self._set_field_value('field vlan_id', 32, 12, int, value)
    @property
    def tpid_sa_lsb(self):
        return npl_tpid_sa_lsb_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @tpid_sa_lsb.setter
    def tpid_sa_lsb(self, value):
        self._set_field_value('field tpid_sa_lsb', 0, 32, npl_tpid_sa_lsb_t, value)



class npl_vlan_edit_secondary_type_with_padding_t(basic_npl_struct):
    def __init__(self, secondary_type=0):
        super().__init__(12)
        self.secondary_type = secondary_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_vlan_edit_secondary_type_with_padding_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def secondary_type(self):
        return self._get_field_value(0, 3)
    @secondary_type.setter
    def secondary_type(self, value):
        self._set_field_value('field secondary_type', 0, 3, int, value)



class npl_vlan_header_flags_t(basic_npl_struct):
    def __init__(self, is_priority=0):
        super().__init__(3)
        self.is_priority = is_priority

    def _get_as_sub_field(data, offset_in_data):
        result = npl_vlan_header_flags_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_priority(self):
        return self._get_field_value(0, 1)
    @is_priority.setter
    def is_priority(self, value):
        self._set_field_value('field is_priority', 0, 1, int, value)



class npl_vlan_id_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(12)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_vlan_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 12)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 12, int, value)



class npl_vlan_profile_and_lp_type_t(basic_npl_struct):
    def __init__(self, l2_lp_type=0, vlan_profile=0):
        super().__init__(8)
        self.l2_lp_type = l2_lp_type
        self.vlan_profile = vlan_profile

    def _get_as_sub_field(data, offset_in_data):
        result = npl_vlan_profile_and_lp_type_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2_lp_type(self):
        return self._get_field_value(4, 4)
    @l2_lp_type.setter
    def l2_lp_type(self, value):
        self._set_field_value('field l2_lp_type', 4, 4, int, value)
    @property
    def vlan_profile(self):
        return self._get_field_value(0, 4)
    @vlan_profile.setter
    def vlan_profile(self, value):
        self._set_field_value('field vlan_profile', 0, 4, int, value)



class npl_vlan_tag_tci_t(basic_npl_struct):
    def __init__(self, pcp_dei=0, vid=0):
        super().__init__(16)
        self.pcp_dei = pcp_dei
        self.vid = vid

    def _get_as_sub_field(data, offset_in_data):
        result = npl_vlan_tag_tci_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def pcp_dei(self):
        return npl_pcp_dei_t._get_as_sub_field(self._data, self._offset_in_data + 12)
    @pcp_dei.setter
    def pcp_dei(self, value):
        self._set_field_value('field pcp_dei', 12, 4, npl_pcp_dei_t, value)
    @property
    def vid(self):
        return npl_vlan_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @vid.setter
    def vid(self, value):
        self._set_field_value('field vid', 0, 12, npl_vlan_id_t, value)



class npl_vni_table_result_t(basic_npl_struct):
    def __init__(self, vlan_profile=0, l2_relay_attributes_id=0, vni_counter=0):
        super().__init__(38)
        self.vlan_profile = vlan_profile
        self.l2_relay_attributes_id = l2_relay_attributes_id
        self.vni_counter = vni_counter

    def _get_as_sub_field(data, offset_in_data):
        result = npl_vni_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def vlan_profile(self):
        return self._get_field_value(34, 4)
    @vlan_profile.setter
    def vlan_profile(self, value):
        self._set_field_value('field vlan_profile', 34, 4, int, value)
    @property
    def l2_relay_attributes_id(self):
        return npl_l2_relay_id_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @l2_relay_attributes_id.setter
    def l2_relay_attributes_id(self, value):
        self._set_field_value('field l2_relay_attributes_id', 20, 14, npl_l2_relay_id_t, value)
    @property
    def vni_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @vni_counter.setter
    def vni_counter(self, value):
        self._set_field_value('field vni_counter', 0, 20, npl_counter_ptr_t, value)



class npl_voq_cgm_slice_dram_cgm_profile_results_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(106)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_voq_cgm_slice_dram_cgm_profile_results_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def wred_probability_region(self):
        return basic_npl_array(104, 8, npl_quan_13b, self._data, self._offset_in_data + 2)
    @wred_probability_region.setter
    def wred_probability_region(self, value):
        field = basic_npl_array(104, 8, npl_quan_13b, self._data, self._offset_in_data + 2)
        field._set_field_value('field wred_probability_region', 0, 104, basic_npl_array, value)
    @property
    def wred_action(self):
        return self._get_field_value(0, 2)
    @wred_action.setter
    def wred_action(self, value):
        self._set_field_value('field wred_action', 0, 2, int, value)



class npl_voq_cgm_slice_profile_buff_region_thresholds_results_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(98)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_voq_cgm_slice_profile_buff_region_thresholds_results_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def q_size_buff_region(self):
        return basic_npl_array(98, 7, npl_quan_14b, self._data, self._offset_in_data + 0)
    @q_size_buff_region.setter
    def q_size_buff_region(self, value):
        field = basic_npl_array(98, 7, npl_quan_14b, self._data, self._offset_in_data + 0)
        field._set_field_value('field q_size_buff_region', 0, 98, basic_npl_array, value)



class npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(120)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def pkt_enq_time_region(self):
        return basic_npl_array(120, 15, npl_quan_8b, self._data, self._offset_in_data + 0)
    @pkt_enq_time_region.setter
    def pkt_enq_time_region(self, value):
        field = basic_npl_array(120, 15, npl_quan_8b, self._data, self._offset_in_data + 0)
        field._set_field_value('field pkt_enq_time_region', 0, 120, basic_npl_array, value)



class npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(98)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def q_size_pkt_region(self):
        return basic_npl_array(98, 7, npl_quan_14b, self._data, self._offset_in_data + 0)
    @q_size_pkt_region.setter
    def q_size_pkt_region(self, value):
        field = basic_npl_array(98, 7, npl_quan_14b, self._data, self._offset_in_data + 0)
        field._set_field_value('field q_size_pkt_region', 0, 98, basic_npl_array, value)



class npl_voq_cgm_slice_slice_cgm_profile_result_t(basic_npl_struct):
    def __init__(self, counter_id=0):
        super().__init__(3)
        self.counter_id = counter_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_voq_cgm_slice_slice_cgm_profile_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def counter_id(self):
        return self._get_field_value(0, 3)
    @counter_id.setter
    def counter_id(self, value):
        self._set_field_value('field counter_id', 0, 3, int, value)



class npl_voq_profile_len(basic_npl_struct):
    def __init__(self, value=0):
        super().__init__(5)
        self.value = value

    def _get_as_sub_field(data, offset_in_data):
        result = npl_voq_profile_len()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def value(self):
        return self._get_field_value(0, 5)
    @value.setter
    def value(self, value):
        self._set_field_value('field value', 0, 5, int, value)



class npl_vpl_label_and_valid_t(basic_npl_struct):
    def __init__(self, v6_label_vld=0, v4_label_vld=0, label_encap=0):
        super().__init__(26)
        self.v6_label_vld = v6_label_vld
        self.v4_label_vld = v4_label_vld
        self.label_encap = label_encap

    def _get_as_sub_field(data, offset_in_data):
        result = npl_vpl_label_and_valid_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def v6_label_vld(self):
        return self._get_field_value(25, 1)
    @v6_label_vld.setter
    def v6_label_vld(self, value):
        self._set_field_value('field v6_label_vld', 25, 1, int, value)
    @property
    def v4_label_vld(self):
        return self._get_field_value(24, 1)
    @v4_label_vld.setter
    def v4_label_vld(self, value):
        self._set_field_value('field v4_label_vld', 24, 1, int, value)
    @property
    def label_encap(self):
        return npl_exp_bos_and_label_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @label_encap.setter
    def label_encap(self, value):
        self._set_field_value('field label_encap', 0, 24, npl_exp_bos_and_label_t, value)



class npl_vxlan_dlp_specific_t(basic_npl_struct):
    def __init__(self, stp_state_is_block=0, lp_profile=0, ttl_mode=0, disabled=0, lp_set=0, qos_info=0, p_counter=0, sip_index=0, dip=0, ttl=0):
        super().__init__(75)
        self.stp_state_is_block = stp_state_is_block
        self.lp_profile = lp_profile
        self.ttl_mode = ttl_mode
        self.disabled = disabled
        self.lp_set = lp_set
        self.qos_info = qos_info
        self.p_counter = p_counter
        self.sip_index = sip_index
        self.dip = dip
        self.ttl = ttl

    def _get_as_sub_field(data, offset_in_data):
        result = npl_vxlan_dlp_specific_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def stp_state_is_block(self):
        return self._get_field_value(74, 1)
    @stp_state_is_block.setter
    def stp_state_is_block(self, value):
        self._set_field_value('field stp_state_is_block', 74, 1, int, value)
    @property
    def lp_profile(self):
        return self._get_field_value(72, 2)
    @lp_profile.setter
    def lp_profile(self, value):
        self._set_field_value('field lp_profile', 72, 2, int, value)
    @property
    def ttl_mode(self):
        return self._get_field_value(71, 1)
    @ttl_mode.setter
    def ttl_mode(self, value):
        self._set_field_value('field ttl_mode', 71, 1, int, value)
    @property
    def disabled(self):
        return self._get_field_value(70, 1)
    @disabled.setter
    def disabled(self, value):
        self._set_field_value('field disabled', 70, 1, int, value)
    @property
    def lp_set(self):
        return self._get_field_value(69, 1)
    @lp_set.setter
    def lp_set(self, value):
        self._set_field_value('field lp_set', 69, 1, int, value)
    @property
    def qos_info(self):
        return npl_qos_info_t._get_as_sub_field(self._data, self._offset_in_data + 64)
    @qos_info.setter
    def qos_info(self, value):
        self._set_field_value('field qos_info', 64, 5, npl_qos_info_t, value)
    @property
    def p_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 44)
    @p_counter.setter
    def p_counter(self, value):
        self._set_field_value('field p_counter', 44, 20, npl_counter_ptr_t, value)
    @property
    def sip_index(self):
        return self._get_field_value(40, 4)
    @sip_index.setter
    def sip_index(self, value):
        self._set_field_value('field sip_index', 40, 4, int, value)
    @property
    def dip(self):
        return npl_ip_tunnel_dip_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @dip.setter
    def dip(self, value):
        self._set_field_value('field dip', 8, 32, npl_ip_tunnel_dip_t, value)
    @property
    def ttl(self):
        return self._get_field_value(0, 8)
    @ttl.setter
    def ttl(self, value):
        self._set_field_value('field ttl', 0, 8, int, value)



class npl_vxlan_encap_data_t(basic_npl_struct):
    def __init__(self, vni=0):
        super().__init__(32)
        self.vni = vni

    def _get_as_sub_field(data, offset_in_data):
        result = npl_vxlan_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def vni(self):
        return self._get_field_value(0, 24)
    @vni.setter
    def vni(self, value):
        self._set_field_value('field vni', 0, 24, int, value)



class npl_vxlan_relay_encap_data_t(basic_npl_struct):
    def __init__(self, vni=0, vni_counter=0):
        super().__init__(44)
        self.vni = vni
        self.vni_counter = vni_counter

    def _get_as_sub_field(data, offset_in_data):
        result = npl_vxlan_relay_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def vni(self):
        return self._get_field_value(20, 24)
    @vni.setter
    def vni(self, value):
        self._set_field_value('field vni', 20, 24, int, value)
    @property
    def vni_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @vni_counter.setter
    def vni_counter(self, value):
        self._set_field_value('field vni_counter', 0, 20, npl_counter_ptr_t, value)



class npl_wfq_priority_weight_t(basic_npl_struct):
    def __init__(self, weight=0):
        super().__init__(8)
        self.weight = weight

    def _get_as_sub_field(data, offset_in_data):
        result = npl_wfq_priority_weight_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def weight(self):
        return self._get_field_value(0, 8)
    @weight.setter
    def weight(self, value):
        self._set_field_value('field weight', 0, 8, int, value)



class npl_wfq_weight_4p_entry_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(32)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_wfq_weight_4p_entry_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def priority(self):
        return basic_npl_array(32, 4, npl_wfq_priority_weight_t, self._data, self._offset_in_data + 0)
    @priority.setter
    def priority(self, value):
        field = basic_npl_array(32, 4, npl_wfq_priority_weight_t, self._data, self._offset_in_data + 0)
        field._set_field_value('field priority', 0, 32, basic_npl_array, value)



class npl_wfq_weight_8p_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(64)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_wfq_weight_8p_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def priority(self):
        return basic_npl_array(64, 8, npl_wfq_priority_weight_t, self._data, self._offset_in_data + 0)
    @priority.setter
    def priority(self, value):
        field = basic_npl_array(64, 8, npl_wfq_priority_weight_t, self._data, self._offset_in_data + 0)
        field._set_field_value('field priority', 0, 64, basic_npl_array, value)



class npl_app_relay_id_t(basic_npl_struct):
    def __init__(self):
        super().__init__(14)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_app_relay_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2_relay_id(self):
        return npl_l2_relay_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_relay_id.setter
    def l2_relay_id(self, value):
        self._set_field_value('field l2_relay_id', 0, 14, npl_l2_relay_id_t, value)
    @property
    def l3_relay_id(self):
        return npl_l3_relay_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_relay_id.setter
    def l3_relay_id(self, value):
        self._set_field_value('field l3_relay_id', 0, 11, npl_l3_relay_id_t, value)



class npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t(basic_npl_struct):
    def __init__(self):
        super().__init__(12)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rtf_conf_set_and_stages(self):
        return npl_rtf_conf_set_and_stages_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @rtf_conf_set_and_stages.setter
    def rtf_conf_set_and_stages(self, value):
        self._set_field_value('field rtf_conf_set_and_stages', 0, 12, npl_rtf_conf_set_and_stages_t, value)
    @property
    def ip_ver_and_post_fwd_stage(self):
        return npl_ip_ver_and_post_fwd_stage_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ip_ver_and_post_fwd_stage.setter
    def ip_ver_and_post_fwd_stage(self, value):
        self._set_field_value('field ip_ver_and_post_fwd_stage', 0, 4, npl_ip_ver_and_post_fwd_stage_t, value)



class npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t(basic_npl_struct):
    def __init__(self):
        super().__init__(40)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ipv6(self):
        return npl_bfd_ipv6_prot_shared_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ipv6.setter
    def ipv6(self, value):
        self._set_field_value('field ipv6', 0, 40, npl_bfd_ipv6_prot_shared_t, value)
    @property
    def ipv4(self):
        return npl_bfd_ipv4_prot_shared_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ipv4.setter
    def ipv4(self, value):
        self._set_field_value('field ipv4', 0, 40, npl_bfd_ipv4_prot_shared_t, value)



class npl_bfd_aux_transmit_payload_t(basic_npl_struct):
    def __init__(self, prot_trans=0, interval_selector=0, echo_mode_enabled=0):
        super().__init__(40)
        self.prot_trans = prot_trans
        self.interval_selector = interval_selector
        self.echo_mode_enabled = echo_mode_enabled

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_aux_transmit_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def prot_trans(self):
        return npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @prot_trans.setter
    def prot_trans(self, value):
        self._set_field_value('field prot_trans', 8, 32, npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t, value)
    @property
    def interval_selector(self):
        return self._get_field_value(1, 3)
    @interval_selector.setter
    def interval_selector(self, value):
        self._set_field_value('field interval_selector', 1, 3, int, value)
    @property
    def echo_mode_enabled(self):
        return self._get_field_value(0, 1)
    @echo_mode_enabled.setter
    def echo_mode_enabled(self, value):
        self._set_field_value('field echo_mode_enabled', 0, 1, int, value)



class npl_bfd_flags_state_t_anonymous_union_bfd_flags_t(basic_npl_struct):
    def __init__(self):
        super().__init__(6)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_flags_state_t_anonymous_union_bfd_flags_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def indiv_flags(self):
        return npl_bfd_flags_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @indiv_flags.setter
    def indiv_flags(self, value):
        self._set_field_value('field indiv_flags', 0, 6, npl_bfd_flags_t, value)
    @property
    def flags(self):
        return self._get_field_value(0, 6)
    @flags.setter
    def flags(self, value):
        self._set_field_value('field flags', 0, 6, int, value)



class npl_bfd_mp_table_extra_payload_t(basic_npl_struct):
    def __init__(self, mpls_label=0, extra_tx_b=0):
        super().__init__(48)
        self.mpls_label = mpls_label
        self.extra_tx_b = extra_tx_b

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_mp_table_extra_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mpls_label(self):
        return npl_mpls_header_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @mpls_label.setter
    def mpls_label(self, value):
        self._set_field_value('field mpls_label', 16, 32, npl_mpls_header_t, value)
    @property
    def extra_tx_b(self):
        return npl_bfd_mp_table_transmit_b_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @extra_tx_b.setter
    def extra_tx_b(self, value):
        self._set_field_value('field extra_tx_b', 0, 16, npl_bfd_mp_table_transmit_b_payload_t, value)



class npl_bfd_mp_table_shared_msb_t(basic_npl_struct):
    def __init__(self, trans_data=0, transport_label=0):
        super().__init__(60)
        self.trans_data = trans_data
        self.transport_label = transport_label

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_mp_table_shared_msb_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def trans_data(self):
        return npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t._get_as_sub_field(self._data, self._offset_in_data + 3)
    @trans_data.setter
    def trans_data(self, value):
        self._set_field_value('field trans_data', 3, 57, npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t, value)
    @property
    def transport_label(self):
        return npl_bfd_transport_and_label_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @transport_label.setter
    def transport_label(self, value):
        self._set_field_value('field transport_label', 0, 3, npl_bfd_transport_and_label_t, value)



class npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t(basic_npl_struct):
    def __init__(self):
        super().__init__(3)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def offset(self):
        return npl_common_cntr_offset_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @offset.setter
    def offset(self, value):
        self._set_field_value('field offset', 0, 3, npl_common_cntr_offset_t, value)



class npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t(basic_npl_struct):
    def __init__(self):
        super().__init__(3)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def offset(self):
        return npl_common_cntr_offset_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @offset.setter
    def offset(self, value):
        self._set_field_value('field offset', 0, 3, npl_common_cntr_offset_t, value)



class npl_demux_pif_ifg_t(basic_npl_struct):
    def __init__(self, pad=0, pif_ifg=0):
        super().__init__(7)
        self.pad = pad
        self.pif_ifg = pif_ifg

    def _get_as_sub_field(data, offset_in_data):
        result = npl_demux_pif_ifg_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def pad(self):
        return self._get_field_value(6, 1)
    @pad.setter
    def pad(self, value):
        self._set_field_value('field pad', 6, 1, int, value)
    @property
    def pif_ifg(self):
        return npl_pif_ifg_base_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @pif_ifg.setter
    def pif_ifg(self, value):
        self._set_field_value('field pif_ifg', 0, 6, npl_pif_ifg_base_t, value)



class npl_dlp_profile_t(basic_npl_struct):
    def __init__(self):
        super().__init__(8)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_dlp_profile_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2(self):
        return npl_qos_and_acl_ids_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2.setter
    def l2(self, value):
        self._set_field_value('field l2', 0, 8, npl_qos_and_acl_ids_t, value)
    @property
    def l3_sec(self):
        return npl_sec_acl_ids_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_sec.setter
    def l3_sec(self, value):
        self._set_field_value('field l3_sec', 0, 8, npl_sec_acl_ids_t, value)



class npl_drop_color_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(16)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_drop_color_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def drop_color(self):
        return basic_npl_array(16, 16, npl_quan_1b, self._data, self._offset_in_data + 0)
    @drop_color.setter
    def drop_color(self, value):
        field = basic_npl_array(16, 16, npl_quan_1b, self._data, self._offset_in_data + 0)
        field._set_field_value('field drop_color', 0, 16, basic_npl_array, value)



class npl_dsp_attr_common_t(basic_npl_struct):
    def __init__(self, dsp_is_dma=0, dsp_map_info=0, mask_egress_vlan_edit=0, dsp=0):
        super().__init__(20)
        self.dsp_is_dma = dsp_is_dma
        self.dsp_map_info = dsp_map_info
        self.mask_egress_vlan_edit = mask_egress_vlan_edit
        self.dsp = dsp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_dsp_attr_common_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def dsp_is_dma(self):
        return self._get_field_value(19, 1)
    @dsp_is_dma.setter
    def dsp_is_dma(self, value):
        self._set_field_value('field dsp_is_dma', 19, 1, int, value)
    @property
    def dsp_map_info(self):
        return npl_dsp_map_info_t._get_as_sub_field(self._data, self._offset_in_data + 17)
    @dsp_map_info.setter
    def dsp_map_info(self, value):
        self._set_field_value('field dsp_map_info', 17, 2, npl_dsp_map_info_t, value)
    @property
    def mask_egress_vlan_edit(self):
        return self._get_field_value(16, 1)
    @mask_egress_vlan_edit.setter
    def mask_egress_vlan_edit(self, value):
        self._set_field_value('field mask_egress_vlan_edit', 16, 1, int, value)
    @property
    def dsp(self):
        return self._get_field_value(0, 16)
    @dsp.setter
    def dsp(self, value):
        self._set_field_value('field dsp', 0, 16, int, value)



class npl_dsp_l2_attributes_t(basic_npl_struct):
    def __init__(self, mc_pruning_low=0, mc_pruning_high=0, dsp_attr_common=0):
        super().__init__(52)
        self.mc_pruning_low = mc_pruning_low
        self.mc_pruning_high = mc_pruning_high
        self.dsp_attr_common = dsp_attr_common

    def _get_as_sub_field(data, offset_in_data):
        result = npl_dsp_l2_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mc_pruning_low(self):
        return self._get_field_value(36, 16)
    @mc_pruning_low.setter
    def mc_pruning_low(self, value):
        self._set_field_value('field mc_pruning_low', 36, 16, int, value)
    @property
    def mc_pruning_high(self):
        return self._get_field_value(20, 16)
    @mc_pruning_high.setter
    def mc_pruning_high(self, value):
        self._set_field_value('field mc_pruning_high', 20, 16, int, value)
    @property
    def dsp_attr_common(self):
        return npl_dsp_attr_common_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dsp_attr_common.setter
    def dsp_attr_common(self, value):
        self._set_field_value('field dsp_attr_common', 0, 20, npl_dsp_attr_common_t, value)



class npl_dsp_l3_attributes_t(basic_npl_struct):
    def __init__(self, mtu=0, no_decrement_ttl=0, mpls_ip_ttl_propagation=0, dsp_attr_common=0):
        super().__init__(38)
        self.mtu = mtu
        self.no_decrement_ttl = no_decrement_ttl
        self.mpls_ip_ttl_propagation = mpls_ip_ttl_propagation
        self.dsp_attr_common = dsp_attr_common

    def _get_as_sub_field(data, offset_in_data):
        result = npl_dsp_l3_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mtu(self):
        return self._get_field_value(24, 14)
    @mtu.setter
    def mtu(self, value):
        self._set_field_value('field mtu', 24, 14, int, value)
    @property
    def no_decrement_ttl(self):
        return self._get_field_value(21, 1)
    @no_decrement_ttl.setter
    def no_decrement_ttl(self, value):
        self._set_field_value('field no_decrement_ttl', 21, 1, int, value)
    @property
    def mpls_ip_ttl_propagation(self):
        return self._get_field_value(20, 1)
    @mpls_ip_ttl_propagation.setter
    def mpls_ip_ttl_propagation(self, value):
        self._set_field_value('field mpls_ip_ttl_propagation', 20, 1, int, value)
    @property
    def dsp_attr_common(self):
        return npl_dsp_attr_common_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dsp_attr_common.setter
    def dsp_attr_common(self, value):
        self._set_field_value('field dsp_attr_common', 0, 20, npl_dsp_attr_common_t, value)



class npl_egress_sec_acl_result_t(basic_npl_struct):
    def __init__(self, drop_punt_or_permit=0, mirror_valid=0, drop_or_permit=0):
        super().__init__(24)
        self.drop_punt_or_permit = drop_punt_or_permit
        self.mirror_valid = mirror_valid
        self.drop_or_permit = drop_or_permit

    def _get_as_sub_field(data, offset_in_data):
        result = npl_egress_sec_acl_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def drop_punt_or_permit(self):
        return npl_drop_punt_or_permit_t._get_as_sub_field(self._data, self._offset_in_data + 21)
    @drop_punt_or_permit.setter
    def drop_punt_or_permit(self, value):
        self._set_field_value('field drop_punt_or_permit', 21, 3, npl_drop_punt_or_permit_t, value)
    @property
    def mirror_valid(self):
        return self._get_field_value(20, 1)
    @mirror_valid.setter
    def mirror_valid(self, value):
        self._set_field_value('field mirror_valid', 20, 1, int, value)
    @property
    def drop_or_permit(self):
        return npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @drop_or_permit.setter
    def drop_or_permit(self, value):
        self._set_field_value('field drop_or_permit', 0, 20, npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t, value)



class npl_em_payload_t(basic_npl_struct):
    def __init__(self):
        super().__init__(40)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_em_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ethernet_oam(self):
        return npl_ethernet_oam_em_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ethernet_oam.setter
    def ethernet_oam(self, value):
        self._set_field_value('field ethernet_oam', 0, 29, npl_ethernet_oam_em_t, value)
    @property
    def bfd(self):
        return npl_bfd_em_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @bfd.setter
    def bfd(self, value):
        self._set_field_value('field bfd', 0, 40, npl_bfd_em_t, value)
    @property
    def mpls_tp(self):
        return npl_mpls_tp_em_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mpls_tp.setter
    def mpls_tp(self, value):
        self._set_field_value('field mpls_tp', 0, 40, npl_mpls_tp_em_t, value)
    @property
    def pfc(self):
        return npl_pfc_em_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @pfc.setter
    def pfc(self, value):
        self._set_field_value('field pfc', 0, 40, npl_pfc_em_t, value)



class npl_ene_inject_down_payload_t(basic_npl_struct):
    def __init__(self, ene_inject_down_encap_type=0, ene_inject_phb=0, ene_inject_destination=0):
        super().__init__(28)
        self.ene_inject_down_encap_type = ene_inject_down_encap_type
        self.ene_inject_phb = ene_inject_phb
        self.ene_inject_destination = ene_inject_destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ene_inject_down_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ene_inject_down_encap_type(self):
        return self._get_field_value(25, 3)
    @ene_inject_down_encap_type.setter
    def ene_inject_down_encap_type(self, value):
        self._set_field_value('field ene_inject_down_encap_type', 25, 3, int, value)
    @property
    def ene_inject_phb(self):
        return npl_phb_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @ene_inject_phb.setter
    def ene_inject_phb(self, value):
        self._set_field_value('field ene_inject_phb', 20, 5, npl_phb_t, value)
    @property
    def ene_inject_destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ene_inject_destination.setter
    def ene_inject_destination(self, value):
        self._set_field_value('field ene_inject_destination', 0, 20, npl_destination_t, value)



class npl_ene_punt_dsp_and_ssp_t(basic_npl_struct):
    def __init__(self, ssp=0, dsp=0):
        super().__init__(32)
        self.ssp = ssp
        self.dsp = dsp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ene_punt_dsp_and_ssp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ssp(self):
        return npl_punt_ssp_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @ssp.setter
    def ssp(self, value):
        self._set_field_value('field ssp', 16, 16, npl_punt_ssp_t, value)
    @property
    def dsp(self):
        return self._get_field_value(0, 16)
    @dsp.setter
    def dsp(self, value):
        self._set_field_value('field dsp', 0, 16, int, value)



class npl_eth_oam_aux_shared_payload_t(basic_npl_struct):
    def __init__(self, meg_id=0):
        super().__init__(120)
        self.meg_id = meg_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_eth_oam_aux_shared_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def meg_id(self):
        return npl_meg_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @meg_id.setter
    def meg_id(self, value):
        self._set_field_value('field meg_id', 0, 120, npl_meg_id_t, value)



class npl_eth_rtf_iteration_properties_t(basic_npl_struct):
    def __init__(self, f0_rtf_prop=0, stop_on_step_and_next_stage_compressed_fields=0):
        super().__init__(12)
        self.f0_rtf_prop = f0_rtf_prop
        self.stop_on_step_and_next_stage_compressed_fields = stop_on_step_and_next_stage_compressed_fields

    def _get_as_sub_field(data, offset_in_data):
        result = npl_eth_rtf_iteration_properties_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def f0_rtf_prop(self):
        return npl_eth_rtf_prop_over_fwd0_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @f0_rtf_prop.setter
    def f0_rtf_prop(self, value):
        self._set_field_value('field f0_rtf_prop', 4, 8, npl_eth_rtf_prop_over_fwd0_t, value)
    @property
    def stop_on_step_and_next_stage_compressed_fields(self):
        return npl_stop_on_step_and_next_stage_compressed_fields_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @stop_on_step_and_next_stage_compressed_fields.setter
    def stop_on_step_and_next_stage_compressed_fields(self, value):
        self._set_field_value('field stop_on_step_and_next_stage_compressed_fields', 0, 4, npl_stop_on_step_and_next_stage_compressed_fields_t, value)



class npl_ethernet_mac_t(basic_npl_struct):
    def __init__(self, da=0, sa=0):
        super().__init__(96)
        self.da = da
        self.sa = sa

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ethernet_mac_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def da(self):
        return npl_mac_addr_t._get_as_sub_field(self._data, self._offset_in_data + 48)
    @da.setter
    def da(self, value):
        self._set_field_value('field da', 48, 48, npl_mac_addr_t, value)
    @property
    def sa(self):
        return npl_mac_addr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @sa.setter
    def sa(self, value):
        self._set_field_value('field sa', 0, 48, npl_mac_addr_t, value)



class npl_force_pipe_ttl_ingress_ptp_info_t(basic_npl_struct):
    def __init__(self, ingress_ptp_info=0, force_pipe_ttl=0):
        super().__init__(4)
        self.ingress_ptp_info = ingress_ptp_info
        self.force_pipe_ttl = force_pipe_ttl

    def _get_as_sub_field(data, offset_in_data):
        result = npl_force_pipe_ttl_ingress_ptp_info_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ingress_ptp_info(self):
        return npl_ingress_ptp_info_t._get_as_sub_field(self._data, self._offset_in_data + 1)
    @ingress_ptp_info.setter
    def ingress_ptp_info(self, value):
        self._set_field_value('field ingress_ptp_info', 1, 3, npl_ingress_ptp_info_t, value)
    @property
    def force_pipe_ttl(self):
        return self._get_field_value(0, 1)
    @force_pipe_ttl.setter
    def force_pipe_ttl(self, value):
        self._set_field_value('field force_pipe_ttl', 0, 1, int, value)



class npl_gre_tunnel_attributes_t(basic_npl_struct):
    def __init__(self, demux_count=0, dip_entropy=0, tunnel_qos_encap=0, tunnel_control=0, qos_info=0, p_counter=0, tunnel_type_q_counter=0, sip_index=0, dip=0, gre_flags=0, ttl=0):
        super().__init__(120)
        self.demux_count = demux_count
        self.dip_entropy = dip_entropy
        self.tunnel_qos_encap = tunnel_qos_encap
        self.tunnel_control = tunnel_control
        self.qos_info = qos_info
        self.p_counter = p_counter
        self.tunnel_type_q_counter = tunnel_type_q_counter
        self.sip_index = sip_index
        self.dip = dip
        self.gre_flags = gre_flags
        self.ttl = ttl

    def _get_as_sub_field(data, offset_in_data):
        result = npl_gre_tunnel_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def demux_count(self):
        return self._get_field_value(119, 1)
    @demux_count.setter
    def demux_count(self, value):
        self._set_field_value('field demux_count', 119, 1, int, value)
    @property
    def dip_entropy(self):
        return self._get_field_value(117, 2)
    @dip_entropy.setter
    def dip_entropy(self, value):
        self._set_field_value('field dip_entropy', 117, 2, int, value)
    @property
    def tunnel_qos_encap(self):
        return npl_qos_encap_t._get_as_sub_field(self._data, self._offset_in_data + 101)
    @tunnel_qos_encap.setter
    def tunnel_qos_encap(self, value):
        self._set_field_value('field tunnel_qos_encap', 101, 16, npl_qos_encap_t, value)
    @property
    def tunnel_control(self):
        return npl_tunnel_control_t._get_as_sub_field(self._data, self._offset_in_data + 97)
    @tunnel_control.setter
    def tunnel_control(self, value):
        self._set_field_value('field tunnel_control', 97, 4, npl_tunnel_control_t, value)
    @property
    def qos_info(self):
        return npl_qos_info_t._get_as_sub_field(self._data, self._offset_in_data + 92)
    @qos_info.setter
    def qos_info(self, value):
        self._set_field_value('field qos_info', 92, 5, npl_qos_info_t, value)
    @property
    def p_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 72)
    @p_counter.setter
    def p_counter(self, value):
        self._set_field_value('field p_counter', 72, 20, npl_counter_ptr_t, value)
    @property
    def tunnel_type_q_counter(self):
        return npl_tunnel_type_q_counter_t._get_as_sub_field(self._data, self._offset_in_data + 52)
    @tunnel_type_q_counter.setter
    def tunnel_type_q_counter(self, value):
        self._set_field_value('field tunnel_type_q_counter', 52, 20, npl_tunnel_type_q_counter_t, value)
    @property
    def sip_index(self):
        return self._get_field_value(48, 4)
    @sip_index.setter
    def sip_index(self, value):
        self._set_field_value('field sip_index', 48, 4, int, value)
    @property
    def dip(self):
        return self._get_field_value(16, 32)
    @dip.setter
    def dip(self, value):
        self._set_field_value('field dip', 16, 32, int, value)
    @property
    def gre_flags(self):
        return self._get_field_value(8, 8)
    @gre_flags.setter
    def gre_flags(self, value):
        self._set_field_value('field gre_flags', 8, 8, int, value)
    @property
    def ttl(self):
        return self._get_field_value(0, 8)
    @ttl.setter
    def ttl(self, value):
        self._set_field_value('field ttl', 0, 8, int, value)



class npl_header_flags_t(basic_npl_struct):
    def __init__(self):
        super().__init__(3)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_header_flags_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def all_header_flags(self):
        return self._get_field_value(0, 3)
    @all_header_flags.setter
    def all_header_flags(self, value):
        self._set_field_value('field all_header_flags', 0, 3, int, value)
    @property
    def ipv4_header_flags(self):
        return npl_ipv4_header_flags_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ipv4_header_flags.setter
    def ipv4_header_flags(self, value):
        self._set_field_value('field ipv4_header_flags', 0, 3, npl_ipv4_header_flags_t, value)
    @property
    def ipv6_header_flags(self):
        return npl_ipv6_header_flags_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ipv6_header_flags.setter
    def ipv6_header_flags(self, value):
        self._set_field_value('field ipv6_header_flags', 0, 3, npl_ipv6_header_flags_t, value)
    @property
    def vlan_header_flags(self):
        return npl_vlan_header_flags_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @vlan_header_flags.setter
    def vlan_header_flags(self, value):
        self._set_field_value('field vlan_header_flags', 0, 3, npl_vlan_header_flags_t, value)
    @property
    def ethernet_header_flags(self):
        return npl_ethernet_header_flags_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ethernet_header_flags.setter
    def ethernet_header_flags(self, value):
        self._set_field_value('field ethernet_header_flags', 0, 3, npl_ethernet_header_flags_t, value)
    @property
    def mpls_header_flags(self):
        return npl_mpls_header_flags_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mpls_header_flags.setter
    def mpls_header_flags(self, value):
        self._set_field_value('field mpls_header_flags', 0, 3, npl_mpls_header_flags_t, value)



class npl_header_format_t(basic_npl_struct):
    def __init__(self, flags=0, type=0):
        super().__init__(8)
        self.flags = flags
        self.type = type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_header_format_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def flags(self):
        return npl_header_flags_t._get_as_sub_field(self._data, self._offset_in_data + 5)
    @flags.setter
    def flags(self, value):
        self._set_field_value('field flags', 5, 3, npl_header_flags_t, value)
    @property
    def type(self):
        return self._get_field_value(0, 5)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 0, 5, int, value)



class npl_hmc_cgm_profile_global_results_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(284)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_hmc_cgm_profile_global_results_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def wred_ema_weight(self):
        return self._get_field_value(280, 4)
    @wred_ema_weight.setter
    def wred_ema_weight(self, value):
        self._set_field_value('field wred_ema_weight', 280, 4, int, value)
    @property
    def wred_fcn_probability_region(self):
        return basic_npl_array(104, 8, npl_quan_13b, self._data, self._offset_in_data + 176)
    @wred_fcn_probability_region.setter
    def wred_fcn_probability_region(self, value):
        field = basic_npl_array(104, 8, npl_quan_13b, self._data, self._offset_in_data + 176)
        field._set_field_value('field wred_fcn_probability_region', 0, 104, basic_npl_array, value)
    @property
    def wred_region_borders(self):
        return basic_npl_array(133, 7, npl_quan_19b, self._data, self._offset_in_data + 43)
    @wred_region_borders.setter
    def wred_region_borders(self, value):
        field = basic_npl_array(133, 7, npl_quan_19b, self._data, self._offset_in_data + 43)
        field._set_field_value('field wred_region_borders', 0, 133, basic_npl_array, value)
    @property
    def wred_fcn_enable(self):
        return self._get_field_value(42, 1)
    @wred_fcn_enable.setter
    def wred_fcn_enable(self, value):
        self._set_field_value('field wred_fcn_enable', 42, 1, int, value)
    @property
    def alpha_dpo1(self):
        return npl_quan_5b._get_as_sub_field(self._data, self._offset_in_data + 37)
    @alpha_dpo1.setter
    def alpha_dpo1(self, value):
        self._set_field_value('field alpha_dpo1', 37, 5, npl_quan_5b, value)
    @property
    def shared_resource_threshold_dp1(self):
        return npl_quan_15b._get_as_sub_field(self._data, self._offset_in_data + 22)
    @shared_resource_threshold_dp1.setter
    def shared_resource_threshold_dp1(self, value):
        self._set_field_value('field shared_resource_threshold_dp1', 22, 15, npl_quan_15b, value)
    @property
    def alpha_dpo0(self):
        return npl_quan_5b._get_as_sub_field(self._data, self._offset_in_data + 17)
    @alpha_dpo0.setter
    def alpha_dpo0(self, value):
        self._set_field_value('field alpha_dpo0', 17, 5, npl_quan_5b, value)
    @property
    def shared_resource_threshold_dp0(self):
        return npl_quan_15b._get_as_sub_field(self._data, self._offset_in_data + 2)
    @shared_resource_threshold_dp0.setter
    def shared_resource_threshold_dp0(self, value):
        self._set_field_value('field shared_resource_threshold_dp0', 2, 15, npl_quan_15b, value)
    @property
    def shared_resource_threshold_mode(self):
        return self._get_field_value(1, 1)
    @shared_resource_threshold_mode.setter
    def shared_resource_threshold_mode(self, value):
        self._set_field_value('field shared_resource_threshold_mode', 1, 1, int, value)
    @property
    def shared_pool_id(self):
        return self._get_field_value(0, 1)
    @shared_pool_id.setter
    def shared_pool_id(self, value):
        self._set_field_value('field shared_pool_id', 0, 1, int, value)



class npl_ibm_cmd_table_result_t(basic_npl_struct):
    def __init__(self, sampling_probability=0, is_mc=0, ignore_in_rxrq_sel=0, mirror_to_dest=0, tc_map_profile=0, destination_device=0, voq_or_bitmap=0):
        super().__init__(49)
        self.sampling_probability = sampling_probability
        self.is_mc = is_mc
        self.ignore_in_rxrq_sel = ignore_in_rxrq_sel
        self.mirror_to_dest = mirror_to_dest
        self.tc_map_profile = tc_map_profile
        self.destination_device = destination_device
        self.voq_or_bitmap = voq_or_bitmap

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ibm_cmd_table_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sampling_probability(self):
        return self._get_field_value(31, 18)
    @sampling_probability.setter
    def sampling_probability(self, value):
        self._set_field_value('field sampling_probability', 31, 18, int, value)
    @property
    def is_mc(self):
        return self._get_field_value(30, 1)
    @is_mc.setter
    def is_mc(self, value):
        self._set_field_value('field is_mc', 30, 1, int, value)
    @property
    def ignore_in_rxrq_sel(self):
        return self._get_field_value(29, 1)
    @ignore_in_rxrq_sel.setter
    def ignore_in_rxrq_sel(self, value):
        self._set_field_value('field ignore_in_rxrq_sel', 29, 1, int, value)
    @property
    def mirror_to_dest(self):
        return self._get_field_value(28, 1)
    @mirror_to_dest.setter
    def mirror_to_dest(self, value):
        self._set_field_value('field mirror_to_dest', 28, 1, int, value)
    @property
    def tc_map_profile(self):
        return self._get_field_value(25, 3)
    @tc_map_profile.setter
    def tc_map_profile(self, value):
        self._set_field_value('field tc_map_profile', 25, 3, int, value)
    @property
    def destination_device(self):
        return self._get_field_value(16, 9)
    @destination_device.setter
    def destination_device(self, value):
        self._set_field_value('field destination_device', 16, 9, int, value)
    @property
    def voq_or_bitmap(self):
        return npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @voq_or_bitmap.setter
    def voq_or_bitmap(self, value):
        self._set_field_value('field voq_or_bitmap', 0, 16, npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t, value)



class npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t(basic_npl_struct):
    def __init__(self, is_slp_dm=0, ingress_ptp_info=0):
        super().__init__(4)
        self.is_slp_dm = is_slp_dm
        self.ingress_ptp_info = ingress_ptp_info

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_slp_dm(self):
        return self._get_field_value(3, 1)
    @is_slp_dm.setter
    def is_slp_dm(self, value):
        self._set_field_value('field is_slp_dm', 3, 1, int, value)
    @property
    def ingress_ptp_info(self):
        return npl_ingress_ptp_info_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ingress_ptp_info.setter
    def ingress_ptp_info(self, value):
        self._set_field_value('field ingress_ptp_info', 0, 3, npl_ingress_ptp_info_t, value)



class npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def initial_lp_id(self):
        return npl_lp_id_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @initial_lp_id.setter
    def initial_lp_id(self, value):
        self._set_field_value('field initial_lp_id', 4, 16, npl_lp_id_t, value)
    @property
    def mpls_label_placeholder(self):
        return self._get_field_value(0, 20)
    @mpls_label_placeholder.setter
    def mpls_label_placeholder(self, value):
        self._set_field_value('field mpls_label_placeholder', 0, 20, int, value)



class npl_initial_recycle_pd_nw_rx_data_t(basic_npl_struct):
    def __init__(self, init_data=0, initial_mapping_type=0, initial_is_rcy_if=0, initial_mac_lp_type=0):
        super().__init__(16)
        self.init_data = init_data
        self.initial_mapping_type = initial_mapping_type
        self.initial_is_rcy_if = initial_is_rcy_if
        self.initial_mac_lp_type = initial_mac_lp_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_initial_recycle_pd_nw_rx_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def init_data(self):
        return npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @init_data.setter
    def init_data(self, value):
        self._set_field_value('field init_data', 8, 8, npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t, value)
    @property
    def initial_mapping_type(self):
        return self._get_field_value(4, 4)
    @initial_mapping_type.setter
    def initial_mapping_type(self, value):
        self._set_field_value('field initial_mapping_type', 4, 4, int, value)
    @property
    def initial_is_rcy_if(self):
        return self._get_field_value(2, 1)
    @initial_is_rcy_if.setter
    def initial_is_rcy_if(self, value):
        self._set_field_value('field initial_is_rcy_if', 2, 1, int, value)
    @property
    def initial_mac_lp_type(self):
        return self._get_field_value(0, 1)
    @initial_mac_lp_type.setter
    def initial_mac_lp_type(self, value):
        self._set_field_value('field initial_mac_lp_type', 0, 1, int, value)



class npl_inject_down_header_t(basic_npl_struct):
    def __init__(self, inject_down_encap_type=0, inject_phb=0, inject_destination=0):
        super().__init__(28)
        self.inject_down_encap_type = inject_down_encap_type
        self.inject_phb = inject_phb
        self.inject_destination = inject_destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_down_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inject_down_encap_type(self):
        return self._get_field_value(25, 3)
    @inject_down_encap_type.setter
    def inject_down_encap_type(self, value):
        self._set_field_value('field inject_down_encap_type', 25, 3, int, value)
    @property
    def inject_phb(self):
        return npl_phb_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @inject_phb.setter
    def inject_phb(self, value):
        self._set_field_value('field inject_phb', 20, 5, npl_phb_t, value)
    @property
    def inject_destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @inject_destination.setter
    def inject_destination(self, value):
        self._set_field_value('field inject_destination', 0, 20, npl_destination_t, value)



class npl_inject_ts_and_lm_cmd_t(basic_npl_struct):
    def __init__(self, time_stamp_cmd=0, counter_stamp_cmd=0):
        super().__init__(24)
        self.time_stamp_cmd = time_stamp_cmd
        self.counter_stamp_cmd = counter_stamp_cmd

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_ts_and_lm_cmd_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def time_stamp_cmd(self):
        return npl_ts_command_t._get_as_sub_field(self._data, self._offset_in_data + 12)
    @time_stamp_cmd.setter
    def time_stamp_cmd(self, value):
        self._set_field_value('field time_stamp_cmd', 12, 12, npl_ts_command_t, value)
    @property
    def counter_stamp_cmd(self):
        return npl_lm_command_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @counter_stamp_cmd.setter
    def counter_stamp_cmd(self, value):
        self._set_field_value('field counter_stamp_cmd', 0, 12, npl_lm_command_t, value)



class npl_inject_up_eth_qos_t(basic_npl_struct):
    def __init__(self, inject_up_hdr_phb_src=0, inject_up_phb=0, inject_up_qos_group=0, inject_up_fwd_qos_tag=0):
        super().__init__(24)
        self.inject_up_hdr_phb_src = inject_up_hdr_phb_src
        self.inject_up_phb = inject_up_phb
        self.inject_up_qos_group = inject_up_qos_group
        self.inject_up_fwd_qos_tag = inject_up_fwd_qos_tag

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_up_eth_qos_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inject_up_hdr_phb_src(self):
        return self._get_field_value(19, 1)
    @inject_up_hdr_phb_src.setter
    def inject_up_hdr_phb_src(self, value):
        self._set_field_value('field inject_up_hdr_phb_src', 19, 1, int, value)
    @property
    def inject_up_phb(self):
        return npl_phb_t._get_as_sub_field(self._data, self._offset_in_data + 14)
    @inject_up_phb.setter
    def inject_up_phb(self, value):
        self._set_field_value('field inject_up_phb', 14, 5, npl_phb_t, value)
    @property
    def inject_up_qos_group(self):
        return self._get_field_value(7, 7)
    @inject_up_qos_group.setter
    def inject_up_qos_group(self, value):
        self._set_field_value('field inject_up_qos_group', 7, 7, int, value)
    @property
    def inject_up_fwd_qos_tag(self):
        return self._get_field_value(0, 7)
    @inject_up_fwd_qos_tag.setter
    def inject_up_fwd_qos_tag(self, value):
        self._set_field_value('field inject_up_fwd_qos_tag', 0, 7, int, value)



class npl_ip_encap_data_t_anonymous_union_upper_layer_t(basic_npl_struct):
    def __init__(self):
        super().__init__(32)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_encap_data_t_anonymous_union_upper_layer_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def vxlan_data(self):
        return npl_vxlan_encap_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @vxlan_data.setter
    def vxlan_data(self, value):
        self._set_field_value('field vxlan_data', 0, 32, npl_vxlan_encap_data_t, value)
    @property
    def gre_data(self):
        return npl_gre_encap_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @gre_data.setter
    def gre_data(self, value):
        self._set_field_value('field gre_data', 0, 32, npl_gre_encap_data_t, value)
    @property
    def udp_data(self):
        return npl_udp_encap_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @udp_data.setter
    def udp_data(self, value):
        self._set_field_value('field udp_data', 0, 32, npl_udp_encap_data_t, value)



class npl_ip_lpm_result_t(basic_npl_struct):
    def __init__(self, destination_or_default=0, rtype_or_is_fec=0, no_hbm_access=0, is_default_unused=0):
        super().__init__(24)
        self.destination_or_default = destination_or_default
        self.rtype_or_is_fec = rtype_or_is_fec
        self.no_hbm_access = no_hbm_access
        self.is_default_unused = is_default_unused

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_lpm_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination_or_default(self):
        return npl_ip_lpm_result_t_anonymous_union_destination_or_default_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @destination_or_default.setter
    def destination_or_default(self, value):
        self._set_field_value('field destination_or_default', 4, 20, npl_ip_lpm_result_t_anonymous_union_destination_or_default_t, value)
    @property
    def rtype_or_is_fec(self):
        return npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @rtype_or_is_fec.setter
    def rtype_or_is_fec(self, value):
        self._set_field_value('field rtype_or_is_fec', 2, 2, npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t, value)
    @property
    def no_hbm_access(self):
        return self._get_field_value(1, 1)
    @no_hbm_access.setter
    def no_hbm_access(self, value):
        self._set_field_value('field no_hbm_access', 1, 1, int, value)
    @property
    def is_default_unused(self):
        return self._get_field_value(0, 1)
    @is_default_unused.setter
    def is_default_unused(self, value):
        self._set_field_value('field is_default_unused', 0, 1, int, value)



class npl_ip_muxed_fields_t(basic_npl_struct):
    def __init__(self, muxed_soft_lb_wa_enable=0, muxed_is_bfd_and_udp=0, muxed_is_bfd=0, muxed_is_hop_by_hop=0, muxed_is_udp=0):
        super().__init__(6)
        self.muxed_soft_lb_wa_enable = muxed_soft_lb_wa_enable
        self.muxed_is_bfd_and_udp = muxed_is_bfd_and_udp
        self.muxed_is_bfd = muxed_is_bfd
        self.muxed_is_hop_by_hop = muxed_is_hop_by_hop
        self.muxed_is_udp = muxed_is_udp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_muxed_fields_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def muxed_soft_lb_wa_enable(self):
        return npl_soft_lb_wa_enable_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @muxed_soft_lb_wa_enable.setter
    def muxed_soft_lb_wa_enable(self, value):
        self._set_field_value('field muxed_soft_lb_wa_enable', 4, 2, npl_soft_lb_wa_enable_t, value)
    @property
    def muxed_is_bfd_and_udp(self):
        return self._get_field_value(3, 1)
    @muxed_is_bfd_and_udp.setter
    def muxed_is_bfd_and_udp(self, value):
        self._set_field_value('field muxed_is_bfd_and_udp', 3, 1, int, value)
    @property
    def muxed_is_bfd(self):
        return self._get_field_value(2, 1)
    @muxed_is_bfd.setter
    def muxed_is_bfd(self, value):
        self._set_field_value('field muxed_is_bfd', 2, 1, int, value)
    @property
    def muxed_is_hop_by_hop(self):
        return self._get_field_value(1, 1)
    @muxed_is_hop_by_hop.setter
    def muxed_is_hop_by_hop(self, value):
        self._set_field_value('field muxed_is_hop_by_hop', 1, 1, int, value)
    @property
    def muxed_is_udp(self):
        return self._get_field_value(0, 1)
    @muxed_is_udp.setter
    def muxed_is_udp(self, value):
        self._set_field_value('field muxed_is_udp', 0, 1, int, value)



class npl_ip_rtf_iteration_properties_t(basic_npl_struct):
    def __init__(self, f0_rtf_prop=0, f1_rtf_prop=0, stop_on_step_and_next_stage_compressed_fields=0, use_fwd1_interface=0):
        super().__init__(24)
        self.f0_rtf_prop = f0_rtf_prop
        self.f1_rtf_prop = f1_rtf_prop
        self.stop_on_step_and_next_stage_compressed_fields = stop_on_step_and_next_stage_compressed_fields
        self.use_fwd1_interface = use_fwd1_interface

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_rtf_iteration_properties_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def f0_rtf_prop(self):
        return npl_rtf_iter_prop_over_fwd0_t._get_as_sub_field(self._data, self._offset_in_data + 14)
    @f0_rtf_prop.setter
    def f0_rtf_prop(self, value):
        self._set_field_value('field f0_rtf_prop', 14, 10, npl_rtf_iter_prop_over_fwd0_t, value)
    @property
    def f1_rtf_prop(self):
        return npl_rtf_iter_prop_over_fwd1_t._get_as_sub_field(self._data, self._offset_in_data + 5)
    @f1_rtf_prop.setter
    def f1_rtf_prop(self, value):
        self._set_field_value('field f1_rtf_prop', 5, 9, npl_rtf_iter_prop_over_fwd1_t, value)
    @property
    def stop_on_step_and_next_stage_compressed_fields(self):
        return npl_stop_on_step_and_next_stage_compressed_fields_t._get_as_sub_field(self._data, self._offset_in_data + 1)
    @stop_on_step_and_next_stage_compressed_fields.setter
    def stop_on_step_and_next_stage_compressed_fields(self, value):
        self._set_field_value('field stop_on_step_and_next_stage_compressed_fields', 1, 4, npl_stop_on_step_and_next_stage_compressed_fields_t, value)
    @property
    def use_fwd1_interface(self):
        return self._get_field_value(0, 1)
    @use_fwd1_interface.setter
    def use_fwd1_interface(self, value):
        self._set_field_value('field use_fwd1_interface', 0, 1, int, value)



class npl_ipv4_encap_data_t(basic_npl_struct):
    def __init__(self, ene_ttl_and_protocol=0, ene_ipv4_sip_dip=0):
        super().__init__(80)
        self.ene_ttl_and_protocol = ene_ttl_and_protocol
        self.ene_ipv4_sip_dip = ene_ipv4_sip_dip

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ipv4_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ene_ttl_and_protocol(self):
        return npl_ttl_and_protocol_t._get_as_sub_field(self._data, self._offset_in_data + 64)
    @ene_ttl_and_protocol.setter
    def ene_ttl_and_protocol(self, value):
        self._set_field_value('field ene_ttl_and_protocol', 64, 16, npl_ttl_and_protocol_t, value)
    @property
    def ene_ipv4_sip_dip(self):
        return npl_ipv4_sip_dip_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ene_ipv4_sip_dip.setter
    def ene_ipv4_sip_dip(self, value):
        self._set_field_value('field ene_ipv4_sip_dip', 0, 64, npl_ipv4_sip_dip_t, value)



class npl_ipv4_ipv6_eth_init_rtf_stages_t(basic_npl_struct):
    def __init__(self, ipv4_ipv6_init_rtf_stage=0, eth_init_rtf_stage=0):
        super().__init__(7)
        self.ipv4_ipv6_init_rtf_stage = ipv4_ipv6_init_rtf_stage
        self.eth_init_rtf_stage = eth_init_rtf_stage

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ipv4_ipv6_eth_init_rtf_stages_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ipv4_ipv6_init_rtf_stage(self):
        return npl_ipv4_ipv6_init_rtf_stage_t._get_as_sub_field(self._data, self._offset_in_data + 3)
    @ipv4_ipv6_init_rtf_stage.setter
    def ipv4_ipv6_init_rtf_stage(self, value):
        self._set_field_value('field ipv4_ipv6_init_rtf_stage', 3, 4, npl_ipv4_ipv6_init_rtf_stage_t, value)
    @property
    def eth_init_rtf_stage(self):
        return self._get_field_value(0, 3)
    @eth_init_rtf_stage.setter
    def eth_init_rtf_stage(self, value):
        self._set_field_value('field eth_init_rtf_stage', 0, 3, int, value)



class npl_ipv6_encap_data_t(basic_npl_struct):
    def __init__(self, ene_nh_and_hl=0, ene_ipv6_sip_msb=0):
        super().__init__(80)
        self.ene_nh_and_hl = ene_nh_and_hl
        self.ene_ipv6_sip_msb = ene_ipv6_sip_msb

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ipv6_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ene_nh_and_hl(self):
        return npl_next_header_and_hop_limit_t._get_as_sub_field(self._data, self._offset_in_data + 64)
    @ene_nh_and_hl.setter
    def ene_nh_and_hl(self, value):
        self._set_field_value('field ene_nh_and_hl', 64, 16, npl_next_header_and_hop_limit_t, value)
    @property
    def ene_ipv6_sip_msb(self):
        return self._get_field_value(0, 64)
    @ene_ipv6_sip_msb.setter
    def ene_ipv6_sip_msb(self, value):
        self._set_field_value('field ene_ipv6_sip_msb', 0, 64, int, value)



class npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t(basic_npl_struct):
    def __init__(self):
        super().__init__(12)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def secondary_type_with_padding(self):
        return npl_vlan_edit_secondary_type_with_padding_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @secondary_type_with_padding.setter
    def secondary_type_with_padding(self, value):
        self._set_field_value('field secondary_type_with_padding', 0, 12, npl_vlan_edit_secondary_type_with_padding_t, value)
    @property
    def vid2(self):
        return self._get_field_value(0, 12)
    @vid2.setter
    def vid2(self, value):
        self._set_field_value('field vid2', 0, 12, int, value)



class npl_l2_ac_encap_t(basic_npl_struct):
    def __init__(self, l2_dlp=0):
        super().__init__(20)
        self.l2_dlp = l2_dlp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_ac_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2_dlp(self):
        return npl_npu_encap_header_l2_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_dlp.setter
    def l2_dlp(self, value):
        self._set_field_value('field l2_dlp', 0, 20, npl_npu_encap_header_l2_dlp_t, value)



class npl_l2_dlp_attr_on_nh_t(basic_npl_struct):
    def __init__(self, nh_ene_macro_code=0, l2_tpid_prof=0, l2_dlp_qos_and_attr=0):
        super().__init__(54)
        self.nh_ene_macro_code = nh_ene_macro_code
        self.l2_tpid_prof = l2_tpid_prof
        self.l2_dlp_qos_and_attr = l2_dlp_qos_and_attr

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_dlp_attr_on_nh_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def nh_ene_macro_code(self):
        return self._get_field_value(52, 2)
    @nh_ene_macro_code.setter
    def nh_ene_macro_code(self, value):
        self._set_field_value('field nh_ene_macro_code', 52, 2, int, value)
    @property
    def l2_tpid_prof(self):
        return self._get_field_value(50, 2)
    @l2_tpid_prof.setter
    def l2_tpid_prof(self, value):
        self._set_field_value('field l2_tpid_prof', 50, 2, int, value)
    @property
    def l2_dlp_qos_and_attr(self):
        return npl_qos_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_dlp_qos_and_attr.setter
    def l2_dlp_qos_and_attr(self, value):
        self._set_field_value('field l2_dlp_qos_and_attr', 0, 46, npl_qos_attributes_t, value)



class npl_l2_lp_with_padding_t(basic_npl_struct):
    def __init__(self, l2_lp=0):
        super().__init__(20)
        self.l2_lp = l2_lp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_lp_with_padding_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2_lp(self):
        return npl_punt_l2_lp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_lp.setter
    def l2_lp(self, value):
        self._set_field_value('field l2_lp', 0, 18, npl_punt_l2_lp_t, value)



class npl_l2_lpts_payload_t(basic_npl_struct):
    def __init__(self, lacp=0, l2cp0=0, l2cp1=0, l2cp2=0, l2cp3=0, l2cp4=0, l2cp5=0, l2cp6=0, l2cp7=0, cisco_protocols=0, isis_over_l2=0, isis_drain=0, isis_over_l3=0, arp=0, ptp_over_eth=0, macsec=0, dhcpv4_server=0, dhcpv4_client=0, dhcpv6_server=0, dhcpv6_client=0, rsvd=0):
        super().__init__(32)
        self.lacp = lacp
        self.l2cp0 = l2cp0
        self.l2cp1 = l2cp1
        self.l2cp2 = l2cp2
        self.l2cp3 = l2cp3
        self.l2cp4 = l2cp4
        self.l2cp5 = l2cp5
        self.l2cp6 = l2cp6
        self.l2cp7 = l2cp7
        self.cisco_protocols = cisco_protocols
        self.isis_over_l2 = isis_over_l2
        self.isis_drain = isis_drain
        self.isis_over_l3 = isis_over_l3
        self.arp = arp
        self.ptp_over_eth = ptp_over_eth
        self.macsec = macsec
        self.dhcpv4_server = dhcpv4_server
        self.dhcpv4_client = dhcpv4_client
        self.dhcpv6_server = dhcpv6_server
        self.dhcpv6_client = dhcpv6_client
        self.rsvd = rsvd

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_lpts_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lacp(self):
        return self._get_field_value(31, 1)
    @lacp.setter
    def lacp(self, value):
        self._set_field_value('field lacp', 31, 1, int, value)
    @property
    def l2cp0(self):
        return self._get_field_value(30, 1)
    @l2cp0.setter
    def l2cp0(self, value):
        self._set_field_value('field l2cp0', 30, 1, int, value)
    @property
    def l2cp1(self):
        return self._get_field_value(29, 1)
    @l2cp1.setter
    def l2cp1(self, value):
        self._set_field_value('field l2cp1', 29, 1, int, value)
    @property
    def l2cp2(self):
        return self._get_field_value(28, 1)
    @l2cp2.setter
    def l2cp2(self, value):
        self._set_field_value('field l2cp2', 28, 1, int, value)
    @property
    def l2cp3(self):
        return self._get_field_value(27, 1)
    @l2cp3.setter
    def l2cp3(self, value):
        self._set_field_value('field l2cp3', 27, 1, int, value)
    @property
    def l2cp4(self):
        return self._get_field_value(26, 1)
    @l2cp4.setter
    def l2cp4(self, value):
        self._set_field_value('field l2cp4', 26, 1, int, value)
    @property
    def l2cp5(self):
        return self._get_field_value(25, 1)
    @l2cp5.setter
    def l2cp5(self, value):
        self._set_field_value('field l2cp5', 25, 1, int, value)
    @property
    def l2cp6(self):
        return self._get_field_value(24, 1)
    @l2cp6.setter
    def l2cp6(self, value):
        self._set_field_value('field l2cp6', 24, 1, int, value)
    @property
    def l2cp7(self):
        return self._get_field_value(23, 1)
    @l2cp7.setter
    def l2cp7(self, value):
        self._set_field_value('field l2cp7', 23, 1, int, value)
    @property
    def cisco_protocols(self):
        return self._get_field_value(22, 1)
    @cisco_protocols.setter
    def cisco_protocols(self, value):
        self._set_field_value('field cisco_protocols', 22, 1, int, value)
    @property
    def isis_over_l2(self):
        return self._get_field_value(21, 1)
    @isis_over_l2.setter
    def isis_over_l2(self, value):
        self._set_field_value('field isis_over_l2', 21, 1, int, value)
    @property
    def isis_drain(self):
        return self._get_field_value(20, 1)
    @isis_drain.setter
    def isis_drain(self, value):
        self._set_field_value('field isis_drain', 20, 1, int, value)
    @property
    def isis_over_l3(self):
        return self._get_field_value(19, 1)
    @isis_over_l3.setter
    def isis_over_l3(self, value):
        self._set_field_value('field isis_over_l3', 19, 1, int, value)
    @property
    def arp(self):
        return self._get_field_value(18, 1)
    @arp.setter
    def arp(self, value):
        self._set_field_value('field arp', 18, 1, int, value)
    @property
    def ptp_over_eth(self):
        return self._get_field_value(17, 1)
    @ptp_over_eth.setter
    def ptp_over_eth(self, value):
        self._set_field_value('field ptp_over_eth', 17, 1, int, value)
    @property
    def macsec(self):
        return self._get_field_value(16, 1)
    @macsec.setter
    def macsec(self, value):
        self._set_field_value('field macsec', 16, 1, int, value)
    @property
    def dhcpv4_server(self):
        return self._get_field_value(15, 1)
    @dhcpv4_server.setter
    def dhcpv4_server(self, value):
        self._set_field_value('field dhcpv4_server', 15, 1, int, value)
    @property
    def dhcpv4_client(self):
        return self._get_field_value(14, 1)
    @dhcpv4_client.setter
    def dhcpv4_client(self, value):
        self._set_field_value('field dhcpv4_client', 14, 1, int, value)
    @property
    def dhcpv6_server(self):
        return self._get_field_value(13, 1)
    @dhcpv6_server.setter
    def dhcpv6_server(self, value):
        self._set_field_value('field dhcpv6_server', 13, 1, int, value)
    @property
    def dhcpv6_client(self):
        return self._get_field_value(12, 1)
    @dhcpv6_client.setter
    def dhcpv6_client(self, value):
        self._set_field_value('field dhcpv6_client', 12, 1, int, value)
    @property
    def rsvd(self):
        return npl_l2_lpts_traps_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @rsvd.setter
    def rsvd(self, value):
        self._set_field_value('field rsvd', 0, 12, npl_l2_lpts_traps_t, value)



class npl_l2_rtf_conf_set_and_init_stages_t(basic_npl_struct):
    def __init__(self, rtf_conf_set_and_stages=0, eth_rtf_stage=0):
        super().__init__(15)
        self.rtf_conf_set_and_stages = rtf_conf_set_and_stages
        self.eth_rtf_stage = eth_rtf_stage

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_rtf_conf_set_and_init_stages_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rtf_conf_set_and_stages(self):
        return npl_rtf_conf_set_and_stages_t._get_as_sub_field(self._data, self._offset_in_data + 3)
    @rtf_conf_set_and_stages.setter
    def rtf_conf_set_and_stages(self, value):
        self._set_field_value('field rtf_conf_set_and_stages', 3, 12, npl_rtf_conf_set_and_stages_t, value)
    @property
    def eth_rtf_stage(self):
        return self._get_field_value(0, 3)
    @eth_rtf_stage.setter
    def eth_rtf_stage(self, value):
        self._set_field_value('field eth_rtf_stage', 0, 3, int, value)



class npl_l3_dlp_encap_t(basic_npl_struct):
    def __init__(self, sa_prefix_index=0, vlan_and_sa_lsb_encap=0, vid2_or_flood_rcy_sm_vlans=0):
        super().__init__(72)
        self.sa_prefix_index = sa_prefix_index
        self.vlan_and_sa_lsb_encap = vlan_and_sa_lsb_encap
        self.vid2_or_flood_rcy_sm_vlans = vid2_or_flood_rcy_sm_vlans

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_dlp_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sa_prefix_index(self):
        return self._get_field_value(68, 4)
    @sa_prefix_index.setter
    def sa_prefix_index(self, value):
        self._set_field_value('field sa_prefix_index', 68, 4, int, value)
    @property
    def vlan_and_sa_lsb_encap(self):
        return npl_vlan_and_sa_lsb_encap_t._get_as_sub_field(self._data, self._offset_in_data + 24)
    @vlan_and_sa_lsb_encap.setter
    def vlan_and_sa_lsb_encap(self, value):
        self._set_field_value('field vlan_and_sa_lsb_encap', 24, 44, npl_vlan_and_sa_lsb_encap_t, value)
    @property
    def vid2_or_flood_rcy_sm_vlans(self):
        return npl_vid2_or_flood_rcy_sm_vlans_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @vid2_or_flood_rcy_sm_vlans.setter
    def vid2_or_flood_rcy_sm_vlans(self, value):
        self._set_field_value('field vid2_or_flood_rcy_sm_vlans', 0, 24, npl_vid2_or_flood_rcy_sm_vlans_t, value)



class npl_l3_dlp_msbs_t(basic_npl_struct):
    def __init__(self, l3_dlp_msbs=0):
        super().__init__(2)
        self.l3_dlp_msbs = l3_dlp_msbs

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_dlp_msbs_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_dlp_msbs(self):
        return npl_no_acls_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_dlp_msbs.setter
    def l3_dlp_msbs(self, value):
        self._set_field_value('field l3_dlp_msbs', 0, 2, npl_no_acls_t, value)



class npl_l3_lp_additional_attributes_t(basic_npl_struct):
    def __init__(self, load_balance_profile=0, enable_monitor=0, slp_based_fwd_and_per_vrf_mpls_fwd=0, qos_id=0):
        super().__init__(9)
        self.load_balance_profile = load_balance_profile
        self.enable_monitor = enable_monitor
        self.slp_based_fwd_and_per_vrf_mpls_fwd = slp_based_fwd_and_per_vrf_mpls_fwd
        self.qos_id = qos_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_lp_additional_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def load_balance_profile(self):
        return self._get_field_value(7, 2)
    @load_balance_profile.setter
    def load_balance_profile(self, value):
        self._set_field_value('field load_balance_profile', 7, 2, int, value)
    @property
    def enable_monitor(self):
        return self._get_field_value(6, 1)
    @enable_monitor.setter
    def enable_monitor(self, value):
        self._set_field_value('field enable_monitor', 6, 1, int, value)
    @property
    def slp_based_fwd_and_per_vrf_mpls_fwd(self):
        return npl_slp_based_fwd_and_per_vrf_mpls_fwd_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @slp_based_fwd_and_per_vrf_mpls_fwd.setter
    def slp_based_fwd_and_per_vrf_mpls_fwd(self, value):
        self._set_field_value('field slp_based_fwd_and_per_vrf_mpls_fwd', 4, 2, npl_slp_based_fwd_and_per_vrf_mpls_fwd_t, value)
    @property
    def qos_id(self):
        return self._get_field_value(0, 4)
    @qos_id.setter
    def qos_id(self, value):
        self._set_field_value('field qos_id', 0, 4, int, value)



class npl_l3_sa_lsb_on_nh_t(basic_npl_struct):
    def __init__(self, sa_prefix_index=0, tpid_sa_lsb=0):
        super().__init__(36)
        self.sa_prefix_index = sa_prefix_index
        self.tpid_sa_lsb = tpid_sa_lsb

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_sa_lsb_on_nh_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sa_prefix_index(self):
        return self._get_field_value(32, 4)
    @sa_prefix_index.setter
    def sa_prefix_index(self, value):
        self._set_field_value('field sa_prefix_index', 32, 4, int, value)
    @property
    def tpid_sa_lsb(self):
        return npl_tpid_sa_lsb_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @tpid_sa_lsb.setter
    def tpid_sa_lsb(self, value):
        self._set_field_value('field tpid_sa_lsb', 0, 32, npl_tpid_sa_lsb_t, value)



class npl_l3_slp_msbs_t(basic_npl_struct):
    def __init__(self, l3_slp_msbs=0):
        super().__init__(2)
        self.l3_slp_msbs = l3_slp_msbs

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_slp_msbs_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_slp_msbs(self):
        return npl_no_acls_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_slp_msbs.setter
    def l3_slp_msbs(self, value):
        self._set_field_value('field l3_slp_msbs', 0, 2, npl_no_acls_t, value)



class npl_l3_vxlan_encap_t(basic_npl_struct):
    def __init__(self, tunnel_dlp=0, overlay_nh=0):
        super().__init__(32)
        self.tunnel_dlp = tunnel_dlp
        self.overlay_nh = overlay_nh

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_vxlan_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tunnel_dlp(self):
        return npl_npu_encap_header_l2_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 12)
    @tunnel_dlp.setter
    def tunnel_dlp(self, value):
        self._set_field_value('field tunnel_dlp', 12, 20, npl_npu_encap_header_l2_dlp_t, value)
    @property
    def overlay_nh(self):
        return self._get_field_value(0, 10)
    @overlay_nh.setter
    def overlay_nh(self, value):
        self._set_field_value('field overlay_nh', 0, 10, int, value)



class npl_l3_vxlan_relay_encap_data_t(basic_npl_struct):
    def __init__(self, overlay_nh_data=0, vni=0, vni_counter=0):
        super().__init__(112)
        self.overlay_nh_data = overlay_nh_data
        self.vni = vni
        self.vni_counter = vni_counter

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_vxlan_relay_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def overlay_nh_data(self):
        return npl_overlay_nh_data_t._get_as_sub_field(self._data, self._offset_in_data + 44)
    @overlay_nh_data.setter
    def overlay_nh_data(self, value):
        self._set_field_value('field overlay_nh_data', 44, 68, npl_overlay_nh_data_t, value)
    @property
    def vni(self):
        return self._get_field_value(20, 24)
    @vni.setter
    def vni(self, value):
        self._set_field_value('field vni', 20, 24, int, value)
    @property
    def vni_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @vni_counter.setter
    def vni_counter(self, value):
        self._set_field_value('field vni_counter', 0, 20, npl_counter_ptr_t, value)



class npl_label_or_num_labels_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_label_or_num_labels_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def label(self):
        return self._get_field_value(0, 20)
    @label.setter
    def label(self, value):
        self._set_field_value('field label', 0, 20, int, value)
    @property
    def num_labels(self):
        return npl_num_labels_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @num_labels.setter
    def num_labels(self, value):
        self._set_field_value('field num_labels', 0, 20, npl_num_labels_t, value)



class npl_ldp_over_te_tunnel_data_t(basic_npl_struct):
    def __init__(self, num_labels=0, lsp_labels=0, te_counter=0):
        super().__init__(62)
        self.num_labels = num_labels
        self.lsp_labels = lsp_labels
        self.te_counter = te_counter

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ldp_over_te_tunnel_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def num_labels(self):
        return self._get_field_value(60, 2)
    @num_labels.setter
    def num_labels(self, value):
        self._set_field_value('field num_labels', 60, 2, int, value)
    @property
    def lsp_labels(self):
        return npl_lsp_labels_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @lsp_labels.setter
    def lsp_labels(self, value):
        self._set_field_value('field lsp_labels', 20, 40, npl_lsp_labels_t, value)
    @property
    def te_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @te_counter.setter
    def te_counter(self, value):
        self._set_field_value('field te_counter', 0, 20, npl_counter_ptr_t, value)



class npl_lpts_object_groups_t(basic_npl_struct):
    def __init__(self, src_code=0, dest_code=0):
        super().__init__(32)
        self.src_code = src_code
        self.dest_code = dest_code

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lpts_object_groups_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def src_code(self):
        return npl_og_lpts_compression_code_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @src_code.setter
    def src_code(self, value):
        self._set_field_value('field src_code', 16, 16, npl_og_lpts_compression_code_t, value)
    @property
    def dest_code(self):
        return npl_og_lpts_compression_code_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dest_code.setter
    def dest_code(self, value):
        self._set_field_value('field dest_code', 0, 16, npl_og_lpts_compression_code_t, value)



class npl_lpts_payload_t(basic_npl_struct):
    def __init__(self, phb=0, destination=0):
        super().__init__(25)
        self.phb = phb
        self.destination = destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lpts_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def phb(self):
        return npl_phb_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @phb.setter
    def phb(self, value):
        self._set_field_value('field phb', 20, 5, npl_phb_t, value)
    @property
    def destination(self):
        return self._get_field_value(0, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 20, int, value)



class npl_lsp_destination_t(basic_npl_struct):
    def __init__(self, lsp_type=0, lsp_dest_prefix=0):
        super().__init__(20)
        self.lsp_type = lsp_type
        self.lsp_dest_prefix = lsp_dest_prefix

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lsp_destination_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lsp_type(self):
        return npl_lsp_type_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @lsp_type.setter
    def lsp_type(self, value):
        self._set_field_value('field lsp_type', 16, 4, npl_lsp_type_t, value)
    @property
    def lsp_dest_prefix(self):
        return self._get_field_value(0, 16)
    @lsp_dest_prefix.setter
    def lsp_dest_prefix(self, value):
        self._set_field_value('field lsp_dest_prefix', 0, 16, int, value)



class npl_lsp_encap_fields_t(basic_npl_struct):
    def __init__(self, service_flags=0, num_outer_transport_labels=0):
        super().__init__(10)
        self.service_flags = service_flags
        self.num_outer_transport_labels = num_outer_transport_labels

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lsp_encap_fields_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def service_flags(self):
        return npl_service_flags_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @service_flags.setter
    def service_flags(self, value):
        self._set_field_value('field service_flags', 8, 2, npl_service_flags_t, value)
    @property
    def num_outer_transport_labels(self):
        return npl_num_outer_transport_labels_t._get_as_sub_field(self._data, self._offset_in_data + 3)
    @num_outer_transport_labels.setter
    def num_outer_transport_labels(self, value):
        self._set_field_value('field num_outer_transport_labels', 3, 5, npl_num_outer_transport_labels_t, value)



class npl_lsp_labels_opt2_t(basic_npl_struct):
    def __init__(self, label_0=0, labels_1_2=0):
        super().__init__(60)
        self.label_0 = label_0
        self.labels_1_2 = labels_1_2

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lsp_labels_opt2_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def label_0(self):
        return self._get_field_value(40, 20)
    @label_0.setter
    def label_0(self, value):
        self._set_field_value('field label_0', 40, 20, int, value)
    @property
    def labels_1_2(self):
        return npl_lsp_labels_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @labels_1_2.setter
    def labels_1_2(self, value):
        self._set_field_value('field labels_1_2', 0, 40, npl_lsp_labels_t, value)



class npl_lsr_encap_t(basic_npl_struct):
    def __init__(self, lsp=0, backup_te_tunnel=0, mldp_protection=0):
        super().__init__(46)
        self.lsp = lsp
        self.backup_te_tunnel = backup_te_tunnel
        self.mldp_protection = mldp_protection

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lsr_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lsp(self):
        return npl_lsr_encap_t_anonymous_union_lsp_t._get_as_sub_field(self._data, self._offset_in_data + 26)
    @lsp.setter
    def lsp(self, value):
        self._set_field_value('field lsp', 26, 20, npl_lsr_encap_t_anonymous_union_lsp_t, value)
    @property
    def backup_te_tunnel(self):
        return self._get_field_value(10, 16)
    @backup_te_tunnel.setter
    def backup_te_tunnel(self, value):
        self._set_field_value('field backup_te_tunnel', 10, 16, int, value)
    @property
    def mldp_protection(self):
        return npl_mldp_protection_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mldp_protection.setter
    def mldp_protection(self, value):
        self._set_field_value('field mldp_protection', 0, 10, npl_mldp_protection_t, value)



class npl_mac_af_npp_attributes_t(basic_npl_struct):
    def __init__(self, enable_sr_dm_accounting=0, npp_attributes=0, mapping_type=0, port_vlan_tag=0, mac_relay_id=0, enable_vlan_membership=0, enable_vrf_for_l2=0, vlan_membership_index=0, enable_transparent_ptp=0):
        super().__init__(49)
        self.enable_sr_dm_accounting = enable_sr_dm_accounting
        self.npp_attributes = npp_attributes
        self.mapping_type = mapping_type
        self.port_vlan_tag = port_vlan_tag
        self.mac_relay_id = mac_relay_id
        self.enable_vlan_membership = enable_vlan_membership
        self.enable_vrf_for_l2 = enable_vrf_for_l2
        self.vlan_membership_index = vlan_membership_index
        self.enable_transparent_ptp = enable_transparent_ptp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_af_npp_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enable_sr_dm_accounting(self):
        return self._get_field_value(48, 1)
    @enable_sr_dm_accounting.setter
    def enable_sr_dm_accounting(self, value):
        self._set_field_value('field enable_sr_dm_accounting', 48, 1, int, value)
    @property
    def npp_attributes(self):
        return self._get_field_value(40, 8)
    @npp_attributes.setter
    def npp_attributes(self, value):
        self._set_field_value('field npp_attributes', 40, 8, int, value)
    @property
    def mapping_type(self):
        return self._get_field_value(36, 4)
    @mapping_type.setter
    def mapping_type(self, value):
        self._set_field_value('field mapping_type', 36, 4, int, value)
    @property
    def port_vlan_tag(self):
        return npl_vlan_tag_tci_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @port_vlan_tag.setter
    def port_vlan_tag(self, value):
        self._set_field_value('field port_vlan_tag', 20, 16, npl_vlan_tag_tci_t, value)
    @property
    def mac_relay_id(self):
        return self._get_field_value(8, 12)
    @mac_relay_id.setter
    def mac_relay_id(self, value):
        self._set_field_value('field mac_relay_id', 8, 12, int, value)
    @property
    def enable_vlan_membership(self):
        return self._get_field_value(7, 1)
    @enable_vlan_membership.setter
    def enable_vlan_membership(self, value):
        self._set_field_value('field enable_vlan_membership', 7, 1, int, value)
    @property
    def enable_vrf_for_l2(self):
        return self._get_field_value(6, 1)
    @enable_vrf_for_l2.setter
    def enable_vrf_for_l2(self, value):
        self._set_field_value('field enable_vrf_for_l2', 6, 1, int, value)
    @property
    def vlan_membership_index(self):
        return self._get_field_value(1, 5)
    @vlan_membership_index.setter
    def vlan_membership_index(self, value):
        self._set_field_value('field vlan_membership_index', 1, 5, int, value)
    @property
    def enable_transparent_ptp(self):
        return self._get_field_value(0, 1)
    @enable_transparent_ptp.setter
    def enable_transparent_ptp(self, value):
        self._set_field_value('field enable_transparent_ptp', 0, 1, int, value)



class npl_mac_forwarding_key_t(basic_npl_struct):
    def __init__(self, relay_id=0, mac_address=0):
        super().__init__(62)
        self.relay_id = relay_id
        self.mac_address = mac_address

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_forwarding_key_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def relay_id(self):
        return npl_relay_id_t._get_as_sub_field(self._data, self._offset_in_data + 48)
    @relay_id.setter
    def relay_id(self, value):
        self._set_field_value('field relay_id', 48, 14, npl_relay_id_t, value)
    @property
    def mac_address(self):
        return npl_mac_addr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mac_address.setter
    def mac_address(self, value):
        self._set_field_value('field mac_address', 0, 48, npl_mac_addr_t, value)



class npl_mac_lp_attr_t(basic_npl_struct):
    def __init__(self, vlan_profile_and_lp_type=0, local_slp_id=0):
        super().__init__(24)
        self.vlan_profile_and_lp_type = vlan_profile_and_lp_type
        self.local_slp_id = local_slp_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_lp_attr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def vlan_profile_and_lp_type(self):
        return npl_vlan_profile_and_lp_type_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @vlan_profile_and_lp_type.setter
    def vlan_profile_and_lp_type(self, value):
        self._set_field_value('field vlan_profile_and_lp_type', 16, 8, npl_vlan_profile_and_lp_type_t, value)
    @property
    def local_slp_id(self):
        return npl_lp_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @local_slp_id.setter
    def local_slp_id(self, value):
        self._set_field_value('field local_slp_id', 0, 16, npl_lp_id_t, value)



class npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t(basic_npl_struct):
    def __init__(self):
        super().__init__(14)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return self._get_field_value(0, 14)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 14, int, value)
    @property
    def l3_lp_additional_attributes(self):
        return npl_l3_lp_additional_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_lp_additional_attributes.setter
    def l3_lp_additional_attributes(self, value):
        self._set_field_value('field l3_lp_additional_attributes', 0, 9, npl_l3_lp_additional_attributes_t, value)



class npl_mac_relay_attributes_payload_t(basic_npl_struct):
    def __init__(self, l3_lp_additional_attributes=0, mac_l2_relay_attributes=0):
        super().__init__(43)
        self.l3_lp_additional_attributes = l3_lp_additional_attributes
        self.mac_l2_relay_attributes = mac_l2_relay_attributes

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_relay_attributes_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_lp_additional_attributes(self):
        return npl_l3_lp_additional_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 34)
    @l3_lp_additional_attributes.setter
    def l3_lp_additional_attributes(self, value):
        self._set_field_value('field l3_lp_additional_attributes', 34, 9, npl_l3_lp_additional_attributes_t, value)
    @property
    def mac_l2_relay_attributes(self):
        return npl_mac_l2_relay_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mac_l2_relay_attributes.setter
    def mac_l2_relay_attributes(self, value):
        self._set_field_value('field mac_l2_relay_attributes', 0, 34, npl_mac_l2_relay_attributes_t, value)



class npl_mc_em_db_result_rx_single_t(basic_npl_struct):
    def __init__(self, tc_map_profile=0, base_voq_nr=0, mc_copy_id=0):
        super().__init__(36)
        self.tc_map_profile = tc_map_profile
        self.base_voq_nr = base_voq_nr
        self.mc_copy_id = mc_copy_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_em_db_result_rx_single_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tc_map_profile(self):
        return npl_mc_rx_tc_map_profile_t._get_as_sub_field(self._data, self._offset_in_data + 34)
    @tc_map_profile.setter
    def tc_map_profile(self, value):
        self._set_field_value('field tc_map_profile', 34, 2, npl_mc_rx_tc_map_profile_t, value)
    @property
    def base_voq_nr(self):
        return npl_base_voq_nr_t._get_as_sub_field(self._data, self._offset_in_data + 18)
    @base_voq_nr.setter
    def base_voq_nr(self, value):
        self._set_field_value('field base_voq_nr', 18, 16, npl_base_voq_nr_t, value)
    @property
    def mc_copy_id(self):
        return npl_mc_copy_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mc_copy_id.setter
    def mc_copy_id(self, value):
        self._set_field_value('field mc_copy_id', 0, 18, npl_mc_copy_id_t, value)



class npl_mc_em_db_result_rx_t(basic_npl_struct):
    def __init__(self, result_1=0, result_0=0):
        super().__init__(72)
        self.result_1 = result_1
        self.result_0 = result_0

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_em_db_result_rx_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def result_1(self):
        return npl_mc_em_db_result_rx_single_t._get_as_sub_field(self._data, self._offset_in_data + 36)
    @result_1.setter
    def result_1(self, value):
        self._set_field_value('field result_1', 36, 36, npl_mc_em_db_result_rx_single_t, value)
    @property
    def result_0(self):
        return npl_mc_em_db_result_rx_single_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @result_0.setter
    def result_0(self, value):
        self._set_field_value('field result_0', 0, 36, npl_mc_em_db_result_rx_single_t, value)



class npl_mc_em_db_result_tx_format_0_t(basic_npl_struct):
    def __init__(self, tc_map_profile_1=0, tc_map_profile_0=0, oq_group_1=0, oq_group_0=0, mc_copy_id_1=0, mc_copy_id_0=0):
        super().__init__(58)
        self.tc_map_profile_1 = tc_map_profile_1
        self.tc_map_profile_0 = tc_map_profile_0
        self.oq_group_1 = oq_group_1
        self.oq_group_0 = oq_group_0
        self.mc_copy_id_1 = mc_copy_id_1
        self.mc_copy_id_0 = mc_copy_id_0

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_em_db_result_tx_format_0_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tc_map_profile_1(self):
        return npl_mc_tx_tc_map_profile_t._get_as_sub_field(self._data, self._offset_in_data + 55)
    @tc_map_profile_1.setter
    def tc_map_profile_1(self, value):
        self._set_field_value('field tc_map_profile_1', 55, 3, npl_mc_tx_tc_map_profile_t, value)
    @property
    def tc_map_profile_0(self):
        return npl_mc_tx_tc_map_profile_t._get_as_sub_field(self._data, self._offset_in_data + 52)
    @tc_map_profile_0.setter
    def tc_map_profile_0(self, value):
        self._set_field_value('field tc_map_profile_0', 52, 3, npl_mc_tx_tc_map_profile_t, value)
    @property
    def oq_group_1(self):
        return npl_oq_group_t._get_as_sub_field(self._data, self._offset_in_data + 44)
    @oq_group_1.setter
    def oq_group_1(self, value):
        self._set_field_value('field oq_group_1', 44, 8, npl_oq_group_t, value)
    @property
    def oq_group_0(self):
        return npl_oq_group_t._get_as_sub_field(self._data, self._offset_in_data + 36)
    @oq_group_0.setter
    def oq_group_0(self, value):
        self._set_field_value('field oq_group_0', 36, 8, npl_oq_group_t, value)
    @property
    def mc_copy_id_1(self):
        return npl_mc_copy_id_t._get_as_sub_field(self._data, self._offset_in_data + 18)
    @mc_copy_id_1.setter
    def mc_copy_id_1(self, value):
        self._set_field_value('field mc_copy_id_1', 18, 18, npl_mc_copy_id_t, value)
    @property
    def mc_copy_id_0(self):
        return npl_mc_copy_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mc_copy_id_0.setter
    def mc_copy_id_0(self, value):
        self._set_field_value('field mc_copy_id_0', 0, 18, npl_mc_copy_id_t, value)



class npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t(basic_npl_struct):
    def __init__(self):
        super().__init__(71)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def format_0(self):
        return npl_mc_em_db_result_tx_format_0_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @format_0.setter
    def format_0(self, value):
        self._set_field_value('field format_0', 0, 58, npl_mc_em_db_result_tx_format_0_t, value)
    @property
    def format_1(self):
        return npl_mc_em_db_result_tx_format_1_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @format_1.setter
    def format_1(self, value):
        self._set_field_value('field format_1', 0, 71, npl_mc_em_db_result_tx_format_1_t, value)



class npl_mc_slice_bitmap_table_entry_t(basic_npl_struct):
    def __init__(self, counterA_inc_enable=0, group_size_or_bitmap=0):
        super().__init__(12)
        self.counterA_inc_enable = counterA_inc_enable
        self.group_size_or_bitmap = group_size_or_bitmap

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_slice_bitmap_table_entry_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def counterA_inc_enable(self):
        return self._get_field_value(11, 1)
    @counterA_inc_enable.setter
    def counterA_inc_enable(self, value):
        self._set_field_value('field counterA_inc_enable', 11, 1, int, value)
    @property
    def group_size_or_bitmap(self):
        return npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @group_size_or_bitmap.setter
    def group_size_or_bitmap(self, value):
        self._set_field_value('field group_size_or_bitmap', 0, 11, npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t, value)



class npl_mcid_array_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(128)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_mcid_array_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mcid(self):
        return basic_npl_array(128, 8, npl_mcid_t, self._data, self._offset_in_data + 0)
    @mcid.setter
    def mcid(self, value):
        field = basic_npl_array(128, 8, npl_mcid_t, self._data, self._offset_in_data + 0)
        field._set_field_value('field mcid', 0, 128, basic_npl_array, value)



class npl_mcid_array_wrapper_t(basic_npl_struct):
    def __init__(self, payload=0, key=0):
        super().__init__(144)
        self.payload = payload
        self.key = key

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mcid_array_wrapper_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return npl_mcid_array_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 16, 128, npl_mcid_array_t, value)
    @property
    def key(self):
        return self._get_field_value(0, 16)
    @key.setter
    def key(self, value):
        self._set_field_value('field key', 0, 16, int, value)



class npl_mmm_tm_header_t(basic_npl_struct):
    def __init__(self, base=0, multicast_id=0):
        super().__init__(24)
        self.base = base
        self.multicast_id = multicast_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mmm_tm_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def base(self):
        return npl_tm_header_base_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @base.setter
    def base(self, value):
        self._set_field_value('field base', 16, 8, npl_tm_header_base_t, value)
    @property
    def multicast_id(self):
        return self._get_field_value(0, 16)
    @multicast_id.setter
    def multicast_id(self, value):
        self._set_field_value('field multicast_id', 0, 16, int, value)



class npl_more_labels_and_flags_t(basic_npl_struct):
    def __init__(self, more_labels=0, enable_sr_dm_accounting=0, multi_counter_enable=0, service_flags=0, total_num_labels=0):
        super().__init__(20)
        self.more_labels = more_labels
        self.enable_sr_dm_accounting = enable_sr_dm_accounting
        self.multi_counter_enable = multi_counter_enable
        self.service_flags = service_flags
        self.total_num_labels = total_num_labels

    def _get_as_sub_field(data, offset_in_data):
        result = npl_more_labels_and_flags_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def more_labels(self):
        return npl_more_labels_index_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @more_labels.setter
    def more_labels(self, value):
        self._set_field_value('field more_labels', 8, 12, npl_more_labels_index_t, value)
    @property
    def enable_sr_dm_accounting(self):
        return self._get_field_value(7, 1)
    @enable_sr_dm_accounting.setter
    def enable_sr_dm_accounting(self, value):
        self._set_field_value('field enable_sr_dm_accounting', 7, 1, int, value)
    @property
    def multi_counter_enable(self):
        return self._get_field_value(6, 1)
    @multi_counter_enable.setter
    def multi_counter_enable(self, value):
        self._set_field_value('field multi_counter_enable', 6, 1, int, value)
    @property
    def service_flags(self):
        return npl_service_flags_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @service_flags.setter
    def service_flags(self, value):
        self._set_field_value('field service_flags', 4, 2, npl_service_flags_t, value)
    @property
    def total_num_labels(self):
        return self._get_field_value(0, 4)
    @total_num_labels.setter
    def total_num_labels(self, value):
        self._set_field_value('field total_num_labels', 0, 4, int, value)



class npl_mpls_termination_l3vpn_uc_t(basic_npl_struct):
    def __init__(self, allow_ipv4_ipv6_fwd_bits=0):
        super().__init__(16)
        self.allow_ipv4_ipv6_fwd_bits = allow_ipv4_ipv6_fwd_bits

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mpls_termination_l3vpn_uc_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def allow_ipv4_ipv6_fwd_bits(self):
        return npl_override_enable_ipv4_ipv6_uc_bits_t._get_as_sub_field(self._data, self._offset_in_data + 12)
    @allow_ipv4_ipv6_fwd_bits.setter
    def allow_ipv4_ipv6_fwd_bits(self, value):
        self._set_field_value('field allow_ipv4_ipv6_fwd_bits', 12, 2, npl_override_enable_ipv4_ipv6_uc_bits_t, value)



class npl_mpls_termination_pwe_t(basic_npl_struct):
    def __init__(self, is_pwe_raw=0, enable_mpls_tp_oam=0, fat_exists=0, cw_exists=0, bfd_channel=0, l2_relay_id=0, mac_lp_attr=0):
        super().__init__(47)
        self.is_pwe_raw = is_pwe_raw
        self.enable_mpls_tp_oam = enable_mpls_tp_oam
        self.fat_exists = fat_exists
        self.cw_exists = cw_exists
        self.bfd_channel = bfd_channel
        self.l2_relay_id = l2_relay_id
        self.mac_lp_attr = mac_lp_attr

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mpls_termination_pwe_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def is_pwe_raw(self):
        return self._get_field_value(45, 1)
    @is_pwe_raw.setter
    def is_pwe_raw(self, value):
        self._set_field_value('field is_pwe_raw', 45, 1, int, value)
    @property
    def enable_mpls_tp_oam(self):
        return self._get_field_value(44, 1)
    @enable_mpls_tp_oam.setter
    def enable_mpls_tp_oam(self, value):
        self._set_field_value('field enable_mpls_tp_oam', 44, 1, int, value)
    @property
    def fat_exists(self):
        return self._get_field_value(43, 1)
    @fat_exists.setter
    def fat_exists(self, value):
        self._set_field_value('field fat_exists', 43, 1, int, value)
    @property
    def cw_exists(self):
        return self._get_field_value(42, 1)
    @cw_exists.setter
    def cw_exists(self, value):
        self._set_field_value('field cw_exists', 42, 1, int, value)
    @property
    def bfd_channel(self):
        return self._get_field_value(38, 4)
    @bfd_channel.setter
    def bfd_channel(self, value):
        self._set_field_value('field bfd_channel', 38, 4, int, value)
    @property
    def l2_relay_id(self):
        return npl_l2_relay_id_t._get_as_sub_field(self._data, self._offset_in_data + 24)
    @l2_relay_id.setter
    def l2_relay_id(self, value):
        self._set_field_value('field l2_relay_id', 24, 14, npl_l2_relay_id_t, value)
    @property
    def mac_lp_attr(self):
        return npl_mac_lp_attr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mac_lp_attr.setter
    def mac_lp_attr(self, value):
        self._set_field_value('field mac_lp_attr', 0, 24, npl_mac_lp_attr_t, value)



class npl_mum_tm_header_t(basic_npl_struct):
    def __init__(self, base=0, reserved=0, destination_device=0, destination_slice=0, destination_txrq=0, multicast_id=0):
        super().__init__(40)
        self.base = base
        self.reserved = reserved
        self.destination_device = destination_device
        self.destination_slice = destination_slice
        self.destination_txrq = destination_txrq
        self.multicast_id = multicast_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mum_tm_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def base(self):
        return npl_tm_header_base_t._get_as_sub_field(self._data, self._offset_in_data + 32)
    @base.setter
    def base(self, value):
        self._set_field_value('field base', 32, 8, npl_tm_header_base_t, value)
    @property
    def reserved(self):
        return self._get_field_value(29, 3)
    @reserved.setter
    def reserved(self, value):
        self._set_field_value('field reserved', 29, 3, int, value)
    @property
    def destination_device(self):
        return self._get_field_value(20, 9)
    @destination_device.setter
    def destination_device(self, value):
        self._set_field_value('field destination_device', 20, 9, int, value)
    @property
    def destination_slice(self):
        return self._get_field_value(17, 3)
    @destination_slice.setter
    def destination_slice(self, value):
        self._set_field_value('field destination_slice', 17, 3, int, value)
    @property
    def destination_txrq(self):
        return self._get_field_value(16, 1)
    @destination_txrq.setter
    def destination_txrq(self, value):
        self._set_field_value('field destination_txrq', 16, 1, int, value)
    @property
    def multicast_id(self):
        return self._get_field_value(0, 16)
    @multicast_id.setter
    def multicast_id(self, value):
        self._set_field_value('field multicast_id', 0, 16, int, value)



class npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t(basic_npl_struct):
    def __init__(self):
        super().__init__(16)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sip_ip_tunnel_termination_attr(self):
        return npl_sip_ip_tunnel_termination_attr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @sip_ip_tunnel_termination_attr.setter
    def sip_ip_tunnel_termination_attr(self, value):
        self._set_field_value('field sip_ip_tunnel_termination_attr', 0, 16, npl_sip_ip_tunnel_termination_attr_t, value)
    @property
    def tunnel_slp_id(self):
        return npl_lp_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @tunnel_slp_id.setter
    def tunnel_slp_id(self, value):
        self._set_field_value('field tunnel_slp_id', 0, 16, npl_lp_id_t, value)



class npl_native_ce_ptr_table_result_narrow_t(basic_npl_struct):
    def __init__(self):
        super().__init__(24)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_ce_ptr_table_result_narrow_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination1(self):
        return npl_native_l2_lp_destination1_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination1.setter
    def destination1(self, value):
        self._set_field_value('field destination1', 0, 24, npl_native_l2_lp_destination1_t, value)
    @property
    def destination2(self):
        return npl_native_l2_lp_destination2_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination2.setter
    def destination2(self, value):
        self._set_field_value('field destination2', 0, 24, npl_native_l2_lp_destination2_t, value)
    @property
    def stage2_ecmp_vpn_inter_as(self):
        return npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @stage2_ecmp_vpn_inter_as.setter
    def stage2_ecmp_vpn_inter_as(self, value):
        self._set_field_value('field stage2_ecmp_vpn_inter_as', 0, 24, npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t, value)
    @property
    def raw(self):
        return npl_native_l2_lp_narrow_raw_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 24, npl_native_l2_lp_narrow_raw_t, value)



class npl_native_ce_ptr_table_result_wide_t(basic_npl_struct):
    def __init__(self):
        super().__init__(48)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_ce_ptr_table_result_wide_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination_te_tunnel16b(self):
        return npl_native_l2_lp_destination_te_tunnel16b_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination_te_tunnel16b.setter
    def destination_te_tunnel16b(self, value):
        self._set_field_value('field destination_te_tunnel16b', 0, 48, npl_native_l2_lp_destination_te_tunnel16b_t, value)
    @property
    def destination_ip_tunnel(self):
        return npl_native_l2_lp_destination_ip_tunnel_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination_ip_tunnel.setter
    def destination_ip_tunnel(self, value):
        self._set_field_value('field destination_ip_tunnel', 0, 48, npl_native_l2_lp_destination_ip_tunnel_t, value)
    @property
    def destination_ecmp_ce_ptr(self):
        return npl_native_l2_lp_stage2_ecmp_ce_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination_ecmp_ce_ptr.setter
    def destination_ecmp_ce_ptr(self, value):
        self._set_field_value('field destination_ecmp_ce_ptr', 0, 41, npl_native_l2_lp_stage2_ecmp_ce_ptr_t, value)
    @property
    def destination_stage3_nh(self):
        return npl_native_l2_lp_stage3_nh_ce_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination_stage3_nh.setter
    def destination_stage3_nh(self, value):
        self._set_field_value('field destination_stage3_nh', 0, 41, npl_native_l2_lp_stage3_nh_ce_ptr_t, value)
    @property
    def destination_stage2_p_nh(self):
        return npl_native_l2_lp_stage2_p_nh_ce_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination_stage2_p_nh.setter
    def destination_stage2_p_nh(self, value):
        self._set_field_value('field destination_stage2_p_nh', 0, 41, npl_native_l2_lp_stage2_p_nh_ce_ptr_t, value)
    @property
    def raw(self):
        return npl_native_l2_lp_wide_raw_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 48, npl_native_l2_lp_wide_raw_t, value)



class npl_native_frr_table_result_protected_t(basic_npl_struct):
    def __init__(self, type=0, path=0, protection_id=0, primary=0, protecting=0):
        super().__init__(119)
        self.type = type
        self.path = path
        self.protection_id = protection_id
        self.primary = primary
        self.protecting = protecting

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_frr_table_result_protected_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def type(self):
        return self._get_field_value(118, 1)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 118, 1, int, value)
    @property
    def path(self):
        return npl_protection_selector_t._get_as_sub_field(self._data, self._offset_in_data + 117)
    @path.setter
    def path(self, value):
        self._set_field_value('field path', 117, 1, npl_protection_selector_t, value)
    @property
    def protection_id(self):
        return npl_native_protection_id_t._get_as_sub_field(self._data, self._offset_in_data + 104)
    @protection_id.setter
    def protection_id(self, value):
        self._set_field_value('field protection_id', 104, 13, npl_native_protection_id_t, value)
    @property
    def primary(self):
        return npl_native_frr_table_protection_entry_t._get_as_sub_field(self._data, self._offset_in_data + 52)
    @primary.setter
    def primary(self, value):
        self._set_field_value('field primary', 52, 52, npl_native_frr_table_protection_entry_t, value)
    @property
    def protecting(self):
        return npl_native_frr_table_protection_entry_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @protecting.setter
    def protecting(self, value):
        self._set_field_value('field protecting', 0, 52, npl_native_frr_table_protection_entry_t, value)



class npl_native_l2_lp_table_result_protected_t(basic_npl_struct):
    def __init__(self, type=0, path=0, protection_id=0, primary=0, protecting=0):
        super().__init__(97)
        self.type = type
        self.path = path
        self.protection_id = protection_id
        self.primary = primary
        self.protecting = protecting

    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_table_result_protected_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def type(self):
        return self._get_field_value(96, 1)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 96, 1, int, value)
    @property
    def path(self):
        return npl_protection_selector_t._get_as_sub_field(self._data, self._offset_in_data + 95)
    @path.setter
    def path(self, value):
        self._set_field_value('field path', 95, 1, npl_protection_selector_t, value)
    @property
    def protection_id(self):
        return npl_native_protection_id_t._get_as_sub_field(self._data, self._offset_in_data + 82)
    @protection_id.setter
    def protection_id(self, value):
        self._set_field_value('field protection_id', 82, 13, npl_native_protection_id_t, value)
    @property
    def primary(self):
        return npl_native_l2_lp_table_protection_entry_t._get_as_sub_field(self._data, self._offset_in_data + 41)
    @primary.setter
    def primary(self, value):
        self._set_field_value('field primary', 41, 41, npl_native_l2_lp_table_protection_entry_t, value)
    @property
    def protecting(self):
        return npl_native_l2_lp_table_protection_entry_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @protecting.setter
    def protecting(self, value):
        self._set_field_value('field protecting', 0, 41, npl_native_l2_lp_table_protection_entry_t, value)



class npl_native_l2_lp_table_result_wide_t(basic_npl_struct):
    def __init__(self):
        super().__init__(48)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_native_l2_lp_table_result_wide_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination(self):
        return npl_native_l2_lp_destination_t._get_as_sub_field(self._data, self._offset_in_data + 24)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 24, 24, npl_native_l2_lp_destination_t, value)
    @property
    def destination_te_tunnel16b(self):
        return npl_native_l2_lp_destination_te_tunnel16b_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination_te_tunnel16b.setter
    def destination_te_tunnel16b(self, value):
        self._set_field_value('field destination_te_tunnel16b', 0, 48, npl_native_l2_lp_destination_te_tunnel16b_t, value)
    @property
    def destination_overlay_nh(self):
        return npl_native_l2_lp_destination_overlay_nh_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination_overlay_nh.setter
    def destination_overlay_nh(self, value):
        self._set_field_value('field destination_overlay_nh', 0, 48, npl_native_l2_lp_destination_overlay_nh_t, value)
    @property
    def destination_ip_tunnel(self):
        return npl_native_l2_lp_destination_ip_tunnel_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination_ip_tunnel.setter
    def destination_ip_tunnel(self, value):
        self._set_field_value('field destination_ip_tunnel', 0, 48, npl_native_l2_lp_destination_ip_tunnel_t, value)
    @property
    def raw(self):
        return npl_native_l2_lp_wide_raw_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 48, npl_native_l2_lp_wide_raw_t, value)



class npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t(basic_npl_struct):
    def __init__(self):
        super().__init__(54)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2_dlp_attr(self):
        return npl_l2_dlp_attr_on_nh_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_dlp_attr.setter
    def l2_dlp_attr(self, value):
        self._set_field_value('field l2_dlp_attr', 0, 54, npl_l2_dlp_attr_on_nh_t, value)
    @property
    def l3_sa_lsb(self):
        return npl_l3_sa_lsb_on_nh_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_sa_lsb.setter
    def l3_sa_lsb(self, value):
        self._set_field_value('field l3_sa_lsb', 0, 36, npl_l3_sa_lsb_on_nh_t, value)



class npl_npu_dsp_pif_ifg_t(basic_npl_struct):
    def __init__(self, padded_pif_ifg=0, use_npu_header_pif_ifg=0):
        super().__init__(8)
        self.padded_pif_ifg = padded_pif_ifg
        self.use_npu_header_pif_ifg = use_npu_header_pif_ifg

    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_dsp_pif_ifg_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def padded_pif_ifg(self):
        return npl_demux_pif_ifg_t._get_as_sub_field(self._data, self._offset_in_data + 1)
    @padded_pif_ifg.setter
    def padded_pif_ifg(self, value):
        self._set_field_value('field padded_pif_ifg', 1, 7, npl_demux_pif_ifg_t, value)
    @property
    def use_npu_header_pif_ifg(self):
        return self._get_field_value(0, 1)
    @use_npu_header_pif_ifg.setter
    def use_npu_header_pif_ifg(self, value):
        self._set_field_value('field use_npu_header_pif_ifg', 0, 1, int, value)



class npl_object_groups_t(basic_npl_struct):
    def __init__(self, src_code=0, dest_code=0):
        super().__init__(40)
        self.src_code = src_code
        self.dest_code = dest_code

    def _get_as_sub_field(data, offset_in_data):
        result = npl_object_groups_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def src_code(self):
        return npl_og_pd_compression_code_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @src_code.setter
    def src_code(self, value):
        self._set_field_value('field src_code', 20, 20, npl_og_pd_compression_code_t, value)
    @property
    def dest_code(self):
        return npl_og_pd_compression_code_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dest_code.setter
    def dest_code(self, value):
        self._set_field_value('field dest_code', 0, 20, npl_og_pd_compression_code_t, value)



class npl_og_lpm_code_or_destination_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_og_lpm_code_or_destination_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lpm_code(self):
        return npl_og_lpm_compression_code_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @lpm_code.setter
    def lpm_code(self, value):
        self._set_field_value('field lpm_code', 0, 20, npl_og_lpm_compression_code_t, value)
    @property
    def lpts_code(self):
        return npl_og_lpts_compression_code_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @lpts_code.setter
    def lpts_code(self, value):
        self._set_field_value('field lpts_code', 0, 16, npl_og_lpts_compression_code_t, value)
    @property
    def destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 20, npl_destination_t, value)



class npl_og_lpm_result_t(basic_npl_struct):
    def __init__(self, lpm_code_or_dest=0, rtype=0, no_hbm_access=0, is_default_unused=0):
        super().__init__(24)
        self.lpm_code_or_dest = lpm_code_or_dest
        self.rtype = rtype
        self.no_hbm_access = no_hbm_access
        self.is_default_unused = is_default_unused

    def _get_as_sub_field(data, offset_in_data):
        result = npl_og_lpm_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lpm_code_or_dest(self):
        return npl_og_lpm_code_or_destination_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @lpm_code_or_dest.setter
    def lpm_code_or_dest(self, value):
        self._set_field_value('field lpm_code_or_dest', 4, 20, npl_og_lpm_code_or_destination_t, value)
    @property
    def rtype(self):
        return self._get_field_value(2, 2)
    @rtype.setter
    def rtype(self, value):
        self._set_field_value('field rtype', 2, 2, int, value)
    @property
    def no_hbm_access(self):
        return self._get_field_value(1, 1)
    @no_hbm_access.setter
    def no_hbm_access(self, value):
        self._set_field_value('field no_hbm_access', 1, 1, int, value)
    @property
    def is_default_unused(self):
        return self._get_field_value(0, 1)
    @is_default_unused.setter
    def is_default_unused(self, value):
        self._set_field_value('field is_default_unused', 0, 1, int, value)



class npl_og_pcl_config_t(basic_npl_struct):
    def __init__(self, compress=0, pcl_id=0):
        super().__init__(9)
        self.compress = compress
        self.pcl_id = pcl_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_og_pcl_config_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def compress(self):
        return self._get_field_value(8, 1)
    @compress.setter
    def compress(self, value):
        self._set_field_value('field compress', 8, 1, int, value)
    @property
    def pcl_id(self):
        return npl_og_pcl_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @pcl_id.setter
    def pcl_id(self, value):
        self._set_field_value('field pcl_id', 0, 8, npl_og_pcl_id_t, value)



class npl_output_learn_info_t(basic_npl_struct):
    def __init__(self, slp=0, relay_id=0):
        super().__init__(34)
        self.slp = slp
        self.relay_id = relay_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_output_learn_info_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def slp(self):
        return self._get_field_value(14, 20)
    @slp.setter
    def slp(self, value):
        self._set_field_value('field slp', 14, 20, int, value)
    @property
    def relay_id(self):
        return npl_relay_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @relay_id.setter
    def relay_id(self, value):
        self._set_field_value('field relay_id', 0, 14, npl_relay_id_t, value)



class npl_output_learn_record_t(basic_npl_struct):
    def __init__(self, result=0, learn_info=0, ethernet_address=0, mact_ldb=0):
        super().__init__(88)
        self.result = result
        self.learn_info = learn_info
        self.ethernet_address = ethernet_address
        self.mact_ldb = mact_ldb

    def _get_as_sub_field(data, offset_in_data):
        result = npl_output_learn_record_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def result(self):
        return self._get_field_value(86, 2)
    @result.setter
    def result(self, value):
        self._set_field_value('field result', 86, 2, int, value)
    @property
    def learn_info(self):
        return npl_output_learn_info_t._get_as_sub_field(self._data, self._offset_in_data + 52)
    @learn_info.setter
    def learn_info(self, value):
        self._set_field_value('field learn_info', 52, 34, npl_output_learn_info_t, value)
    @property
    def ethernet_address(self):
        return self._get_field_value(4, 48)
    @ethernet_address.setter
    def ethernet_address(self, value):
        self._set_field_value('field ethernet_address', 4, 48, int, value)
    @property
    def mact_ldb(self):
        return self._get_field_value(0, 4)
    @mact_ldb.setter
    def mact_ldb(self, value):
        self._set_field_value('field mact_ldb', 0, 4, int, value)



class npl_overload_union_dlp_profile_union_t_user_app_data_defined_t(basic_npl_struct):
    def __init__(self):
        super().__init__(8)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_overload_union_dlp_profile_union_t_user_app_data_defined_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def user_app_dlp_profile(self):
        return npl_dlp_profile_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @user_app_dlp_profile.setter
    def user_app_dlp_profile(self, value):
        self._set_field_value('field user_app_dlp_profile', 0, 8, npl_dlp_profile_t, value)
    @property
    def user_app_data_defined(self):
        return self._get_field_value(0, 8)
    @user_app_data_defined.setter
    def user_app_data_defined(self, value):
        self._set_field_value('field user_app_data_defined', 0, 8, int, value)



class npl_path_lp_table_result_protected_t(basic_npl_struct):
    def __init__(self, type=0, path=0, protection_id=0, primary=0, protecting=0):
        super().__init__(83)
        self.type = type
        self.path = path
        self.protection_id = protection_id
        self.primary = primary
        self.protecting = protecting

    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lp_table_result_protected_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def type(self):
        return self._get_field_value(82, 1)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 82, 1, int, value)
    @property
    def path(self):
        return npl_protection_selector_t._get_as_sub_field(self._data, self._offset_in_data + 81)
    @path.setter
    def path(self, value):
        self._set_field_value('field path', 81, 1, npl_protection_selector_t, value)
    @property
    def protection_id(self):
        return npl_path_protection_id_t._get_as_sub_field(self._data, self._offset_in_data + 68)
    @protection_id.setter
    def protection_id(self, value):
        self._set_field_value('field protection_id', 68, 13, npl_path_protection_id_t, value)
    @property
    def primary(self):
        return npl_path_lp_table_protection_entry_t._get_as_sub_field(self._data, self._offset_in_data + 34)
    @primary.setter
    def primary(self, value):
        self._set_field_value('field primary', 34, 34, npl_path_lp_table_protection_entry_t, value)
    @property
    def protecting(self):
        return npl_path_lp_table_protection_entry_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @protecting.setter
    def protecting(self, value):
        self._set_field_value('field protecting', 0, 34, npl_path_lp_table_protection_entry_t, value)



class npl_path_lp_table_result_wide_t(basic_npl_struct):
    def __init__(self):
        super().__init__(40)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_path_lp_table_result_wide_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def raw(self):
        return npl_path_lp_wide_raw_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 40, npl_path_lp_wide_raw_t, value)



class npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t(basic_npl_struct):
    def __init__(self):
        super().__init__(16)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def init_recycle_fields(self):
        return npl_initial_recycle_pd_nw_rx_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @init_recycle_fields.setter
    def init_recycle_fields(self, value):
        self._set_field_value('field init_recycle_fields', 0, 16, npl_initial_recycle_pd_nw_rx_data_t, value)



class npl_pdoq_oq_ifc_mapping_result_t(basic_npl_struct):
    def __init__(self, fcn_profile=0, txpp_map_data=0, dest_pif=0):
        super().__init__(15)
        self.fcn_profile = fcn_profile
        self.txpp_map_data = txpp_map_data
        self.dest_pif = dest_pif

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pdoq_oq_ifc_mapping_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def fcn_profile(self):
        return self._get_field_value(13, 2)
    @fcn_profile.setter
    def fcn_profile(self, value):
        self._set_field_value('field fcn_profile', 13, 2, int, value)
    @property
    def txpp_map_data(self):
        return npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t._get_as_sub_field(self._data, self._offset_in_data + 5)
    @txpp_map_data.setter
    def txpp_map_data(self, value):
        self._set_field_value('field txpp_map_data', 5, 8, npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t, value)
    @property
    def dest_pif(self):
        return self._get_field_value(0, 5)
    @dest_pif.setter
    def dest_pif(self, value):
        self._set_field_value('field dest_pif', 0, 5, int, value)



class npl_pdvoq_bank_pair_offset_result_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(108)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_pdvoq_bank_pair_offset_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def array(self):
        return basic_npl_array(108, 108, npl_pdvoq_bank_pair_offset_t, self._data, self._offset_in_data + 0)
    @array.setter
    def array(self, value):
        field = basic_npl_array(108, 108, npl_pdvoq_bank_pair_offset_t, self._data, self._offset_in_data + 0)
        field._set_field_value('field array', 0, 108, basic_npl_array, value)



class npl_pdvoq_slice_voq_properties_result_t(basic_npl_struct):
    def __init__(self, type=0, profile=0):
        super().__init__(8)
        self.type = type
        self.profile = profile

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pdvoq_slice_voq_properties_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def type(self):
        return self._get_field_value(5, 3)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 5, 3, int, value)
    @property
    def profile(self):
        return npl_voq_profile_len._get_as_sub_field(self._data, self._offset_in_data + 0)
    @profile.setter
    def profile(self, value):
        self._set_field_value('field profile', 0, 5, npl_voq_profile_len, value)



class npl_pfc_em_compound_results_t(basic_npl_struct):
    def __init__(self, payload=0):
        super().__init__(40)
        self.payload = payload

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pfc_em_compound_results_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return npl_pfc_em_lookup_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 0, 40, npl_pfc_em_lookup_t, value)



class npl_port_npp_protection_table_result_protected_t(basic_npl_struct):
    def __init__(self, type=0, path=0, protection_id=0, primary=0, protecting=0):
        super().__init__(92)
        self.type = type
        self.path = path
        self.protection_id = protection_id
        self.primary = primary
        self.protecting = protecting

    def _get_as_sub_field(data, offset_in_data):
        result = npl_port_npp_protection_table_result_protected_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def type(self):
        return self._get_field_value(91, 1)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 91, 1, int, value)
    @property
    def path(self):
        return npl_protection_selector_t._get_as_sub_field(self._data, self._offset_in_data + 90)
    @path.setter
    def path(self, value):
        self._set_field_value('field path', 90, 1, npl_protection_selector_t, value)
    @property
    def protection_id(self):
        return npl_port_protection_id_t._get_as_sub_field(self._data, self._offset_in_data + 80)
    @protection_id.setter
    def protection_id(self, value):
        self._set_field_value('field protection_id', 80, 10, npl_port_protection_id_t, value)
    @property
    def primary(self):
        return npl_port_npp_protection_table_protection_entry_t._get_as_sub_field(self._data, self._offset_in_data + 40)
    @primary.setter
    def primary(self, value):
        self._set_field_value('field primary', 40, 40, npl_port_npp_protection_table_protection_entry_t, value)
    @property
    def protecting(self):
        return npl_port_npp_protection_table_protection_entry_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @protecting.setter
    def protecting(self, value):
        self._set_field_value('field protecting', 0, 40, npl_port_npp_protection_table_protection_entry_t, value)



class npl_post_fwd_params_t(basic_npl_struct):
    def __init__(self, use_metedata_table_per_packet_format=0, ip_ver_and_post_fwd_stage=0):
        super().__init__(6)
        self.use_metedata_table_per_packet_format = use_metedata_table_per_packet_format
        self.ip_ver_and_post_fwd_stage = ip_ver_and_post_fwd_stage

    def _get_as_sub_field(data, offset_in_data):
        result = npl_post_fwd_params_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def use_metedata_table_per_packet_format(self):
        return npl_use_metedata_table_per_packet_format_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @use_metedata_table_per_packet_format.setter
    def use_metedata_table_per_packet_format(self, value):
        self._set_field_value('field use_metedata_table_per_packet_format', 4, 2, npl_use_metedata_table_per_packet_format_t, value)
    @property
    def ip_ver_and_post_fwd_stage(self):
        return npl_ip_ver_and_post_fwd_stage_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ip_ver_and_post_fwd_stage.setter
    def ip_ver_and_post_fwd_stage(self, value):
        self._set_field_value('field ip_ver_and_post_fwd_stage', 0, 4, npl_ip_ver_and_post_fwd_stage_t, value)



class npl_properties_t(basic_npl_struct):
    def __init__(self, l3_dlp_id_ext=0, monitor_or_l3_dlp_ip_type=0):
        super().__init__(4)
        self.l3_dlp_id_ext = l3_dlp_id_ext
        self.monitor_or_l3_dlp_ip_type = monitor_or_l3_dlp_ip_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_properties_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_dlp_id_ext(self):
        return npl_l3_dlp_msbs_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @l3_dlp_id_ext.setter
    def l3_dlp_id_ext(self, value):
        self._set_field_value('field l3_dlp_id_ext', 2, 2, npl_l3_dlp_msbs_t, value)
    @property
    def monitor_or_l3_dlp_ip_type(self):
        return npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @monitor_or_l3_dlp_ip_type.setter
    def monitor_or_l3_dlp_ip_type(self, value):
        self._set_field_value('field monitor_or_l3_dlp_ip_type', 0, 1, npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t, value)



class npl_punt_code_t(basic_npl_struct):
    def __init__(self):
        super().__init__(8)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_code_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def punt_redirect_code(self):
        return npl_redirect_code_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_redirect_code.setter
    def punt_redirect_code(self, value):
        self._set_field_value('field punt_redirect_code', 0, 8, npl_redirect_code_t, value)
    @property
    def snoop_code(self):
        return npl_snoop_code_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @snoop_code.setter
    def snoop_code(self, value):
        self._set_field_value('field snoop_code', 0, 8, npl_snoop_code_t, value)
    @property
    def punt_mirror_code(self):
        return self._get_field_value(0, 8)
    @punt_mirror_code.setter
    def punt_mirror_code(self, value):
        self._set_field_value('field punt_mirror_code', 0, 8, int, value)
    @property
    def lpts_reason(self):
        return self._get_field_value(0, 8)
    @lpts_reason.setter
    def lpts_reason(self, value):
        self._set_field_value('field lpts_reason', 0, 8, int, value)



class npl_punt_encap_data_lsb_t(basic_npl_struct):
    def __init__(self, punt_nw_encap_ptr=0, punt_nw_encap_type=0, extra=0, punt_controls=0):
        super().__init__(16)
        self.punt_nw_encap_ptr = punt_nw_encap_ptr
        self.punt_nw_encap_type = punt_nw_encap_type
        self.extra = extra
        self.punt_controls = punt_controls

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_encap_data_lsb_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def punt_nw_encap_ptr(self):
        return npl_punt_nw_encap_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @punt_nw_encap_ptr.setter
    def punt_nw_encap_ptr(self, value):
        self._set_field_value('field punt_nw_encap_ptr', 8, 8, npl_punt_nw_encap_ptr_t, value)
    @property
    def punt_nw_encap_type(self):
        return self._get_field_value(4, 4)
    @punt_nw_encap_type.setter
    def punt_nw_encap_type(self, value):
        self._set_field_value('field punt_nw_encap_type', 4, 4, int, value)
    @property
    def extra(self):
        return npl_punt_encap_data_lsb_t_anonymous_union_extra_t._get_as_sub_field(self._data, self._offset_in_data + 3)
    @extra.setter
    def extra(self, value):
        self._set_field_value('field extra', 3, 1, npl_punt_encap_data_lsb_t_anonymous_union_extra_t, value)
    @property
    def punt_controls(self):
        return npl_punt_controls_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_controls.setter
    def punt_controls(self, value):
        self._set_field_value('field punt_controls', 0, 3, npl_punt_controls_t, value)



class npl_punt_npu_host_data_t(basic_npl_struct):
    def __init__(self, npu_host_macro_data=0):
        super().__init__(48)
        self.npu_host_macro_data = npu_host_macro_data

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_npu_host_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def npu_host_macro_data(self):
        return npl_punt_npu_host_macro_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @npu_host_macro_data.setter
    def npu_host_macro_data(self, value):
        self._set_field_value('field npu_host_macro_data', 0, 16, npl_punt_npu_host_macro_data_t, value)



class npl_punt_shared_lsb_encap_t(basic_npl_struct):
    def __init__(self, punt_ts_cmd=0, punt_encap_data_lsb=0, punt_cud_type=0):
        super().__init__(32)
        self.punt_ts_cmd = punt_ts_cmd
        self.punt_encap_data_lsb = punt_encap_data_lsb
        self.punt_cud_type = punt_cud_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_shared_lsb_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def punt_ts_cmd(self):
        return npl_ts_command_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @punt_ts_cmd.setter
    def punt_ts_cmd(self, value):
        self._set_field_value('field punt_ts_cmd', 20, 12, npl_ts_command_t, value)
    @property
    def punt_encap_data_lsb(self):
        return npl_punt_encap_data_lsb_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @punt_encap_data_lsb.setter
    def punt_encap_data_lsb(self, value):
        self._set_field_value('field punt_encap_data_lsb', 4, 16, npl_punt_encap_data_lsb_t, value)
    @property
    def punt_cud_type(self):
        return self._get_field_value(0, 4)
    @punt_cud_type.setter
    def punt_cud_type(self, value):
        self._set_field_value('field punt_cud_type', 0, 4, int, value)



class npl_punt_src_and_code_t(basic_npl_struct):
    def __init__(self, punt_source=0, punt_code=0):
        super().__init__(12)
        self.punt_source = punt_source
        self.punt_code = punt_code

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_src_and_code_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def punt_source(self):
        return self._get_field_value(8, 4)
    @punt_source.setter
    def punt_source(self, value):
        self._set_field_value('field punt_source', 8, 4, int, value)
    @property
    def punt_code(self):
        return npl_punt_code_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_code.setter
    def punt_code(self, value):
        self._set_field_value('field punt_code', 0, 8, npl_punt_code_t, value)



class npl_punt_ssp_attributes_t(basic_npl_struct):
    def __init__(self, split_voq=0, ssp=0):
        super().__init__(27)
        self.split_voq = split_voq
        self.ssp = ssp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_ssp_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def split_voq(self):
        return npl_split_voq_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @split_voq.setter
    def split_voq(self, value):
        self._set_field_value('field split_voq', 16, 11, npl_split_voq_t, value)
    @property
    def ssp(self):
        return npl_punt_ssp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ssp.setter
    def ssp(self, value):
        self._set_field_value('field ssp', 0, 16, npl_punt_ssp_t, value)



class npl_punt_sub_code_t(basic_npl_struct):
    def __init__(self, sub_code=0):
        super().__init__(4)
        self.sub_code = sub_code

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_sub_code_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sub_code(self):
        return npl_punt_sub_code_t_anonymous_union_sub_code_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @sub_code.setter
    def sub_code(self, value):
        self._set_field_value('field sub_code', 0, 4, npl_punt_sub_code_t_anonymous_union_sub_code_t, value)



class npl_punt_sub_code_with_padding_t(basic_npl_struct):
    def __init__(self, ene_punt_sub_code=0):
        super().__init__(8)
        self.ene_punt_sub_code = ene_punt_sub_code

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_sub_code_with_padding_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ene_punt_sub_code(self):
        return npl_punt_sub_code_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ene_punt_sub_code.setter
    def ene_punt_sub_code(self, value):
        self._set_field_value('field ene_punt_sub_code', 0, 4, npl_punt_sub_code_t, value)



class npl_pwe_to_l3_compound_lookup_result_t(basic_npl_struct):
    def __init__(self, payload=0):
        super().__init__(20)
        self.payload = payload

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pwe_to_l3_compound_lookup_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return npl_pwe_to_l3_lookup_result_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 0, 20, npl_pwe_to_l3_lookup_result_t, value)



class npl_qos_mapping_key_t_anonymous_union_key_union_t(basic_npl_struct):
    def __init__(self):
        super().__init__(8)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_qos_mapping_key_t_anonymous_union_key_union_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def key(self):
        return npl_qos_tag_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @key.setter
    def key(self, value):
        self._set_field_value('field key', 0, 8, npl_qos_tag_t, value)
    @property
    def mpls_exp(self):
        return self._get_field_value(0, 3)
    @mpls_exp.setter
    def mpls_exp(self, value):
        self._set_field_value('field mpls_exp', 0, 3, int, value)



class npl_redirect_stage_og_key_t(basic_npl_struct):
    def __init__(self, lpts_is_mc=0, lpts_og_app_id=0, lpts_packet_flags=0, lpts_object_groups=0):
        super().__init__(39)
        self.lpts_is_mc = lpts_is_mc
        self.lpts_og_app_id = lpts_og_app_id
        self.lpts_packet_flags = lpts_packet_flags
        self.lpts_object_groups = lpts_object_groups

    def _get_as_sub_field(data, offset_in_data):
        result = npl_redirect_stage_og_key_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lpts_is_mc(self):
        return self._get_field_value(38, 1)
    @lpts_is_mc.setter
    def lpts_is_mc(self, value):
        self._set_field_value('field lpts_is_mc', 38, 1, int, value)
    @property
    def lpts_og_app_id(self):
        return self._get_field_value(34, 4)
    @lpts_og_app_id.setter
    def lpts_og_app_id(self, value):
        self._set_field_value('field lpts_og_app_id', 34, 4, int, value)
    @property
    def lpts_packet_flags(self):
        return npl_lpts_packet_flags_t._get_as_sub_field(self._data, self._offset_in_data + 32)
    @lpts_packet_flags.setter
    def lpts_packet_flags(self, value):
        self._set_field_value('field lpts_packet_flags', 32, 2, npl_lpts_packet_flags_t, value)
    @property
    def lpts_object_groups(self):
        return npl_lpts_object_groups_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @lpts_object_groups.setter
    def lpts_object_groups(self, value):
        self._set_field_value('field lpts_object_groups', 0, 32, npl_lpts_object_groups_t, value)



class npl_relay_attr_table_payload_t(basic_npl_struct):
    def __init__(self):
        super().__init__(54)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_relay_attr_table_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def relay_attr(self):
        return npl_mac_relay_attributes_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @relay_attr.setter
    def relay_attr(self, value):
        self._set_field_value('field relay_attr', 0, 43, npl_mac_relay_attributes_payload_t, value)



class npl_rtf_next_macro_pack_fields_t(basic_npl_struct):
    def __init__(self, curr_and_next_prot_type=0, stop_on_step_and_next_stage_compressed_fields=0):
        super().__init__(12)
        self.curr_and_next_prot_type = curr_and_next_prot_type
        self.stop_on_step_and_next_stage_compressed_fields = stop_on_step_and_next_stage_compressed_fields

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rtf_next_macro_pack_fields_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def curr_and_next_prot_type(self):
        return npl_curr_and_next_prot_type_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @curr_and_next_prot_type.setter
    def curr_and_next_prot_type(self, value):
        self._set_field_value('field curr_and_next_prot_type', 4, 8, npl_curr_and_next_prot_type_t, value)
    @property
    def stop_on_step_and_next_stage_compressed_fields(self):
        return npl_stop_on_step_and_next_stage_compressed_fields_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @stop_on_step_and_next_stage_compressed_fields.setter
    def stop_on_step_and_next_stage_compressed_fields(self, value):
        self._set_field_value('field stop_on_step_and_next_stage_compressed_fields', 0, 4, npl_stop_on_step_and_next_stage_compressed_fields_t, value)



class npl_rtf_result_profile_0_t(basic_npl_struct):
    def __init__(self, mirror_action=0, phb=0, q_m_offset_5bits=0, counter_action_type=0, mirror_cmd_or_offset=0, override_phb=0, rtf_sec_action=0, override_qos_group=0, ingress_qos_remark=0, force=0):
        super().__init__(62)
        self.mirror_action = mirror_action
        self.phb = phb
        self.q_m_offset_5bits = q_m_offset_5bits
        self.counter_action_type = counter_action_type
        self.mirror_cmd_or_offset = mirror_cmd_or_offset
        self.override_phb = override_phb
        self.rtf_sec_action = rtf_sec_action
        self.override_qos_group = override_qos_group
        self.ingress_qos_remark = ingress_qos_remark
        self.force = force

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rtf_result_profile_0_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mirror_action(self):
        return self._get_field_value(61, 1)
    @mirror_action.setter
    def mirror_action(self, value):
        self._set_field_value('field mirror_action', 61, 1, int, value)
    @property
    def phb(self):
        return npl_phb_t._get_as_sub_field(self._data, self._offset_in_data + 56)
    @phb.setter
    def phb(self, value):
        self._set_field_value('field phb', 56, 5, npl_phb_t, value)
    @property
    def q_m_offset_5bits(self):
        return self._get_field_value(51, 5)
    @q_m_offset_5bits.setter
    def q_m_offset_5bits(self, value):
        self._set_field_value('field q_m_offset_5bits', 51, 5, int, value)
    @property
    def counter_action_type(self):
        return self._get_field_value(49, 2)
    @counter_action_type.setter
    def counter_action_type(self, value):
        self._set_field_value('field counter_action_type', 49, 2, int, value)
    @property
    def mirror_cmd_or_offset(self):
        return npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t._get_as_sub_field(self._data, self._offset_in_data + 44)
    @mirror_cmd_or_offset.setter
    def mirror_cmd_or_offset(self, value):
        self._set_field_value('field mirror_cmd_or_offset', 44, 5, npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t, value)
    @property
    def override_phb(self):
        return self._get_field_value(43, 1)
    @override_phb.setter
    def override_phb(self, value):
        self._set_field_value('field override_phb', 43, 1, int, value)
    @property
    def rtf_sec_action(self):
        return self._get_field_value(40, 3)
    @rtf_sec_action.setter
    def rtf_sec_action(self, value):
        self._set_field_value('field rtf_sec_action', 40, 3, int, value)
    @property
    def override_qos_group(self):
        return self._get_field_value(39, 1)
    @override_qos_group.setter
    def override_qos_group(self, value):
        self._set_field_value('field override_qos_group', 39, 1, int, value)
    @property
    def ingress_qos_remark(self):
        return npl_ingress_qos_mapping_remark_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @ingress_qos_remark.setter
    def ingress_qos_remark(self, value):
        self._set_field_value('field ingress_qos_remark', 20, 19, npl_ingress_qos_mapping_remark_t, value)
    @property
    def force(self):
        return npl_rtf_result_profile_0_t_anonymous_union_force_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @force.setter
    def force(self, value):
        self._set_field_value('field force', 0, 20, npl_rtf_result_profile_0_t_anonymous_union_force_t, value)



class npl_rtf_result_profile_1_t(basic_npl_struct):
    def __init__(self, rtf_res_profile_1_action=0, meter_or_counter=0, override_qos_group=0, ingress_qos_remark=0, destination=0):
        super().__init__(62)
        self.rtf_res_profile_1_action = rtf_res_profile_1_action
        self.meter_or_counter = meter_or_counter
        self.override_qos_group = override_qos_group
        self.ingress_qos_remark = ingress_qos_remark
        self.destination = destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rtf_result_profile_1_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rtf_res_profile_1_action(self):
        return self._get_field_value(60, 1)
    @rtf_res_profile_1_action.setter
    def rtf_res_profile_1_action(self, value):
        self._set_field_value('field rtf_res_profile_1_action', 60, 1, int, value)
    @property
    def meter_or_counter(self):
        return npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t._get_as_sub_field(self._data, self._offset_in_data + 40)
    @meter_or_counter.setter
    def meter_or_counter(self, value):
        self._set_field_value('field meter_or_counter', 40, 20, npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t, value)
    @property
    def override_qos_group(self):
        return self._get_field_value(39, 1)
    @override_qos_group.setter
    def override_qos_group(self, value):
        self._set_field_value('field override_qos_group', 39, 1, int, value)
    @property
    def ingress_qos_remark(self):
        return npl_ingress_qos_mapping_remark_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @ingress_qos_remark.setter
    def ingress_qos_remark(self, value):
        self._set_field_value('field ingress_qos_remark', 20, 19, npl_ingress_qos_mapping_remark_t, value)
    @property
    def destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 20, npl_destination_t, value)



class npl_sch_oqse_cfg_result_4p_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(72)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_sch_oqse_cfg_result_4p_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def logical_port_map(self):
        return basic_npl_array(4, 2, int, self._data, self._offset_in_data + 68)
    @logical_port_map.setter
    def logical_port_map(self, value):
        field = basic_npl_array(4, 2, int, self._data, self._offset_in_data + 68)
        field._set_field_value('field logical_port_map', 0, 4, basic_npl_array, value)
    @property
    def oqse_topology(self):
        return basic_npl_array(4, 2, npl_oqse_topology_4p_t, self._data, self._offset_in_data + 64)
    @oqse_topology.setter
    def oqse_topology(self, value):
        field = basic_npl_array(4, 2, npl_oqse_topology_4p_t, self._data, self._offset_in_data + 64)
        field._set_field_value('field oqse_topology', 0, 4, basic_npl_array, value)
    @property
    def oqse_wfq_weight(self):
        return basic_npl_array(64, 2, npl_wfq_weight_4p_entry_t, self._data, self._offset_in_data + 0)
    @oqse_wfq_weight.setter
    def oqse_wfq_weight(self, value):
        field = basic_npl_array(64, 2, npl_wfq_weight_4p_entry_t, self._data, self._offset_in_data + 0)
        field._set_field_value('field oqse_wfq_weight', 0, 64, basic_npl_array, value)



class npl_sch_oqse_cfg_result_8p_t(basic_npl_struct):
    def __init__(self, logical_port_map=0, oqse_topology=0, oqse_wfq_weight=0):
        super().__init__(72)
        self.logical_port_map = logical_port_map
        self.oqse_topology = oqse_topology
        self.oqse_wfq_weight = oqse_wfq_weight

    def _get_as_sub_field(data, offset_in_data):
        result = npl_sch_oqse_cfg_result_8p_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def logical_port_map(self):
        return self._get_field_value(68, 4)
    @logical_port_map.setter
    def logical_port_map(self, value):
        self._set_field_value('field logical_port_map', 68, 4, int, value)
    @property
    def oqse_topology(self):
        return self._get_field_value(64, 4)
    @oqse_topology.setter
    def oqse_topology(self, value):
        self._set_field_value('field oqse_topology', 64, 4, int, value)
    @property
    def oqse_wfq_weight(self):
        return npl_wfq_weight_8p_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @oqse_wfq_weight.setter
    def oqse_wfq_weight(self, value):
        self._set_field_value('field oqse_wfq_weight', 0, 64, npl_wfq_weight_8p_t, value)



class npl_sch_oqse_cfg_result_t(basic_npl_struct):
    def __init__(self):
        super().__init__(72)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_sch_oqse_cfg_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def single_8p(self):
        return npl_sch_oqse_cfg_result_8p_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @single_8p.setter
    def single_8p(self, value):
        self._set_field_value('field single_8p', 0, 72, npl_sch_oqse_cfg_result_8p_t, value)
    @property
    def pair_4p(self):
        return npl_sch_oqse_cfg_result_4p_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @pair_4p.setter
    def pair_4p(self, value):
        self._set_field_value('field pair_4p', 0, 72, npl_sch_oqse_cfg_result_4p_t, value)



class npl_sec_acl_attributes_t(basic_npl_struct):
    def __init__(self, rtf_conf_set_ptr=0, p_counter=0, slp_dlp=0, per_pkt_type_count=0, port_mirror_type=0, l2_lpts_slp_attributes=0):
        super().__init__(52)
        self.rtf_conf_set_ptr = rtf_conf_set_ptr
        self.p_counter = p_counter
        self.slp_dlp = slp_dlp
        self.per_pkt_type_count = per_pkt_type_count
        self.port_mirror_type = port_mirror_type
        self.l2_lpts_slp_attributes = l2_lpts_slp_attributes

    def _get_as_sub_field(data, offset_in_data):
        result = npl_sec_acl_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rtf_conf_set_ptr(self):
        return self._get_field_value(44, 8)
    @rtf_conf_set_ptr.setter
    def rtf_conf_set_ptr(self, value):
        self._set_field_value('field rtf_conf_set_ptr', 44, 8, int, value)
    @property
    def p_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 24)
    @p_counter.setter
    def p_counter(self, value):
        self._set_field_value('field p_counter', 24, 20, npl_counter_ptr_t, value)
    @property
    def slp_dlp(self):
        return npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @slp_dlp.setter
    def slp_dlp(self, value):
        self._set_field_value('field slp_dlp', 4, 20, npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t, value)
    @property
    def per_pkt_type_count(self):
        return self._get_field_value(3, 1)
    @per_pkt_type_count.setter
    def per_pkt_type_count(self, value):
        self._set_field_value('field per_pkt_type_count', 3, 1, int, value)
    @property
    def port_mirror_type(self):
        return self._get_field_value(2, 1)
    @port_mirror_type.setter
    def port_mirror_type(self, value):
        self._set_field_value('field port_mirror_type', 2, 1, int, value)
    @property
    def l2_lpts_slp_attributes(self):
        return self._get_field_value(0, 2)
    @l2_lpts_slp_attributes.setter
    def l2_lpts_slp_attributes(self, value):
        self._set_field_value('field l2_lpts_slp_attributes', 0, 2, int, value)



class npl_shared_l2_lp_attributes_t(basic_npl_struct):
    def __init__(self, p2p=0, qos_id=0, lp_profile=0, stp_state_block=0, mirror_cmd=0, sec_acl_attributes=0, q_counter=0, m_counter=0):
        super().__init__(105)
        self.p2p = p2p
        self.qos_id = qos_id
        self.lp_profile = lp_profile
        self.stp_state_block = stp_state_block
        self.mirror_cmd = mirror_cmd
        self.sec_acl_attributes = sec_acl_attributes
        self.q_counter = q_counter
        self.m_counter = m_counter

    def _get_as_sub_field(data, offset_in_data):
        result = npl_shared_l2_lp_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def p2p(self):
        return self._get_field_value(104, 1)
    @p2p.setter
    def p2p(self, value):
        self._set_field_value('field p2p', 104, 1, int, value)
    @property
    def qos_id(self):
        return self._get_field_value(100, 4)
    @qos_id.setter
    def qos_id(self, value):
        self._set_field_value('field qos_id', 100, 4, int, value)
    @property
    def lp_profile(self):
        return self._get_field_value(98, 2)
    @lp_profile.setter
    def lp_profile(self, value):
        self._set_field_value('field lp_profile', 98, 2, int, value)
    @property
    def stp_state_block(self):
        return self._get_field_value(97, 1)
    @stp_state_block.setter
    def stp_state_block(self, value):
        self._set_field_value('field stp_state_block', 97, 1, int, value)
    @property
    def mirror_cmd(self):
        return self._get_field_value(92, 5)
    @mirror_cmd.setter
    def mirror_cmd(self, value):
        self._set_field_value('field mirror_cmd', 92, 5, int, value)
    @property
    def sec_acl_attributes(self):
        return npl_sec_acl_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 40)
    @sec_acl_attributes.setter
    def sec_acl_attributes(self, value):
        self._set_field_value('field sec_acl_attributes', 40, 52, npl_sec_acl_attributes_t, value)
    @property
    def q_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @q_counter.setter
    def q_counter(self, value):
        self._set_field_value('field q_counter', 20, 20, npl_counter_ptr_t, value)
    @property
    def m_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @m_counter.setter
    def m_counter(self, value):
        self._set_field_value('field m_counter', 0, 20, npl_counter_ptr_t, value)



class npl_single_label_encap_data_t_anonymous_union_udat_t(basic_npl_struct):
    def __init__(self):
        super().__init__(32)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_single_label_encap_data_t_anonymous_union_udat_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def gre_key(self):
        return self._get_field_value(0, 32)
    @gre_key.setter
    def gre_key(self, value):
        self._set_field_value('field gre_key', 0, 32, int, value)
    @property
    def label_and_valid(self):
        return npl_vpl_label_and_valid_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @label_and_valid.setter
    def label_and_valid(self, value):
        self._set_field_value('field label_and_valid', 0, 26, npl_vpl_label_and_valid_t, value)



class npl_slice_and_source_if_t(basic_npl_struct):
    def __init__(self, slice_id_on_npu=0, source_if_on_npu=0):
        super().__init__(11)
        self.slice_id_on_npu = slice_id_on_npu
        self.source_if_on_npu = source_if_on_npu

    def _get_as_sub_field(data, offset_in_data):
        result = npl_slice_and_source_if_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def slice_id_on_npu(self):
        return self._get_field_value(8, 3)
    @slice_id_on_npu.setter
    def slice_id_on_npu(self, value):
        self._set_field_value('field slice_id_on_npu', 8, 3, int, value)
    @property
    def source_if_on_npu(self):
        return npl_source_if_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @source_if_on_npu.setter
    def source_if_on_npu(self, value):
        self._set_field_value('field source_if_on_npu', 0, 8, npl_source_if_t, value)



class npl_sport_or_l4_protocol_t(basic_npl_struct):
    def __init__(self, sport_or_l4_protocol_type=0):
        super().__init__(16)
        self.sport_or_l4_protocol_type = sport_or_l4_protocol_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_sport_or_l4_protocol_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sport_or_l4_protocol_type(self):
        return npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @sport_or_l4_protocol_type.setter
    def sport_or_l4_protocol_type(self, value):
        self._set_field_value('field sport_or_l4_protocol_type', 0, 16, npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t, value)



class npl_svi_eve_sub_type_plus_pad_plus_prf_t(basic_npl_struct):
    def __init__(self, sub_type_plus_prf=0):
        super().__init__(14)
        self.sub_type_plus_prf = sub_type_plus_prf

    def _get_as_sub_field(data, offset_in_data):
        result = npl_svi_eve_sub_type_plus_pad_plus_prf_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sub_type_plus_prf(self):
        return npl_svi_eve_sub_type_plus_prf_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @sub_type_plus_prf.setter
    def sub_type_plus_prf(self, value):
        self._set_field_value('field sub_type_plus_prf', 0, 5, npl_svi_eve_sub_type_plus_prf_t, value)



class npl_te_midpoint_nhlfe_t(basic_npl_struct):
    def __init__(self, mp_label=0, lsp=0, midpoint_nh=0, counter_offset=0):
        super().__init__(60)
        self.mp_label = mp_label
        self.lsp = lsp
        self.midpoint_nh = midpoint_nh
        self.counter_offset = counter_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_te_midpoint_nhlfe_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mp_label(self):
        return self._get_field_value(40, 20)
    @mp_label.setter
    def mp_label(self, value):
        self._set_field_value('field mp_label', 40, 20, int, value)
    @property
    def lsp(self):
        return npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @lsp.setter
    def lsp(self, value):
        self._set_field_value('field lsp', 20, 20, npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t, value)
    @property
    def midpoint_nh(self):
        return self._get_field_value(8, 12)
    @midpoint_nh.setter
    def midpoint_nh(self, value):
        self._set_field_value('field midpoint_nh', 8, 12, int, value)
    @property
    def counter_offset(self):
        return npl_compressed_counter_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @counter_offset.setter
    def counter_offset(self, value):
        self._set_field_value('field counter_offset', 0, 8, npl_compressed_counter_t, value)



class npl_tunnel_headend_encap_t(basic_npl_struct):
    def __init__(self, lsp_destination=0, te_asbr=0, mldp_protection=0):
        super().__init__(46)
        self.lsp_destination = lsp_destination
        self.te_asbr = te_asbr
        self.mldp_protection = mldp_protection

    def _get_as_sub_field(data, offset_in_data):
        result = npl_tunnel_headend_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lsp_destination(self):
        return npl_lsp_destination_t._get_as_sub_field(self._data, self._offset_in_data + 26)
    @lsp_destination.setter
    def lsp_destination(self, value):
        self._set_field_value('field lsp_destination', 26, 20, npl_lsp_destination_t, value)
    @property
    def te_asbr(self):
        return npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t._get_as_sub_field(self._data, self._offset_in_data + 10)
    @te_asbr.setter
    def te_asbr(self, value):
        self._set_field_value('field te_asbr', 10, 16, npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t, value)
    @property
    def mldp_protection(self):
        return npl_mldp_protection_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mldp_protection.setter
    def mldp_protection(self, value):
        self._set_field_value('field mldp_protection', 0, 10, npl_mldp_protection_t, value)



class npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t(basic_npl_struct):
    def __init__(self, force_pipe_ttl_ingress_ptp_null=0, force_pipe_ttl_ingress_ptp_info=0, tunnel_type=0):
        super().__init__(12)
        self.force_pipe_ttl_ingress_ptp_null = force_pipe_ttl_ingress_ptp_null
        self.force_pipe_ttl_ingress_ptp_info = force_pipe_ttl_ingress_ptp_info
        self.tunnel_type = tunnel_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def force_pipe_ttl_ingress_ptp_null(self):
        return npl_force_pipe_ttl_ingress_ptp_info_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @force_pipe_ttl_ingress_ptp_null.setter
    def force_pipe_ttl_ingress_ptp_null(self, value):
        self._set_field_value('field force_pipe_ttl_ingress_ptp_null', 8, 4, npl_force_pipe_ttl_ingress_ptp_info_t, value)
    @property
    def force_pipe_ttl_ingress_ptp_info(self):
        return npl_force_pipe_ttl_ingress_ptp_info_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @force_pipe_ttl_ingress_ptp_info.setter
    def force_pipe_ttl_ingress_ptp_info(self, value):
        self._set_field_value('field force_pipe_ttl_ingress_ptp_info', 4, 4, npl_force_pipe_ttl_ingress_ptp_info_t, value)
    @property
    def tunnel_type(self):
        return self._get_field_value(0, 4)
    @tunnel_type.setter
    def tunnel_type(self, value):
        self._set_field_value('field tunnel_type', 0, 4, int, value)



class npl_tx_to_rx_rcy_data_t(basic_npl_struct):
    def __init__(self, unscheduled_recycle_code=0, unscheduled_recycle_data=0):
        super().__init__(8)
        self.unscheduled_recycle_code = unscheduled_recycle_code
        self.unscheduled_recycle_data = unscheduled_recycle_data

    def _get_as_sub_field(data, offset_in_data):
        result = npl_tx_to_rx_rcy_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def unscheduled_recycle_code(self):
        return npl_unscheduled_recycle_code_t._get_as_sub_field(self._data, self._offset_in_data + 6)
    @unscheduled_recycle_code.setter
    def unscheduled_recycle_code(self, value):
        self._set_field_value('field unscheduled_recycle_code', 6, 2, npl_unscheduled_recycle_code_t, value)
    @property
    def unscheduled_recycle_data(self):
        return self._get_field_value(0, 6)
    @unscheduled_recycle_data.setter
    def unscheduled_recycle_data(self, value):
        self._set_field_value('field unscheduled_recycle_data', 0, 6, int, value)



class npl_ud_key_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(4096)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ud_key_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def udfs(self):
        return basic_npl_array(4096, 32, npl_udf_t, self._data, self._offset_in_data + 0)
    @udfs.setter
    def udfs(self, value):
        field = basic_npl_array(4096, 32, npl_udf_t, self._data, self._offset_in_data + 0)
        field._set_field_value('field udfs', 0, 4096, basic_npl_array, value)



class npl_unicast_flb_tm_header_padded_t(basic_npl_struct):
    def __init__(self, unicast_flb_tm_header=0):
        super().__init__(24)
        self.unicast_flb_tm_header = unicast_flb_tm_header

    def _get_as_sub_field(data, offset_in_data):
        result = npl_unicast_flb_tm_header_padded_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def unicast_flb_tm_header(self):
        return npl_unicast_flb_tm_header_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @unicast_flb_tm_header.setter
    def unicast_flb_tm_header(self, value):
        self._set_field_value('field unicast_flb_tm_header', 0, 24, npl_unicast_flb_tm_header_t, value)



class npl_unicast_plb_tm_header_padded_t(basic_npl_struct):
    def __init__(self, unicast_plb_tm_header=0):
        super().__init__(32)
        self.unicast_plb_tm_header = unicast_plb_tm_header

    def _get_as_sub_field(data, offset_in_data):
        result = npl_unicast_plb_tm_header_padded_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def unicast_plb_tm_header(self):
        return npl_unicast_plb_tm_header_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @unicast_plb_tm_header.setter
    def unicast_plb_tm_header(self, value):
        self._set_field_value('field unicast_plb_tm_header', 0, 32, npl_unicast_plb_tm_header_t, value)



class npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t(basic_npl_struct):
    def __init__(self):
        super().__init__(16)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def drop_green(self):
        return npl_drop_color_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @drop_green.setter
    def drop_green(self, value):
        self._set_field_value('field drop_green', 0, 16, npl_drop_color_t, value)
    @property
    def drop_green_u(self):
        return self._get_field_value(0, 16)
    @drop_green_u.setter
    def drop_green_u(self, value):
        self._set_field_value('field drop_green_u', 0, 16, int, value)



class npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t(basic_npl_struct):
    def __init__(self):
        super().__init__(16)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def drop_yellow(self):
        return npl_drop_color_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @drop_yellow.setter
    def drop_yellow(self, value):
        self._set_field_value('field drop_yellow', 0, 16, npl_drop_color_t, value)
    @property
    def drop_yellow_u(self):
        return self._get_field_value(0, 16)
    @drop_yellow_u.setter
    def drop_yellow_u(self, value):
        self._set_field_value('field drop_yellow_u', 0, 16, int, value)



class npl_additional_labels_t(basic_npl_struct):
    def __init__(self, label_3=0, label_4=0, label_5=0, label_6=0, label_7=0, label_8_or_num_labels=0):
        super().__init__(120)
        self.label_3 = label_3
        self.label_4 = label_4
        self.label_5 = label_5
        self.label_6 = label_6
        self.label_7 = label_7
        self.label_8_or_num_labels = label_8_or_num_labels

    def _get_as_sub_field(data, offset_in_data):
        result = npl_additional_labels_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def label_3(self):
        return self._get_field_value(100, 20)
    @label_3.setter
    def label_3(self, value):
        self._set_field_value('field label_3', 100, 20, int, value)
    @property
    def label_4(self):
        return self._get_field_value(80, 20)
    @label_4.setter
    def label_4(self, value):
        self._set_field_value('field label_4', 80, 20, int, value)
    @property
    def label_5(self):
        return self._get_field_value(60, 20)
    @label_5.setter
    def label_5(self, value):
        self._set_field_value('field label_5', 60, 20, int, value)
    @property
    def label_6(self):
        return self._get_field_value(40, 20)
    @label_6.setter
    def label_6(self, value):
        self._set_field_value('field label_6', 40, 20, int, value)
    @property
    def label_7(self):
        return self._get_field_value(20, 20)
    @label_7.setter
    def label_7(self, value):
        self._set_field_value('field label_7', 20, 20, int, value)
    @property
    def label_8_or_num_labels(self):
        return npl_label_or_num_labels_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @label_8_or_num_labels.setter
    def label_8_or_num_labels(self, value):
        self._set_field_value('field label_8_or_num_labels', 0, 20, npl_label_or_num_labels_t, value)



class npl_bfd_aux_shared_payload_t(basic_npl_struct):
    def __init__(self, local_discriminator=0, remote_discriminator=0, tos=0, local_diag_code=0, requires_inject_up=0, session_type=0, prot_shared=0):
        super().__init__(120)
        self.local_discriminator = local_discriminator
        self.remote_discriminator = remote_discriminator
        self.tos = tos
        self.local_diag_code = local_diag_code
        self.requires_inject_up = requires_inject_up
        self.session_type = session_type
        self.prot_shared = prot_shared

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_aux_shared_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def local_discriminator(self):
        return self._get_field_value(88, 32)
    @local_discriminator.setter
    def local_discriminator(self, value):
        self._set_field_value('field local_discriminator', 88, 32, int, value)
    @property
    def remote_discriminator(self):
        return self._get_field_value(56, 32)
    @remote_discriminator.setter
    def remote_discriminator(self, value):
        self._set_field_value('field remote_discriminator', 56, 32, int, value)
    @property
    def tos(self):
        return self._get_field_value(48, 8)
    @tos.setter
    def tos(self, value):
        self._set_field_value('field tos', 48, 8, int, value)
    @property
    def local_diag_code(self):
        return self._get_field_value(43, 5)
    @local_diag_code.setter
    def local_diag_code(self, value):
        self._set_field_value('field local_diag_code', 43, 5, int, value)
    @property
    def requires_inject_up(self):
        return self._get_field_value(42, 1)
    @requires_inject_up.setter
    def requires_inject_up(self, value):
        self._set_field_value('field requires_inject_up', 42, 1, int, value)
    @property
    def session_type(self):
        return self._get_field_value(40, 2)
    @session_type.setter
    def session_type(self, value):
        self._set_field_value('field session_type', 40, 2, int, value)
    @property
    def prot_shared(self):
        return npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @prot_shared.setter
    def prot_shared(self, value):
        self._set_field_value('field prot_shared', 0, 40, npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t, value)



class npl_bfd_em_lookup_t(basic_npl_struct):
    def __init__(self, encap_result=0, meter=0, destination=0, punt_encap_data=0):
        super().__init__(44)
        self.encap_result = encap_result
        self.meter = meter
        self.destination = destination
        self.punt_encap_data = punt_encap_data

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_em_lookup_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def encap_result(self):
        return self._get_field_value(43, 1)
    @encap_result.setter
    def encap_result(self, value):
        self._set_field_value('field encap_result', 43, 1, int, value)
    @property
    def meter(self):
        return self._get_field_value(36, 4)
    @meter.setter
    def meter(self, value):
        self._set_field_value('field meter', 36, 4, int, value)
    @property
    def destination(self):
        return self._get_field_value(16, 20)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 16, 20, int, value)
    @property
    def punt_encap_data(self):
        return npl_punt_encap_data_lsb_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_encap_data.setter
    def punt_encap_data(self, value):
        self._set_field_value('field punt_encap_data', 0, 16, npl_punt_encap_data_lsb_t, value)



class npl_bfd_flags_state_t(basic_npl_struct):
    def __init__(self, state=0, bfd_flags=0):
        super().__init__(8)
        self.state = state
        self.bfd_flags = bfd_flags

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_flags_state_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def state(self):
        return self._get_field_value(6, 2)
    @state.setter
    def state(self, value):
        self._set_field_value('field state', 6, 2, int, value)
    @property
    def bfd_flags(self):
        return npl_bfd_flags_state_t_anonymous_union_bfd_flags_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @bfd_flags.setter
    def bfd_flags(self, value):
        self._set_field_value('field bfd_flags', 0, 6, npl_bfd_flags_state_t_anonymous_union_bfd_flags_t, value)



class npl_bfd_remote_session_attributes_t(basic_npl_struct):
    def __init__(self, last_time=0, remote_info=0, rmep_profile=0, rmep_valid=0):
        super().__init__(48)
        self.last_time = last_time
        self.remote_info = remote_info
        self.rmep_profile = rmep_profile
        self.rmep_valid = rmep_valid

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_remote_session_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def last_time(self):
        return self._get_field_value(16, 32)
    @last_time.setter
    def last_time(self, value):
        self._set_field_value('field last_time', 16, 32, int, value)
    @property
    def remote_info(self):
        return npl_bfd_flags_state_t._get_as_sub_field(self._data, self._offset_in_data + 5)
    @remote_info.setter
    def remote_info(self, value):
        self._set_field_value('field remote_info', 5, 8, npl_bfd_flags_state_t, value)
    @property
    def rmep_profile(self):
        return self._get_field_value(1, 4)
    @rmep_profile.setter
    def rmep_profile(self, value):
        self._set_field_value('field rmep_profile', 1, 4, int, value)
    @property
    def rmep_valid(self):
        return self._get_field_value(0, 1)
    @rmep_valid.setter
    def rmep_valid(self, value):
        self._set_field_value('field rmep_valid', 0, 1, int, value)



class npl_common_cntr_offset_and_padding_t(basic_npl_struct):
    def __init__(self, cntr_offset=0):
        super().__init__(3)
        self.cntr_offset = cntr_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_common_cntr_offset_and_padding_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def cntr_offset(self):
        return npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @cntr_offset.setter
    def cntr_offset(self, value):
        self._set_field_value('field cntr_offset', 0, 3, npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t, value)



class npl_common_cntr_offset_packed_t(basic_npl_struct):
    def __init__(self, cntr_offset=0):
        super().__init__(3)
        self.cntr_offset = cntr_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_common_cntr_offset_packed_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def cntr_offset(self):
        return npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @cntr_offset.setter
    def cntr_offset(self, value):
        self._set_field_value('field cntr_offset', 0, 3, npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t, value)



class npl_destination_prefix_lp_t(basic_npl_struct):
    def __init__(self, prefix=0, lsbs=0, msbs=0):
        super().__init__(20)
        self.prefix = prefix
        self.lsbs = lsbs
        self.msbs = msbs

    def _get_as_sub_field(data, offset_in_data):
        result = npl_destination_prefix_lp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def prefix(self):
        return self._get_field_value(16, 4)
    @prefix.setter
    def prefix(self, value):
        self._set_field_value('field prefix', 16, 4, int, value)
    @property
    def lsbs(self):
        return npl_l3_dlp_lsbs_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @lsbs.setter
    def lsbs(self, value):
        self._set_field_value('field lsbs', 4, 12, npl_l3_dlp_lsbs_t, value)
    @property
    def msbs(self):
        return npl_l3_dlp_msbs_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @msbs.setter
    def msbs(self, value):
        self._set_field_value('field msbs', 2, 2, npl_l3_dlp_msbs_t, value)



class npl_dlp_attributes_t(basic_npl_struct):
    def __init__(self, acl_drop_offset=0, lp_profile=0, port_mirror_type=0):
        super().__init__(6)
        self.acl_drop_offset = acl_drop_offset
        self.lp_profile = lp_profile
        self.port_mirror_type = port_mirror_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_dlp_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def acl_drop_offset(self):
        return npl_common_cntr_offset_packed_t._get_as_sub_field(self._data, self._offset_in_data + 3)
    @acl_drop_offset.setter
    def acl_drop_offset(self, value):
        self._set_field_value('field acl_drop_offset', 3, 3, npl_common_cntr_offset_packed_t, value)
    @property
    def lp_profile(self):
        return self._get_field_value(1, 2)
    @lp_profile.setter
    def lp_profile(self, value):
        self._set_field_value('field lp_profile', 1, 2, int, value)
    @property
    def port_mirror_type(self):
        return self._get_field_value(0, 1)
    @port_mirror_type.setter
    def port_mirror_type(self, value):
        self._set_field_value('field port_mirror_type', 0, 1, int, value)



class npl_dlp_profile_union_t(basic_npl_struct):
    def __init__(self):
        super().__init__(8)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_dlp_profile_union_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def data(self):
        return self._get_field_value(0, 8)
    @data.setter
    def data(self, value):
        self._set_field_value('field data', 0, 8, int, value)
    @property
    def overload_union_user_app_data_defined(self):
        return npl_overload_union_dlp_profile_union_t_user_app_data_defined_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @overload_union_user_app_data_defined.setter
    def overload_union_user_app_data_defined(self, value):
        self._set_field_value('field overload_union_user_app_data_defined', 0, 8, npl_overload_union_dlp_profile_union_t_user_app_data_defined_t, value)



class npl_egress_ipv6_acl_result_t(basic_npl_struct):
    def __init__(self, sec=0):
        super().__init__(24)
        self.sec = sec

    def _get_as_sub_field(data, offset_in_data):
        result = npl_egress_ipv6_acl_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def sec(self):
        return npl_egress_sec_acl_result_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @sec.setter
    def sec(self, value):
        self._set_field_value('field sec', 0, 24, npl_egress_sec_acl_result_t, value)



class npl_egress_qos_result_t(basic_npl_struct):
    def __init__(self, fwd_remark_exp=0, remark_l2=0, remark_l3=0, q_offset=0, fwd_remark_dscp=0, encap=0):
        super().__init__(30)
        self.fwd_remark_exp = fwd_remark_exp
        self.remark_l2 = remark_l2
        self.remark_l3 = remark_l3
        self.q_offset = q_offset
        self.fwd_remark_dscp = fwd_remark_dscp
        self.encap = encap

    def _get_as_sub_field(data, offset_in_data):
        result = npl_egress_qos_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def fwd_remark_exp(self):
        return self._get_field_value(27, 3)
    @fwd_remark_exp.setter
    def fwd_remark_exp(self, value):
        self._set_field_value('field fwd_remark_exp', 27, 3, int, value)
    @property
    def remark_l2(self):
        return self._get_field_value(26, 1)
    @remark_l2.setter
    def remark_l2(self, value):
        self._set_field_value('field remark_l2', 26, 1, int, value)
    @property
    def remark_l3(self):
        return npl_egress_qos_result_t_anonymous_union_remark_l3_t._get_as_sub_field(self._data, self._offset_in_data + 25)
    @remark_l3.setter
    def remark_l3(self, value):
        self._set_field_value('field remark_l3', 25, 1, npl_egress_qos_result_t_anonymous_union_remark_l3_t, value)
    @property
    def q_offset(self):
        return npl_common_cntr_offset_and_padding_t._get_as_sub_field(self._data, self._offset_in_data + 22)
    @q_offset.setter
    def q_offset(self, value):
        self._set_field_value('field q_offset', 22, 3, npl_common_cntr_offset_and_padding_t, value)
    @property
    def fwd_remark_dscp(self):
        return self._get_field_value(16, 6)
    @fwd_remark_dscp.setter
    def fwd_remark_dscp(self, value):
        self._set_field_value('field fwd_remark_dscp', 16, 6, int, value)
    @property
    def encap(self):
        return npl_qos_encap_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @encap.setter
    def encap(self, value):
        self._set_field_value('field encap', 0, 16, npl_qos_encap_t, value)



class npl_em_destination_t(basic_npl_struct):
    def __init__(self, em_rpf_src=0, dest=0):
        super().__init__(62)
        self.em_rpf_src = em_rpf_src
        self.dest = dest

    def _get_as_sub_field(data, offset_in_data):
        result = npl_em_destination_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def em_rpf_src(self):
        return npl_destination_prefix_lp_t._get_as_sub_field(self._data, self._offset_in_data + 22)
    @em_rpf_src.setter
    def em_rpf_src(self, value):
        self._set_field_value('field em_rpf_src', 22, 20, npl_destination_prefix_lp_t, value)
    @property
    def dest(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dest.setter
    def dest(self, value):
        self._set_field_value('field dest', 0, 20, npl_destination_t, value)



class npl_ene_inject_down_header_t(basic_npl_struct):
    def __init__(self, ene_inject_down_payload=0):
        super().__init__(28)
        self.ene_inject_down_payload = ene_inject_down_payload

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ene_inject_down_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ene_inject_down_payload(self):
        return npl_ene_inject_down_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ene_inject_down_payload.setter
    def ene_inject_down_payload(self, value):
        self._set_field_value('field ene_inject_down_payload', 0, 28, npl_ene_inject_down_payload_t, value)



class npl_ene_punt_sub_code_and_dsp_and_ssp_t(basic_npl_struct):
    def __init__(self, ene_punt_sub_code=0, ene_punt_dsp_and_ssp=0):
        super().__init__(40)
        self.ene_punt_sub_code = ene_punt_sub_code
        self.ene_punt_dsp_and_ssp = ene_punt_dsp_and_ssp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ene_punt_sub_code_and_dsp_and_ssp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ene_punt_sub_code(self):
        return npl_punt_sub_code_t._get_as_sub_field(self._data, self._offset_in_data + 32)
    @ene_punt_sub_code.setter
    def ene_punt_sub_code(self, value):
        self._set_field_value('field ene_punt_sub_code', 32, 4, npl_punt_sub_code_t, value)
    @property
    def ene_punt_dsp_and_ssp(self):
        return npl_ene_punt_dsp_and_ssp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ene_punt_dsp_and_ssp.setter
    def ene_punt_dsp_and_ssp(self, value):
        self._set_field_value('field ene_punt_dsp_and_ssp', 0, 32, npl_ene_punt_dsp_and_ssp_t, value)



class npl_ethernet_header_t(basic_npl_struct):
    def __init__(self, mac_addr=0, ether_type_or_tpid=0):
        super().__init__(112)
        self.mac_addr = mac_addr
        self.ether_type_or_tpid = ether_type_or_tpid

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ethernet_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mac_addr(self):
        return npl_ethernet_mac_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @mac_addr.setter
    def mac_addr(self, value):
        self._set_field_value('field mac_addr', 16, 96, npl_ethernet_mac_t, value)
    @property
    def ether_type_or_tpid(self):
        return self._get_field_value(0, 16)
    @ether_type_or_tpid.setter
    def ether_type_or_tpid(self, value):
        self._set_field_value('field ether_type_or_tpid', 0, 16, int, value)



class npl_fi_core_tcam_assoc_data_t(basic_npl_struct):
    def __init__(self, next_macro=0, last_macro=0, start_new_header=0, start_new_layer=0, advance_data=0, tcam_mask_alu_header_format=0, tcam_mask_alu_header_size=0, tcam_mask_hw_logic_advance_data=0, tcam_mask_hw_logic_last_macro=0, tcam_mask_hw_logic_header_format=0, tcam_mask_hw_logic_header_size=0, header_format=0, header_size=0):
        super().__init__(54)
        self.next_macro = next_macro
        self.last_macro = last_macro
        self.start_new_header = start_new_header
        self.start_new_layer = start_new_layer
        self.advance_data = advance_data
        self.tcam_mask_alu_header_format = tcam_mask_alu_header_format
        self.tcam_mask_alu_header_size = tcam_mask_alu_header_size
        self.tcam_mask_hw_logic_advance_data = tcam_mask_hw_logic_advance_data
        self.tcam_mask_hw_logic_last_macro = tcam_mask_hw_logic_last_macro
        self.tcam_mask_hw_logic_header_format = tcam_mask_hw_logic_header_format
        self.tcam_mask_hw_logic_header_size = tcam_mask_hw_logic_header_size
        self.header_format = header_format
        self.header_size = header_size

    def _get_as_sub_field(data, offset_in_data):
        result = npl_fi_core_tcam_assoc_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def next_macro(self):
        return self._get_field_value(48, 6)
    @next_macro.setter
    def next_macro(self, value):
        self._set_field_value('field next_macro', 48, 6, int, value)
    @property
    def last_macro(self):
        return self._get_field_value(47, 1)
    @last_macro.setter
    def last_macro(self, value):
        self._set_field_value('field last_macro', 47, 1, int, value)
    @property
    def start_new_header(self):
        return self._get_field_value(46, 1)
    @start_new_header.setter
    def start_new_header(self, value):
        self._set_field_value('field start_new_header', 46, 1, int, value)
    @property
    def start_new_layer(self):
        return self._get_field_value(45, 1)
    @start_new_layer.setter
    def start_new_layer(self, value):
        self._set_field_value('field start_new_layer', 45, 1, int, value)
    @property
    def advance_data(self):
        return self._get_field_value(44, 1)
    @advance_data.setter
    def advance_data(self, value):
        self._set_field_value('field advance_data', 44, 1, int, value)
    @property
    def tcam_mask_alu_header_format(self):
        return npl_header_format_t._get_as_sub_field(self._data, self._offset_in_data + 36)
    @tcam_mask_alu_header_format.setter
    def tcam_mask_alu_header_format(self, value):
        self._set_field_value('field tcam_mask_alu_header_format', 36, 8, npl_header_format_t, value)
    @property
    def tcam_mask_alu_header_size(self):
        return self._get_field_value(30, 6)
    @tcam_mask_alu_header_size.setter
    def tcam_mask_alu_header_size(self, value):
        self._set_field_value('field tcam_mask_alu_header_size', 30, 6, int, value)
    @property
    def tcam_mask_hw_logic_advance_data(self):
        return self._get_field_value(29, 1)
    @tcam_mask_hw_logic_advance_data.setter
    def tcam_mask_hw_logic_advance_data(self, value):
        self._set_field_value('field tcam_mask_hw_logic_advance_data', 29, 1, int, value)
    @property
    def tcam_mask_hw_logic_last_macro(self):
        return self._get_field_value(28, 1)
    @tcam_mask_hw_logic_last_macro.setter
    def tcam_mask_hw_logic_last_macro(self, value):
        self._set_field_value('field tcam_mask_hw_logic_last_macro', 28, 1, int, value)
    @property
    def tcam_mask_hw_logic_header_format(self):
        return npl_header_format_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @tcam_mask_hw_logic_header_format.setter
    def tcam_mask_hw_logic_header_format(self, value):
        self._set_field_value('field tcam_mask_hw_logic_header_format', 20, 8, npl_header_format_t, value)
    @property
    def tcam_mask_hw_logic_header_size(self):
        return self._get_field_value(14, 6)
    @tcam_mask_hw_logic_header_size.setter
    def tcam_mask_hw_logic_header_size(self, value):
        self._set_field_value('field tcam_mask_hw_logic_header_size', 14, 6, int, value)
    @property
    def header_format(self):
        return npl_header_format_t._get_as_sub_field(self._data, self._offset_in_data + 6)
    @header_format.setter
    def header_format(self, value):
        self._set_field_value('field header_format', 6, 8, npl_header_format_t, value)
    @property
    def header_size(self):
        return self._get_field_value(0, 6)
    @header_size.setter
    def header_size(self, value):
        self._set_field_value('field header_size', 0, 6, int, value)



class npl_ingress_lpts_og_app_config_t(basic_npl_struct):
    def __init__(self, app_data=0, src=0):
        super().__init__(14)
        self.app_data = app_data
        self.src = src

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ingress_lpts_og_app_config_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def app_data(self):
        return npl_ingress_lpts_og_app_data_t._get_as_sub_field(self._data, self._offset_in_data + 9)
    @app_data.setter
    def app_data(self, value):
        self._set_field_value('field app_data', 9, 5, npl_ingress_lpts_og_app_data_t, value)
    @property
    def src(self):
        return npl_og_pcl_config_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @src.setter
    def src(self, value):
        self._set_field_value('field src', 0, 9, npl_og_pcl_config_t, value)



class npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t(basic_npl_struct):
    def __init__(self):
        super().__init__(5)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def q_m_offset_5bits(self):
        return npl_common_cntr_5bits_offset_and_padding_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @q_m_offset_5bits.setter
    def q_m_offset_5bits(self, value):
        self._set_field_value('field q_m_offset_5bits', 0, 5, npl_common_cntr_5bits_offset_and_padding_t, value)
    @property
    def q_m_offset(self):
        return npl_common_cntr_offset_packed_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @q_m_offset.setter
    def q_m_offset(self, value):
        self._set_field_value('field q_m_offset', 0, 3, npl_common_cntr_offset_packed_t, value)



class npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t(basic_npl_struct):
    def __init__(self):
        super().__init__(5)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def q_m_offset_5bits(self):
        return npl_common_cntr_5bits_offset_and_padding_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @q_m_offset_5bits.setter
    def q_m_offset_5bits(self, value):
        self._set_field_value('field q_m_offset_5bits', 0, 5, npl_common_cntr_5bits_offset_and_padding_t, value)
    @property
    def q_m_offset(self):
        return npl_common_cntr_offset_packed_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @q_m_offset.setter
    def q_m_offset(self, value):
        self._set_field_value('field q_m_offset', 0, 3, npl_common_cntr_offset_packed_t, value)



class npl_initial_pd_nw_rx_data_t(basic_npl_struct):
    def __init__(self, init_data=0, initial_mapping_type=0, initial_is_rcy_if=0, pfc_enable=0, initial_mac_lp_type=0, initial_lp_type=0, initial_vlan_profile=0, mapping_key=0):
        super().__init__(48)
        self.init_data = init_data
        self.initial_mapping_type = initial_mapping_type
        self.initial_is_rcy_if = initial_is_rcy_if
        self.pfc_enable = pfc_enable
        self.initial_mac_lp_type = initial_mac_lp_type
        self.initial_lp_type = initial_lp_type
        self.initial_vlan_profile = initial_vlan_profile
        self.mapping_key = mapping_key

    def _get_as_sub_field(data, offset_in_data):
        result = npl_initial_pd_nw_rx_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def init_data(self):
        return npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t._get_as_sub_field(self._data, self._offset_in_data + 40)
    @init_data.setter
    def init_data(self, value):
        self._set_field_value('field init_data', 40, 8, npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t, value)
    @property
    def initial_mapping_type(self):
        return self._get_field_value(36, 4)
    @initial_mapping_type.setter
    def initial_mapping_type(self, value):
        self._set_field_value('field initial_mapping_type', 36, 4, int, value)
    @property
    def initial_is_rcy_if(self):
        return self._get_field_value(34, 1)
    @initial_is_rcy_if.setter
    def initial_is_rcy_if(self, value):
        self._set_field_value('field initial_is_rcy_if', 34, 1, int, value)
    @property
    def pfc_enable(self):
        return self._get_field_value(33, 1)
    @pfc_enable.setter
    def pfc_enable(self, value):
        self._set_field_value('field pfc_enable', 33, 1, int, value)
    @property
    def initial_mac_lp_type(self):
        return self._get_field_value(32, 1)
    @initial_mac_lp_type.setter
    def initial_mac_lp_type(self, value):
        self._set_field_value('field initial_mac_lp_type', 32, 1, int, value)
    @property
    def initial_lp_type(self):
        return self._get_field_value(28, 4)
    @initial_lp_type.setter
    def initial_lp_type(self, value):
        self._set_field_value('field initial_lp_type', 28, 4, int, value)
    @property
    def initial_vlan_profile(self):
        return self._get_field_value(24, 4)
    @initial_vlan_profile.setter
    def initial_vlan_profile(self, value):
        self._set_field_value('field initial_vlan_profile', 24, 4, int, value)
    @property
    def mapping_key(self):
        return npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @mapping_key.setter
    def mapping_key(self, value):
        self._set_field_value('field mapping_key', 4, 20, npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t, value)



class npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t(basic_npl_struct):
    def __init__(self):
        super().__init__(24)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def time_and_cntr_stamp_cmd(self):
        return npl_inject_ts_and_lm_cmd_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @time_and_cntr_stamp_cmd.setter
    def time_and_cntr_stamp_cmd(self, value):
        self._set_field_value('field time_and_cntr_stamp_cmd', 0, 24, npl_inject_ts_and_lm_cmd_t, value)



class npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t(basic_npl_struct):
    def __init__(self):
        super().__init__(28)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inject_down(self):
        return npl_inject_down_header_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @inject_down.setter
    def inject_down(self, value):
        self._set_field_value('field inject_down', 0, 28, npl_inject_down_header_t, value)
    @property
    def ene_inject_down(self):
        return npl_ene_inject_down_header_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ene_inject_down.setter
    def ene_inject_down(self, value):
        self._set_field_value('field ene_inject_down', 0, 28, npl_ene_inject_down_header_t, value)



class npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t(basic_npl_struct):
    def __init__(self):
        super().__init__(24)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inject_up_qos(self):
        return npl_inject_up_eth_qos_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @inject_up_qos.setter
    def inject_up_qos(self, value):
        self._set_field_value('field inject_up_qos', 0, 24, npl_inject_up_eth_qos_t, value)
    @property
    def inject_up_dest(self):
        return npl_inject_up_destination_override_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @inject_up_dest.setter
    def inject_up_dest(self, value):
        self._set_field_value('field inject_up_dest', 0, 24, npl_inject_up_destination_override_t, value)



class npl_ip_encap_data_t_anonymous_union_ip_t(basic_npl_struct):
    def __init__(self):
        super().__init__(80)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_encap_data_t_anonymous_union_ip_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def v4(self):
        return npl_ipv4_encap_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @v4.setter
    def v4(self, value):
        self._set_field_value('field v4', 0, 80, npl_ipv4_encap_data_t, value)
    @property
    def v6(self):
        return npl_ipv6_encap_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @v6.setter
    def v6(self, value):
        self._set_field_value('field v6', 0, 80, npl_ipv6_encap_data_t, value)



class npl_ive_profile_and_data_t(basic_npl_struct):
    def __init__(self, main_type=0, secondary_type_or_vid_2=0, prf=0, vid1=0):
        super().__init__(28)
        self.main_type = main_type
        self.secondary_type_or_vid_2 = secondary_type_or_vid_2
        self.prf = prf
        self.vid1 = vid1

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ive_profile_and_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def main_type(self):
        return self._get_field_value(26, 2)
    @main_type.setter
    def main_type(self, value):
        self._set_field_value('field main_type', 26, 2, int, value)
    @property
    def secondary_type_or_vid_2(self):
        return npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t._get_as_sub_field(self._data, self._offset_in_data + 14)
    @secondary_type_or_vid_2.setter
    def secondary_type_or_vid_2(self, value):
        self._set_field_value('field secondary_type_or_vid_2', 14, 12, npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t, value)
    @property
    def prf(self):
        return self._get_field_value(12, 2)
    @prf.setter
    def prf(self, value):
        self._set_field_value('field prf', 12, 2, int, value)
    @property
    def vid1(self):
        return self._get_field_value(0, 12)
    @vid1.setter
    def vid1(self, value):
        self._set_field_value('field vid1', 0, 12, int, value)



class npl_l2_relay_id_or_l3_attr_t(basic_npl_struct):
    def __init__(self):
        super().__init__(14)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_relay_id_or_l3_attr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def relay_id(self):
        return npl_l2_relay_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @relay_id.setter
    def relay_id(self, value):
        self._set_field_value('field relay_id', 0, 14, npl_l2_relay_id_t, value)
    @property
    def l3_lp_additional_attributes(self):
        return npl_l3_lp_additional_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_lp_additional_attributes.setter
    def l3_lp_additional_attributes(self, value):
        self._set_field_value('field l3_lp_additional_attributes', 0, 9, npl_l3_lp_additional_attributes_t, value)
    @property
    def l2_vpn_pwe_id(self):
        return self._get_field_value(0, 14)
    @l2_vpn_pwe_id.setter
    def l2_vpn_pwe_id(self, value):
        self._set_field_value('field l2_vpn_pwe_id', 0, 14, int, value)



class npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t(basic_npl_struct):
    def __init__(self):
        super().__init__(72)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_dlp_encap(self):
        return npl_l3_dlp_encap_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_dlp_encap.setter
    def l3_dlp_encap(self, value):
        self._set_field_value('field l3_dlp_encap', 0, 72, npl_l3_dlp_encap_t, value)
    @property
    def ldp_over_te_tunnel_data(self):
        return npl_ldp_over_te_tunnel_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ldp_over_te_tunnel_data.setter
    def ldp_over_te_tunnel_data(self, value):
        self._set_field_value('field ldp_over_te_tunnel_data', 0, 62, npl_ldp_over_te_tunnel_data_t, value)



class npl_l3_dlp_id_t(basic_npl_struct):
    def __init__(self, msbs=0, lsbs=0):
        super().__init__(14)
        self.msbs = msbs
        self.lsbs = lsbs

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_dlp_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def msbs(self):
        return npl_l3_dlp_msbs_t._get_as_sub_field(self._data, self._offset_in_data + 12)
    @msbs.setter
    def msbs(self, value):
        self._set_field_value('field msbs', 12, 2, npl_l3_dlp_msbs_t, value)
    @property
    def lsbs(self):
        return npl_l3_dlp_lsbs_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @lsbs.setter
    def lsbs(self, value):
        self._set_field_value('field lsbs', 0, 12, npl_l3_dlp_lsbs_t, value)



class npl_l3_dlp_info_t(basic_npl_struct):
    def __init__(self, l3_ecn_ctrl=0, dlp_attributes=0):
        super().__init__(8)
        self.l3_ecn_ctrl = l3_ecn_ctrl
        self.dlp_attributes = dlp_attributes

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_dlp_info_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_ecn_ctrl(self):
        return npl_l3_ecn_ctrl_t._get_as_sub_field(self._data, self._offset_in_data + 6)
    @l3_ecn_ctrl.setter
    def l3_ecn_ctrl(self, value):
        self._set_field_value('field l3_ecn_ctrl', 6, 2, npl_l3_ecn_ctrl_t, value)
    @property
    def dlp_attributes(self):
        return npl_dlp_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dlp_attributes.setter
    def dlp_attributes(self, value):
        self._set_field_value('field dlp_attributes', 0, 6, npl_dlp_attributes_t, value)



class npl_l3_dlp_qos_and_attributes_t(basic_npl_struct):
    def __init__(self, l3_dlp_info=0, qos_attributes=0):
        super().__init__(54)
        self.l3_dlp_info = l3_dlp_info
        self.qos_attributes = qos_attributes

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_dlp_qos_and_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_dlp_info(self):
        return npl_l3_dlp_info_t._get_as_sub_field(self._data, self._offset_in_data + 46)
    @l3_dlp_info.setter
    def l3_dlp_info(self, value):
        self._set_field_value('field l3_dlp_info', 46, 8, npl_l3_dlp_info_t, value)
    @property
    def qos_attributes(self):
        return npl_qos_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @qos_attributes.setter
    def qos_attributes(self, value):
        self._set_field_value('field qos_attributes', 0, 46, npl_qos_attributes_t, value)



class npl_l3_dlp_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(14)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return npl_l3_dlp_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 14, npl_l3_dlp_id_t, value)



class npl_l3_slp_id_t(basic_npl_struct):
    def __init__(self, msbs=0, lsbs=0):
        super().__init__(14)
        self.msbs = msbs
        self.lsbs = lsbs

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_slp_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def msbs(self):
        return npl_l3_slp_msbs_t._get_as_sub_field(self._data, self._offset_in_data + 12)
    @msbs.setter
    def msbs(self, value):
        self._set_field_value('field msbs', 12, 2, npl_l3_slp_msbs_t, value)
    @property
    def lsbs(self):
        return npl_l3_slp_lsbs_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @lsbs.setter
    def lsbs(self, value):
        self._set_field_value('field lsbs', 0, 12, npl_l3_slp_lsbs_t, value)



class npl_label_or_more_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_label_or_more_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def label(self):
        return self._get_field_value(0, 20)
    @label.setter
    def label(self, value):
        self._set_field_value('field label', 0, 20, int, value)
    @property
    def more(self):
        return npl_more_labels_and_flags_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @more.setter
    def more(self, value):
        self._set_field_value('field more', 0, 20, npl_more_labels_and_flags_t, value)



class npl_lpts_tcam_first_result_encap_data_msb_t(basic_npl_struct):
    def __init__(self, encap_punt_code=0, ingress_punt_src=0, punt_sub_code=0):
        super().__init__(16)
        self.encap_punt_code = encap_punt_code
        self.ingress_punt_src = ingress_punt_src
        self.punt_sub_code = punt_sub_code

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lpts_tcam_first_result_encap_data_msb_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def encap_punt_code(self):
        return npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @encap_punt_code.setter
    def encap_punt_code(self, value):
        self._set_field_value('field encap_punt_code', 8, 8, npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t, value)
    @property
    def ingress_punt_src(self):
        return self._get_field_value(4, 4)
    @ingress_punt_src.setter
    def ingress_punt_src(self, value):
        self._set_field_value('field ingress_punt_src', 4, 4, int, value)
    @property
    def punt_sub_code(self):
        return npl_punt_sub_code_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_sub_code.setter
    def punt_sub_code(self, value):
        self._set_field_value('field punt_sub_code', 0, 4, npl_punt_sub_code_t, value)



class npl_lsp_labels_opt1_t(basic_npl_struct):
    def __init__(self, labels_0_1=0, label_2_or_more=0):
        super().__init__(60)
        self.labels_0_1 = labels_0_1
        self.label_2_or_more = label_2_or_more

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lsp_labels_opt1_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def labels_0_1(self):
        return npl_lsp_labels_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @labels_0_1.setter
    def labels_0_1(self, value):
        self._set_field_value('field labels_0_1', 20, 40, npl_lsp_labels_t, value)
    @property
    def label_2_or_more(self):
        return npl_label_or_more_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @label_2_or_more.setter
    def label_2_or_more(self, value):
        self._set_field_value('field label_2_or_more', 0, 20, npl_label_or_more_t, value)



class npl_mac_relay_attributes_inf_payload_t(basic_npl_struct):
    def __init__(self, l3_lp_additional_attributes=0, mac_l2_relay_attributes=0, l2_relay_id_or_l3_attr_u=0):
        super().__init__(57)
        self.l3_lp_additional_attributes = l3_lp_additional_attributes
        self.mac_l2_relay_attributes = mac_l2_relay_attributes
        self.l2_relay_id_or_l3_attr_u = l2_relay_id_or_l3_attr_u

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_relay_attributes_inf_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_lp_additional_attributes(self):
        return npl_l3_lp_additional_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 48)
    @l3_lp_additional_attributes.setter
    def l3_lp_additional_attributes(self, value):
        self._set_field_value('field l3_lp_additional_attributes', 48, 9, npl_l3_lp_additional_attributes_t, value)
    @property
    def mac_l2_relay_attributes(self):
        return npl_mac_l2_relay_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 14)
    @mac_l2_relay_attributes.setter
    def mac_l2_relay_attributes(self, value):
        self._set_field_value('field mac_l2_relay_attributes', 14, 34, npl_mac_l2_relay_attributes_t, value)
    @property
    def l2_relay_id_or_l3_attr_u(self):
        return npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_relay_id_or_l3_attr_u.setter
    def l2_relay_id_or_l3_attr_u(self, value):
        self._set_field_value('field l2_relay_id_or_l3_attr_u', 0, 14, npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t, value)



class npl_mac_relay_attributes_t(basic_npl_struct):
    def __init__(self, payload=0, l2_relay_id_or_l3_attr_u=0):
        super().__init__(48)
        self.payload = payload
        self.l2_relay_id_or_l3_attr_u = l2_relay_id_or_l3_attr_u

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_relay_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return npl_mac_l2_relay_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 14)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 14, 34, npl_mac_l2_relay_attributes_t, value)
    @property
    def l2_relay_id_or_l3_attr_u(self):
        return npl_l2_relay_id_or_l3_attr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_relay_id_or_l3_attr_u.setter
    def l2_relay_id_or_l3_attr_u(self, value):
        self._set_field_value('field l2_relay_id_or_l3_attr_u', 0, 14, npl_l2_relay_id_or_l3_attr_t, value)



class npl_mc_em_db_result_tx_t(basic_npl_struct):
    def __init__(self, format_0_or_1=0, format=0):
        super().__init__(72)
        self.format_0_or_1 = format_0_or_1
        self.format = format

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_em_db_result_tx_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def format_0_or_1(self):
        return npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t._get_as_sub_field(self._data, self._offset_in_data + 1)
    @format_0_or_1.setter
    def format_0_or_1(self, value):
        self._set_field_value('field format_0_or_1', 1, 71, npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t, value)
    @property
    def format(self):
        return self._get_field_value(0, 1)
    @format.setter
    def format(self, value):
        self._set_field_value('field format', 0, 1, int, value)



class npl_mmm_tm_header_padded_t(basic_npl_struct):
    def __init__(self, mmm_tm_header=0):
        super().__init__(24)
        self.mmm_tm_header = mmm_tm_header

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mmm_tm_header_padded_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mmm_tm_header(self):
        return npl_mmm_tm_header_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mmm_tm_header.setter
    def mmm_tm_header(self, value):
        self._set_field_value('field mmm_tm_header', 0, 24, npl_mmm_tm_header_t, value)



class npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t(basic_npl_struct):
    def __init__(self):
        super().__init__(16)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mldp_info(self):
        return npl_mpls_termination_mldp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mldp_info.setter
    def mldp_info(self, value):
        self._set_field_value('field mldp_info', 0, 16, npl_mpls_termination_mldp_t, value)
    @property
    def vpn_info(self):
        return npl_mpls_termination_l3vpn_uc_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @vpn_info.setter
    def vpn_info(self, value):
        self._set_field_value('field vpn_info', 0, 16, npl_mpls_termination_l3vpn_uc_t, value)



class npl_my_ipv4_table_payload_t(basic_npl_struct):
    def __init__(self, ip_termination_type=0, ip_tunnel_termination_attr_or_slp=0):
        super().__init__(18)
        self.ip_termination_type = ip_termination_type
        self.ip_tunnel_termination_attr_or_slp = ip_tunnel_termination_attr_or_slp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_my_ipv4_table_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ip_termination_type(self):
        return self._get_field_value(16, 2)
    @ip_termination_type.setter
    def ip_termination_type(self, value):
        self._set_field_value('field ip_termination_type', 16, 2, int, value)
    @property
    def ip_tunnel_termination_attr_or_slp(self):
        return npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ip_tunnel_termination_attr_or_slp.setter
    def ip_tunnel_termination_attr_or_slp(self, value):
        self._set_field_value('field ip_tunnel_termination_attr_or_slp', 0, 16, npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t, value)



class npl_nh_payload_t(basic_npl_struct):
    def __init__(self, eve_vid1=0, l2_port=0, l2_flood=0, l3_sa_vlan_or_l2_dlp_attr=0):
        super().__init__(68)
        self.eve_vid1 = eve_vid1
        self.l2_port = l2_port
        self.l2_flood = l2_flood
        self.l3_sa_vlan_or_l2_dlp_attr = l3_sa_vlan_or_l2_dlp_attr

    def _get_as_sub_field(data, offset_in_data):
        result = npl_nh_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def eve_vid1(self):
        return self._get_field_value(56, 12)
    @eve_vid1.setter
    def eve_vid1(self, value):
        self._set_field_value('field eve_vid1', 56, 12, int, value)
    @property
    def l2_port(self):
        return self._get_field_value(55, 1)
    @l2_port.setter
    def l2_port(self, value):
        self._set_field_value('field l2_port', 55, 1, int, value)
    @property
    def l2_flood(self):
        return self._get_field_value(54, 1)
    @l2_flood.setter
    def l2_flood(self, value):
        self._set_field_value('field l2_flood', 54, 1, int, value)
    @property
    def l3_sa_vlan_or_l2_dlp_attr(self):
        return npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_sa_vlan_or_l2_dlp_attr.setter
    def l3_sa_vlan_or_l2_dlp_attr(self, value):
        self._set_field_value('field l3_sa_vlan_or_l2_dlp_attr', 0, 54, npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t, value)



class npl_npu_encap_header_l3_dlp_t(basic_npl_struct):
    def __init__(self, l3_dlp_id=0, properties=0):
        super().__init__(16)
        self.l3_dlp_id = l3_dlp_id
        self.properties = properties

    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_encap_header_l3_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_dlp_id(self):
        return npl_l3_dlp_lsbs_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @l3_dlp_id.setter
    def l3_dlp_id(self, value):
        self._set_field_value('field l3_dlp_id', 4, 12, npl_l3_dlp_lsbs_t, value)
    @property
    def properties(self):
        return npl_properties_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @properties.setter
    def properties(self, value):
        self._set_field_value('field properties', 0, 4, npl_properties_t, value)



class npl_npu_ip_collapsed_mc_encap_header_t(basic_npl_struct):
    def __init__(self, collapsed_mc_encap_type=0, l3_dlp=0, punt=0, resolve_local_mcid=0, l2_dlp=0):
        super().__init__(40)
        self.collapsed_mc_encap_type = collapsed_mc_encap_type
        self.l3_dlp = l3_dlp
        self.punt = punt
        self.resolve_local_mcid = resolve_local_mcid
        self.l2_dlp = l2_dlp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_ip_collapsed_mc_encap_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def collapsed_mc_encap_type(self):
        return self._get_field_value(36, 4)
    @collapsed_mc_encap_type.setter
    def collapsed_mc_encap_type(self, value):
        self._set_field_value('field collapsed_mc_encap_type', 36, 4, int, value)
    @property
    def l3_dlp(self):
        return npl_npu_encap_header_l3_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @l3_dlp.setter
    def l3_dlp(self, value):
        self._set_field_value('field l3_dlp', 20, 16, npl_npu_encap_header_l3_dlp_t, value)
    @property
    def punt(self):
        return npl_bool_t._get_as_sub_field(self._data, self._offset_in_data + 19)
    @punt.setter
    def punt(self, value):
        self._set_field_value('field punt', 19, 1, npl_bool_t, value)
    @property
    def resolve_local_mcid(self):
        return npl_bool_t._get_as_sub_field(self._data, self._offset_in_data + 18)
    @resolve_local_mcid.setter
    def resolve_local_mcid(self, value):
        self._set_field_value('field resolve_local_mcid', 18, 1, npl_bool_t, value)
    @property
    def l2_dlp(self):
        return npl_l2_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_dlp.setter
    def l2_dlp(self, value):
        self._set_field_value('field l2_dlp', 0, 18, npl_l2_dlp_t, value)



class npl_npu_l3_common_dlp_nh_encap_t(basic_npl_struct):
    def __init__(self, l3_dlp=0, nh=0):
        super().__init__(28)
        self.l3_dlp = l3_dlp
        self.nh = nh

    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_l3_common_dlp_nh_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_dlp(self):
        return npl_npu_encap_header_l3_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 12)
    @l3_dlp.setter
    def l3_dlp(self, value):
        self._set_field_value('field l3_dlp', 12, 16, npl_npu_encap_header_l3_dlp_t, value)
    @property
    def nh(self):
        return self._get_field_value(0, 12)
    @nh.setter
    def nh(self, value):
        self._set_field_value('field nh', 0, 12, int, value)



class npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t(basic_npl_struct):
    def __init__(self):
        super().__init__(28)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def npu_l3_common_dlp_nh_encap(self):
        return npl_npu_l3_common_dlp_nh_encap_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @npu_l3_common_dlp_nh_encap.setter
    def npu_l3_common_dlp_nh_encap(self, value):
        self._set_field_value('field npu_l3_common_dlp_nh_encap', 0, 28, npl_npu_l3_common_dlp_nh_encap_t, value)
    @property
    def npu_l3_mc_accounting_encap_data(self):
        return npl_npu_l3_mc_accounting_encap_data_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @npu_l3_mc_accounting_encap_data.setter
    def npu_l3_mc_accounting_encap_data(self, value):
        self._set_field_value('field npu_l3_mc_accounting_encap_data', 8, 20, npl_npu_l3_mc_accounting_encap_data_t, value)



class npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t(basic_npl_struct):
    def __init__(self):
        super().__init__(48)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def tunnel_headend(self):
        return npl_tunnel_headend_encap_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @tunnel_headend.setter
    def tunnel_headend(self, value):
        self._set_field_value('field tunnel_headend', 2, 46, npl_tunnel_headend_encap_t, value)
    @property
    def lsr(self):
        return npl_lsr_encap_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @lsr.setter
    def lsr(self, value):
        self._set_field_value('field lsr', 2, 46, npl_lsr_encap_t, value)
    @property
    def vxlan(self):
        return npl_l3_vxlan_encap_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @vxlan.setter
    def vxlan(self, value):
        self._set_field_value('field vxlan', 16, 32, npl_l3_vxlan_encap_t, value)
    @property
    def gre_tunnel_dlp(self):
        return self._get_field_value(32, 16)
    @gre_tunnel_dlp.setter
    def gre_tunnel_dlp(self, value):
        self._set_field_value('field gre_tunnel_dlp', 32, 16, int, value)
    @property
    def npu_pif_ifg(self):
        return npl_npu_dsp_pif_ifg_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @npu_pif_ifg.setter
    def npu_pif_ifg(self, value):
        self._set_field_value('field npu_pif_ifg', 0, 8, npl_npu_dsp_pif_ifg_t, value)



class npl_og_em_lpm_result_t(basic_npl_struct):
    def __init__(self, lpm_code_or_dest=0, result_type=0, no_hbm_access=0, is_default_unused=0):
        super().__init__(24)
        self.lpm_code_or_dest = lpm_code_or_dest
        self.result_type = result_type
        self.no_hbm_access = no_hbm_access
        self.is_default_unused = is_default_unused

    def _get_as_sub_field(data, offset_in_data):
        result = npl_og_em_lpm_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lpm_code_or_dest(self):
        return npl_og_lpm_code_or_destination_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @lpm_code_or_dest.setter
    def lpm_code_or_dest(self, value):
        self._set_field_value('field lpm_code_or_dest', 4, 20, npl_og_lpm_code_or_destination_t, value)
    @property
    def result_type(self):
        return self._get_field_value(2, 2)
    @result_type.setter
    def result_type(self, value):
        self._set_field_value('field result_type', 2, 2, int, value)
    @property
    def no_hbm_access(self):
        return self._get_field_value(1, 1)
    @no_hbm_access.setter
    def no_hbm_access(self, value):
        self._set_field_value('field no_hbm_access', 1, 1, int, value)
    @property
    def is_default_unused(self):
        return self._get_field_value(0, 1)
    @is_default_unused.setter
    def is_default_unused(self, value):
        self._set_field_value('field is_default_unused', 0, 1, int, value)



class npl_og_em_result_t_anonymous_union_result_t(basic_npl_struct):
    def __init__(self):
        super().__init__(62)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_og_em_result_t_anonymous_union_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lpm_code_or_dest(self):
        return npl_og_lpm_code_or_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @lpm_code_or_dest.setter
    def lpm_code_or_dest(self, value):
        self._set_field_value('field lpm_code_or_dest', 0, 20, npl_og_lpm_code_or_destination_t, value)



class npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t(basic_npl_struct):
    def __init__(self):
        super().__init__(50)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def init_fields(self):
        return npl_initial_pd_nw_rx_data_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @init_fields.setter
    def init_fields(self, value):
        self._set_field_value('field init_fields', 2, 48, npl_initial_pd_nw_rx_data_t, value)



class npl_punt_if_sa_or_npu_host_data_t(basic_npl_struct):
    def __init__(self):
        super().__init__(48)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_if_sa_or_npu_host_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def punt_if_sa(self):
        return npl_mac_addr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_if_sa.setter
    def punt_if_sa(self, value):
        self._set_field_value('field punt_if_sa', 0, 48, npl_mac_addr_t, value)
    @property
    def punt_npu_host_data(self):
        return npl_punt_npu_host_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_npu_host_data.setter
    def punt_npu_host_data(self, value):
        self._set_field_value('field punt_npu_host_data', 0, 48, npl_punt_npu_host_data_t, value)



class npl_punt_lsb_encap_t(basic_npl_struct):
    def __init__(self, packet_fwd_header_type=0, punt_shared_lsb_encap=0):
        super().__init__(40)
        self.packet_fwd_header_type = packet_fwd_header_type
        self.punt_shared_lsb_encap = punt_shared_lsb_encap

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_lsb_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def packet_fwd_header_type(self):
        return self._get_field_value(36, 4)
    @packet_fwd_header_type.setter
    def packet_fwd_header_type(self, value):
        self._set_field_value('field packet_fwd_header_type', 36, 4, int, value)
    @property
    def punt_shared_lsb_encap(self):
        return npl_punt_shared_lsb_encap_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_shared_lsb_encap.setter
    def punt_shared_lsb_encap(self, value):
        self._set_field_value('field punt_shared_lsb_encap', 0, 32, npl_punt_shared_lsb_encap_t, value)



class npl_punt_padding_id_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(14)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_padding_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return npl_l3_dlp_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 14, npl_l3_dlp_id_t, value)



class npl_pwe_dlp_specific_t(basic_npl_struct):
    def __init__(self, eve=0, pwe_label=0, lp_set=0, pwe_fat=0, pwe_cw=0):
        super().__init__(52)
        self.eve = eve
        self.pwe_label = pwe_label
        self.lp_set = lp_set
        self.pwe_fat = pwe_fat
        self.pwe_cw = pwe_cw

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pwe_dlp_specific_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def eve(self):
        return npl_ive_profile_and_data_t._get_as_sub_field(self._data, self._offset_in_data + 24)
    @eve.setter
    def eve(self, value):
        self._set_field_value('field eve', 24, 28, npl_ive_profile_and_data_t, value)
    @property
    def pwe_label(self):
        return self._get_field_value(4, 20)
    @pwe_label.setter
    def pwe_label(self, value):
        self._set_field_value('field pwe_label', 4, 20, int, value)
    @property
    def lp_set(self):
        return self._get_field_value(2, 1)
    @lp_set.setter
    def lp_set(self, value):
        self._set_field_value('field lp_set', 2, 1, int, value)
    @property
    def pwe_fat(self):
        return self._get_field_value(1, 1)
    @pwe_fat.setter
    def pwe_fat(self, value):
        self._set_field_value('field pwe_fat', 1, 1, int, value)
    @property
    def pwe_cw(self):
        return self._get_field_value(0, 1)
    @pwe_cw.setter
    def pwe_cw(self, value):
        self._set_field_value('field pwe_cw', 0, 1, int, value)



class npl_qos_mapping_key_t(basic_npl_struct):
    def __init__(self, key_union=0):
        super().__init__(8)
        self.key_union = key_union

    def _get_as_sub_field(data, offset_in_data):
        result = npl_qos_mapping_key_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def key_union(self):
        return npl_qos_mapping_key_t_anonymous_union_key_union_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @key_union.setter
    def key_union(self, value):
        self._set_field_value('field key_union', 0, 8, npl_qos_mapping_key_t_anonymous_union_key_union_t, value)



class npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t(basic_npl_struct):
    def __init__(self):
        super().__init__(16)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rpf_id(self):
        return self._get_field_value(0, 16)
    @rpf_id.setter
    def rpf_id(self, value):
        self._set_field_value('field rpf_id', 0, 16, int, value)
    @property
    def lp(self):
        return npl_l3_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @lp.setter
    def lp(self, value):
        self._set_field_value('field lp', 0, 14, npl_l3_dlp_t, value)



class npl_rtf_payload_t_anonymous_union_rtf_result_profile_t(basic_npl_struct):
    def __init__(self):
        super().__init__(62)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_rtf_payload_t_anonymous_union_rtf_result_profile_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rtf_result_profile_0(self):
        return npl_rtf_result_profile_0_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @rtf_result_profile_0.setter
    def rtf_result_profile_0(self, value):
        self._set_field_value('field rtf_result_profile_0', 0, 62, npl_rtf_result_profile_0_t, value)
    @property
    def rtf_result_profile_1(self):
        return npl_rtf_result_profile_1_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @rtf_result_profile_1.setter
    def rtf_result_profile_1(self, value):
        self._set_field_value('field rtf_result_profile_1', 0, 62, npl_rtf_result_profile_1_t, value)
    @property
    def rtf_result_profile_2(self):
        return npl_rtf_result_profile_2_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @rtf_result_profile_2.setter
    def rtf_result_profile_2(self, value):
        self._set_field_value('field rtf_result_profile_2', 0, 62, npl_rtf_result_profile_2_t, value)
    @property
    def rtf_result_profile_3(self):
        return npl_rtf_result_profile_3_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @rtf_result_profile_3.setter
    def rtf_result_profile_3(self, value):
        self._set_field_value('field rtf_result_profile_3', 0, 62, npl_rtf_result_profile_3_t, value)



class npl_single_label_encap_data_t(basic_npl_struct):
    def __init__(self, udat=0, v6_label_encap=0):
        super().__init__(56)
        self.udat = udat
        self.v6_label_encap = v6_label_encap

    def _get_as_sub_field(data, offset_in_data):
        result = npl_single_label_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def udat(self):
        return npl_single_label_encap_data_t_anonymous_union_udat_t._get_as_sub_field(self._data, self._offset_in_data + 24)
    @udat.setter
    def udat(self, value):
        self._set_field_value('field udat', 24, 32, npl_single_label_encap_data_t_anonymous_union_udat_t, value)
    @property
    def v6_label_encap(self):
        return npl_exp_bos_and_label_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @v6_label_encap.setter
    def v6_label_encap(self, value):
        self._set_field_value('field v6_label_encap', 0, 24, npl_exp_bos_and_label_t, value)



class npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t(basic_npl_struct):
    def __init__(self):
        super().__init__(8)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def snoop_code(self):
        return self._get_field_value(0, 8)
    @snoop_code.setter
    def snoop_code(self, value):
        self._set_field_value('field snoop_code', 0, 8, int, value)
    @property
    def tx_to_rx_rcy_data(self):
        return npl_tx_to_rx_rcy_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @tx_to_rx_rcy_data.setter
    def tx_to_rx_rcy_data(self, value):
        self._set_field_value('field tx_to_rx_rcy_data', 0, 8, npl_tx_to_rx_rcy_data_t, value)



class npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t(basic_npl_struct):
    def __init__(self):
        super().__init__(14)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def svi_eve_sub_type_plus_pad_plus_prf(self):
        return npl_svi_eve_sub_type_plus_pad_plus_prf_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @svi_eve_sub_type_plus_pad_plus_prf.setter
    def svi_eve_sub_type_plus_pad_plus_prf(self, value):
        self._set_field_value('field svi_eve_sub_type_plus_pad_plus_prf', 0, 14, npl_svi_eve_sub_type_plus_pad_plus_prf_t, value)
    @property
    def svi_eve_vid2_plus_prf_t(self):
        return npl_svi_eve_vid2_plus_prf_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @svi_eve_vid2_plus_prf_t.setter
    def svi_eve_vid2_plus_prf_t(self, value):
        self._set_field_value('field svi_eve_vid2_plus_prf_t', 0, 14, npl_svi_eve_vid2_plus_prf_t, value)
    @property
    def vid2(self):
        return self._get_field_value(2, 12)
    @vid2.setter
    def vid2(self, value):
        self._set_field_value('field vid2', 2, 12, int, value)



class npl_term_l2_lp_attributes_t(basic_npl_struct):
    def __init__(self, enable_monitor=0, mip_exists=0, mep_exists=0, ive_profile_and_data=0, max_mep_level=0):
        super().__init__(34)
        self.enable_monitor = enable_monitor
        self.mip_exists = mip_exists
        self.mep_exists = mep_exists
        self.ive_profile_and_data = ive_profile_and_data
        self.max_mep_level = max_mep_level

    def _get_as_sub_field(data, offset_in_data):
        result = npl_term_l2_lp_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enable_monitor(self):
        return self._get_field_value(33, 1)
    @enable_monitor.setter
    def enable_monitor(self, value):
        self._set_field_value('field enable_monitor', 33, 1, int, value)
    @property
    def mip_exists(self):
        return self._get_field_value(32, 1)
    @mip_exists.setter
    def mip_exists(self, value):
        self._set_field_value('field mip_exists', 32, 1, int, value)
    @property
    def mep_exists(self):
        return self._get_field_value(31, 1)
    @mep_exists.setter
    def mep_exists(self, value):
        self._set_field_value('field mep_exists', 31, 1, int, value)
    @property
    def ive_profile_and_data(self):
        return npl_ive_profile_and_data_t._get_as_sub_field(self._data, self._offset_in_data + 3)
    @ive_profile_and_data.setter
    def ive_profile_and_data(self, value):
        self._set_field_value('field ive_profile_and_data', 3, 28, npl_ive_profile_and_data_t, value)
    @property
    def max_mep_level(self):
        return self._get_field_value(0, 3)
    @max_mep_level.setter
    def max_mep_level(self, value):
        self._set_field_value('field max_mep_level', 0, 3, int, value)



class npl_tm_headers_template_t_anonymous_union_u_t(basic_npl_struct):
    def __init__(self):
        super().__init__(48)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_tm_headers_template_t_anonymous_union_u_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def unicast_flb(self):
        return npl_unicast_flb_tm_header_padded_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @unicast_flb.setter
    def unicast_flb(self, value):
        self._set_field_value('field unicast_flb', 0, 24, npl_unicast_flb_tm_header_padded_t, value)
    @property
    def unicast_plb(self):
        return npl_unicast_plb_tm_header_padded_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @unicast_plb.setter
    def unicast_plb(self, value):
        self._set_field_value('field unicast_plb', 0, 32, npl_unicast_plb_tm_header_padded_t, value)
    @property
    def mmm(self):
        return npl_mmm_tm_header_padded_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mmm.setter
    def mmm(self, value):
        self._set_field_value('field mmm', 0, 24, npl_mmm_tm_header_padded_t, value)
    @property
    def mum(self):
        return npl_mum_tm_header_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mum.setter
    def mum(self, value):
        self._set_field_value('field mum', 0, 40, npl_mum_tm_header_t, value)



class npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t(basic_npl_struct):
    def __init__(self, ):
        super().__init__(64)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def congestion_mark(self):
        return basic_npl_array(16, 16, npl_quan_1b, self._data, self._offset_in_data + 48)
    @congestion_mark.setter
    def congestion_mark(self, value):
        field = basic_npl_array(16, 16, npl_quan_1b, self._data, self._offset_in_data + 48)
        field._set_field_value('field congestion_mark', 0, 16, basic_npl_array, value)
    @property
    def evict_to_dram(self):
        return basic_npl_array(16, 16, npl_quan_1b, self._data, self._offset_in_data + 32)
    @evict_to_dram.setter
    def evict_to_dram(self, value):
        field = basic_npl_array(16, 16, npl_quan_1b, self._data, self._offset_in_data + 32)
        field._set_field_value('field evict_to_dram', 0, 16, basic_npl_array, value)
    @property
    def drop_y(self):
        return npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @drop_y.setter
    def drop_y(self, value):
        self._set_field_value('field drop_y', 16, 16, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t, value)
    @property
    def drop_g(self):
        return npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @drop_g.setter
    def drop_g(self, value):
        self._set_field_value('field drop_g', 0, 16, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t, value)



class npl_vpn_label_encap_data_t(basic_npl_struct):
    def __init__(self):
        super().__init__(76)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_vpn_label_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def single_label_encap_data(self):
        return npl_single_label_encap_data_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @single_label_encap_data.setter
    def single_label_encap_data(self, value):
        self._set_field_value('field single_label_encap_data', 20, 56, npl_single_label_encap_data_t, value)
    @property
    def l2vpn_label_encap_data(self):
        return npl_l2vpn_label_encap_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2vpn_label_encap_data.setter
    def l2vpn_label_encap_data(self, value):
        self._set_field_value('field l2vpn_label_encap_data', 0, 76, npl_l2vpn_label_encap_data_t, value)



class npl_bfd_aux_payload_t(basic_npl_struct):
    def __init__(self, transmit=0, shared=0):
        super().__init__(160)
        self.transmit = transmit
        self.shared = shared

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_aux_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def transmit(self):
        return npl_bfd_aux_transmit_payload_t._get_as_sub_field(self._data, self._offset_in_data + 120)
    @transmit.setter
    def transmit(self, value):
        self._set_field_value('field transmit', 120, 40, npl_bfd_aux_transmit_payload_t, value)
    @property
    def shared(self):
        return npl_bfd_aux_shared_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @shared.setter
    def shared(self, value):
        self._set_field_value('field shared', 0, 120, npl_bfd_aux_shared_payload_t, value)



class npl_bfd_em_compound_results_t(basic_npl_struct):
    def __init__(self, bfd_payload=0):
        super().__init__(44)
        self.bfd_payload = bfd_payload

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_em_compound_results_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def bfd_payload(self):
        return npl_bfd_em_lookup_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @bfd_payload.setter
    def bfd_payload(self, value):
        self._set_field_value('field bfd_payload', 0, 44, npl_bfd_em_lookup_t, value)



class npl_ene_punt_data_on_npuh_t(basic_npl_struct):
    def __init__(self, ene_punt_fwd_header_type=0, ene_punt_src=0, ene_current_nw_hdr_offset=0, ene_punt_sub_code_and_padding_dsp_and_ssp=0, ene_punt_next_header_type=0):
        super().__init__(64)
        self.ene_punt_fwd_header_type = ene_punt_fwd_header_type
        self.ene_punt_src = ene_punt_src
        self.ene_current_nw_hdr_offset = ene_current_nw_hdr_offset
        self.ene_punt_sub_code_and_padding_dsp_and_ssp = ene_punt_sub_code_and_padding_dsp_and_ssp
        self.ene_punt_next_header_type = ene_punt_next_header_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ene_punt_data_on_npuh_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ene_punt_fwd_header_type(self):
        return self._get_field_value(60, 4)
    @ene_punt_fwd_header_type.setter
    def ene_punt_fwd_header_type(self, value):
        self._set_field_value('field ene_punt_fwd_header_type', 60, 4, int, value)
    @property
    def ene_punt_src(self):
        return self._get_field_value(56, 4)
    @ene_punt_src.setter
    def ene_punt_src(self, value):
        self._set_field_value('field ene_punt_src', 56, 4, int, value)
    @property
    def ene_current_nw_hdr_offset(self):
        return self._get_field_value(48, 8)
    @ene_current_nw_hdr_offset.setter
    def ene_current_nw_hdr_offset(self, value):
        self._set_field_value('field ene_current_nw_hdr_offset', 48, 8, int, value)
    @property
    def ene_punt_sub_code_and_padding_dsp_and_ssp(self):
        return npl_ene_punt_sub_code_and_dsp_and_ssp_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @ene_punt_sub_code_and_padding_dsp_and_ssp.setter
    def ene_punt_sub_code_and_padding_dsp_and_ssp(self, value):
        self._set_field_value('field ene_punt_sub_code_and_padding_dsp_and_ssp', 8, 40, npl_ene_punt_sub_code_and_dsp_and_ssp_t, value)
    @property
    def ene_punt_next_header_type(self):
        return self._get_field_value(0, 5)
    @ene_punt_next_header_type.setter
    def ene_punt_next_header_type(self, value):
        self._set_field_value('field ene_punt_next_header_type', 0, 5, int, value)



class npl_host_nh_mac_t(basic_npl_struct):
    def __init__(self, l3_dlp=0, host_mac=0):
        super().__init__(64)
        self.l3_dlp = l3_dlp
        self.host_mac = host_mac

    def _get_as_sub_field(data, offset_in_data):
        result = npl_host_nh_mac_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_dlp(self):
        return npl_npu_encap_header_l3_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 48)
    @l3_dlp.setter
    def l3_dlp(self, value):
        self._set_field_value('field l3_dlp', 48, 16, npl_npu_encap_header_l3_dlp_t, value)
    @property
    def host_mac(self):
        return self._get_field_value(0, 48)
    @host_mac.setter
    def host_mac(self, value):
        self._set_field_value('field host_mac', 0, 48, int, value)



class npl_host_nh_ptr_t(basic_npl_struct):
    def __init__(self, l3_dlp=0, host_ptr=0):
        super().__init__(36)
        self.l3_dlp = l3_dlp
        self.host_ptr = host_ptr

    def _get_as_sub_field(data, offset_in_data):
        result = npl_host_nh_ptr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_dlp(self):
        return npl_npu_encap_header_l3_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @l3_dlp.setter
    def l3_dlp(self, value):
        self._set_field_value('field l3_dlp', 20, 16, npl_npu_encap_header_l3_dlp_t, value)
    @property
    def host_ptr(self):
        return self._get_field_value(0, 20)
    @host_ptr.setter
    def host_ptr(self, value):
        self._set_field_value('field host_ptr', 0, 20, int, value)



class npl_ingress_punt_mc_expand_encap_t(basic_npl_struct):
    def __init__(self, npu_mirror_or_redirect_encapsulation_type=0, lpts_tcam_first_result_encap_data_msb=0, current_nw_hdr_offset=0):
        super().__init__(28)
        self.npu_mirror_or_redirect_encapsulation_type = npu_mirror_or_redirect_encapsulation_type
        self.lpts_tcam_first_result_encap_data_msb = lpts_tcam_first_result_encap_data_msb
        self.current_nw_hdr_offset = current_nw_hdr_offset

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ingress_punt_mc_expand_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def npu_mirror_or_redirect_encapsulation_type(self):
        return self._get_field_value(24, 4)
    @npu_mirror_or_redirect_encapsulation_type.setter
    def npu_mirror_or_redirect_encapsulation_type(self, value):
        self._set_field_value('field npu_mirror_or_redirect_encapsulation_type', 24, 4, int, value)
    @property
    def lpts_tcam_first_result_encap_data_msb(self):
        return npl_lpts_tcam_first_result_encap_data_msb_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @lpts_tcam_first_result_encap_data_msb.setter
    def lpts_tcam_first_result_encap_data_msb(self, value):
        self._set_field_value('field lpts_tcam_first_result_encap_data_msb', 8, 16, npl_lpts_tcam_first_result_encap_data_msb_t, value)
    @property
    def current_nw_hdr_offset(self):
        return self._get_field_value(0, 8)
    @current_nw_hdr_offset.setter
    def current_nw_hdr_offset(self, value):
        self._set_field_value('field current_nw_hdr_offset', 0, 8, int, value)



class npl_ingress_qos_acl_result_t(basic_npl_struct):
    def __init__(self, override_phb=0, override_qos=0, meter=0, phb=0, ctr_offest_union=0, ingress_qos_remark=0):
        super().__init__(32)
        self.override_phb = override_phb
        self.override_qos = override_qos
        self.meter = meter
        self.phb = phb
        self.ctr_offest_union = ctr_offest_union
        self.ingress_qos_remark = ingress_qos_remark

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ingress_qos_acl_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def override_phb(self):
        return self._get_field_value(31, 1)
    @override_phb.setter
    def override_phb(self, value):
        self._set_field_value('field override_phb', 31, 1, int, value)
    @property
    def override_qos(self):
        return self._get_field_value(30, 1)
    @override_qos.setter
    def override_qos(self, value):
        self._set_field_value('field override_qos', 30, 1, int, value)
    @property
    def meter(self):
        return self._get_field_value(29, 1)
    @meter.setter
    def meter(self, value):
        self._set_field_value('field meter', 29, 1, int, value)
    @property
    def phb(self):
        return npl_phb_t._get_as_sub_field(self._data, self._offset_in_data + 24)
    @phb.setter
    def phb(self, value):
        self._set_field_value('field phb', 24, 5, npl_phb_t, value)
    @property
    def ctr_offest_union(self):
        return npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t._get_as_sub_field(self._data, self._offset_in_data + 19)
    @ctr_offest_union.setter
    def ctr_offest_union(self, value):
        self._set_field_value('field ctr_offest_union', 19, 5, npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t, value)
    @property
    def ingress_qos_remark(self):
        return npl_ingress_qos_mapping_remark_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ingress_qos_remark.setter
    def ingress_qos_remark(self, value):
        self._set_field_value('field ingress_qos_remark', 0, 19, npl_ingress_qos_mapping_remark_t, value)



class npl_ingress_qos_result_t(basic_npl_struct):
    def __init__(self, override_qos=0, enable_ingress_remark=0, ctr_offest_union=0, phb=0, encap_mpls_exp=0, fwd_class_qos_group_u=0, meter=0, fwd_qos_tag=0):
        super().__init__(32)
        self.override_qos = override_qos
        self.enable_ingress_remark = enable_ingress_remark
        self.ctr_offest_union = ctr_offest_union
        self.phb = phb
        self.encap_mpls_exp = encap_mpls_exp
        self.fwd_class_qos_group_u = fwd_class_qos_group_u
        self.meter = meter
        self.fwd_qos_tag = fwd_qos_tag

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ingress_qos_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def override_qos(self):
        return self._get_field_value(31, 1)
    @override_qos.setter
    def override_qos(self, value):
        self._set_field_value('field override_qos', 31, 1, int, value)
    @property
    def enable_ingress_remark(self):
        return self._get_field_value(30, 1)
    @enable_ingress_remark.setter
    def enable_ingress_remark(self, value):
        self._set_field_value('field enable_ingress_remark', 30, 1, int, value)
    @property
    def ctr_offest_union(self):
        return npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t._get_as_sub_field(self._data, self._offset_in_data + 25)
    @ctr_offest_union.setter
    def ctr_offest_union(self, value):
        self._set_field_value('field ctr_offest_union', 25, 5, npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t, value)
    @property
    def phb(self):
        return npl_phb_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @phb.setter
    def phb(self, value):
        self._set_field_value('field phb', 20, 5, npl_phb_t, value)
    @property
    def encap_mpls_exp(self):
        return npl_encap_mpls_exp_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @encap_mpls_exp.setter
    def encap_mpls_exp(self, value):
        self._set_field_value('field encap_mpls_exp', 16, 4, npl_encap_mpls_exp_t, value)
    @property
    def fwd_class_qos_group_u(self):
        return npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @fwd_class_qos_group_u.setter
    def fwd_class_qos_group_u(self, value):
        self._set_field_value('field fwd_class_qos_group_u', 8, 8, npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t, value)
    @property
    def meter(self):
        return self._get_field_value(7, 1)
    @meter.setter
    def meter(self, value):
        self._set_field_value('field meter', 7, 1, int, value)
    @property
    def fwd_qos_tag(self):
        return self._get_field_value(0, 7)
    @fwd_qos_tag.setter
    def fwd_qos_tag(self, value):
        self._set_field_value('field fwd_qos_tag', 0, 7, int, value)



class npl_inject_down_encap_dlp_and_nh_t(basic_npl_struct):
    def __init__(self, down_l3_dlp=0, down_nh=0, down_pcp_dei=0):
        super().__init__(32)
        self.down_l3_dlp = down_l3_dlp
        self.down_nh = down_nh
        self.down_pcp_dei = down_pcp_dei

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_down_encap_dlp_and_nh_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def down_l3_dlp(self):
        return npl_npu_encap_header_l3_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @down_l3_dlp.setter
    def down_l3_dlp(self, value):
        self._set_field_value('field down_l3_dlp', 16, 16, npl_npu_encap_header_l3_dlp_t, value)
    @property
    def down_nh(self):
        return self._get_field_value(4, 12)
    @down_nh.setter
    def down_nh(self, value):
        self._set_field_value('field down_nh', 4, 12, int, value)
    @property
    def down_pcp_dei(self):
        return npl_pcp_dei_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @down_pcp_dei.setter
    def down_pcp_dei(self, value):
        self._set_field_value('field down_pcp_dei', 0, 4, npl_pcp_dei_t, value)



class npl_inject_down_encap_ptr_or_dlp_t(basic_npl_struct):
    def __init__(self):
        super().__init__(32)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_down_encap_ptr_or_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inject_down_encap_ptr(self):
        return self._get_field_value(24, 8)
    @inject_down_encap_ptr.setter
    def inject_down_encap_ptr(self, value):
        self._set_field_value('field inject_down_encap_ptr', 24, 8, int, value)
    @property
    def inject_down_encap_nh(self):
        return npl_inject_down_encap_dlp_and_nh_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @inject_down_encap_nh.setter
    def inject_down_encap_nh(self, value):
        self._set_field_value('field inject_down_encap_nh', 0, 32, npl_inject_down_encap_dlp_and_nh_t, value)



class npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t(basic_npl_struct):
    def __init__(self):
        super().__init__(32)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inject_down_encap_ptr_or_dlp(self):
        return npl_inject_down_encap_ptr_or_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @inject_down_encap_ptr_or_dlp.setter
    def inject_down_encap_ptr_or_dlp(self, value):
        self._set_field_value('field inject_down_encap_ptr_or_dlp', 0, 32, npl_inject_down_encap_ptr_or_dlp_t, value)



class npl_inject_up_eth_header_t(basic_npl_struct):
    def __init__(self, qos_or_dest=0, from_port=0):
        super().__init__(36)
        self.qos_or_dest = qos_or_dest
        self.from_port = from_port

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_up_eth_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def qos_or_dest(self):
        return npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t._get_as_sub_field(self._data, self._offset_in_data + 12)
    @qos_or_dest.setter
    def qos_or_dest(self, value):
        self._set_field_value('field qos_or_dest', 12, 24, npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t, value)
    @property
    def from_port(self):
        return npl_inject_up_eth_header_t_anonymous_union_from_port_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @from_port.setter
    def from_port(self, value):
        self._set_field_value('field from_port', 0, 12, npl_inject_up_eth_header_t_anonymous_union_from_port_t, value)



class npl_ip_encap_data_t(basic_npl_struct):
    def __init__(self, ip=0, upper_layer=0):
        super().__init__(112)
        self.ip = ip
        self.upper_layer = upper_layer

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ip(self):
        return npl_ip_encap_data_t_anonymous_union_ip_t._get_as_sub_field(self._data, self._offset_in_data + 32)
    @ip.setter
    def ip(self, value):
        self._set_field_value('field ip', 32, 80, npl_ip_encap_data_t_anonymous_union_ip_t, value)
    @property
    def upper_layer(self):
        return npl_ip_encap_data_t_anonymous_union_upper_layer_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @upper_layer.setter
    def upper_layer(self, value):
        self._set_field_value('field upper_layer', 0, 32, npl_ip_encap_data_t_anonymous_union_upper_layer_t, value)



class npl_l2_adj_sid_nhlfe_t(basic_npl_struct):
    def __init__(self, l3_dlp_nh_encap=0, prefix=0, dsp=0):
        super().__init__(60)
        self.l3_dlp_nh_encap = l3_dlp_nh_encap
        self.prefix = prefix
        self.dsp = dsp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_adj_sid_nhlfe_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_dlp_nh_encap(self):
        return npl_npu_l3_common_dlp_nh_encap_t._get_as_sub_field(self._data, self._offset_in_data + 32)
    @l3_dlp_nh_encap.setter
    def l3_dlp_nh_encap(self, value):
        self._set_field_value('field l3_dlp_nh_encap', 32, 28, npl_npu_l3_common_dlp_nh_encap_t, value)
    @property
    def prefix(self):
        return self._get_field_value(16, 16)
    @prefix.setter
    def prefix(self, value):
        self._set_field_value('field prefix', 16, 16, int, value)
    @property
    def dsp(self):
        return self._get_field_value(0, 16)
    @dsp.setter
    def dsp(self, value):
        self._set_field_value('field dsp', 0, 16, int, value)



class npl_l2_lp_attributes_t(basic_npl_struct):
    def __init__(self, learn_type=0, learn_prob=0, term=0, shared=0):
        super().__init__(142)
        self.learn_type = learn_type
        self.learn_prob = learn_prob
        self.term = term
        self.shared = shared

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_lp_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def learn_type(self):
        return self._get_field_value(140, 2)
    @learn_type.setter
    def learn_type(self, value):
        self._set_field_value('field learn_type', 140, 2, int, value)
    @property
    def learn_prob(self):
        return self._get_field_value(139, 1)
    @learn_prob.setter
    def learn_prob(self, value):
        self._set_field_value('field learn_prob', 139, 1, int, value)
    @property
    def term(self):
        return npl_term_l2_lp_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 105)
    @term.setter
    def term(self, value):
        self._set_field_value('field term', 105, 34, npl_term_l2_lp_attributes_t, value)
    @property
    def shared(self):
        return npl_shared_l2_lp_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @shared.setter
    def shared(self, value):
        self._set_field_value('field shared', 0, 105, npl_shared_l2_lp_attributes_t, value)



class npl_l2_pwe_encap_t(basic_npl_struct):
    def __init__(self, l3_dlp=0, nh=0, lsp_destination=0, l2_dlp=0):
        super().__init__(68)
        self.l3_dlp = l3_dlp
        self.nh = nh
        self.lsp_destination = lsp_destination
        self.l2_dlp = l2_dlp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_pwe_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_dlp(self):
        return npl_npu_encap_header_l3_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 52)
    @l3_dlp.setter
    def l3_dlp(self, value):
        self._set_field_value('field l3_dlp', 52, 16, npl_npu_encap_header_l3_dlp_t, value)
    @property
    def nh(self):
        return self._get_field_value(40, 12)
    @nh.setter
    def nh(self, value):
        self._set_field_value('field nh', 40, 12, int, value)
    @property
    def lsp_destination(self):
        return npl_lsp_destination_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @lsp_destination.setter
    def lsp_destination(self, value):
        self._set_field_value('field lsp_destination', 20, 20, npl_lsp_destination_t, value)
    @property
    def l2_dlp(self):
        return npl_npu_encap_header_l2_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_dlp.setter
    def l2_dlp(self, value):
        self._set_field_value('field l2_dlp', 0, 20, npl_npu_encap_header_l2_dlp_t, value)



class npl_l2_relay_and_l3_lp_attributes_payload_t(basic_npl_struct):
    def __init__(self):
        super().__init__(57)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_relay_and_l3_lp_attributes_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def relay_att_inf_payload(self):
        return npl_mac_relay_attributes_inf_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @relay_att_inf_payload.setter
    def relay_att_inf_payload(self, value):
        self._set_field_value('field relay_att_inf_payload', 0, 57, npl_mac_relay_attributes_inf_payload_t, value)
    @property
    def mac_relay_attributes(self):
        return npl_mac_relay_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mac_relay_attributes.setter
    def mac_relay_attributes(self, value):
        self._set_field_value('field mac_relay_attributes', 0, 48, npl_mac_relay_attributes_t, value)
    @property
    def relay_att_table_payload(self):
        return npl_mac_relay_attributes_payload_t._get_as_sub_field(self._data, self._offset_in_data + 14)
    @relay_att_table_payload.setter
    def relay_att_table_payload(self, value):
        self._set_field_value('field relay_att_table_payload', 14, 43, npl_mac_relay_attributes_payload_t, value)



class npl_l2_vxlan_encap_t(basic_npl_struct):
    def __init__(self, l3_dlp=0, nh=0, tunnel_dlp=0, overlay_nh=0):
        super().__init__(60)
        self.l3_dlp = l3_dlp
        self.nh = nh
        self.tunnel_dlp = tunnel_dlp
        self.overlay_nh = overlay_nh

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_vxlan_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_dlp(self):
        return npl_npu_encap_header_l3_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 44)
    @l3_dlp.setter
    def l3_dlp(self, value):
        self._set_field_value('field l3_dlp', 44, 16, npl_npu_encap_header_l3_dlp_t, value)
    @property
    def nh(self):
        return self._get_field_value(32, 12)
    @nh.setter
    def nh(self, value):
        self._set_field_value('field nh', 32, 12, int, value)
    @property
    def tunnel_dlp(self):
        return npl_npu_encap_header_l2_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 12)
    @tunnel_dlp.setter
    def tunnel_dlp(self, value):
        self._set_field_value('field tunnel_dlp', 12, 20, npl_npu_encap_header_l2_dlp_t, value)
    @property
    def overlay_nh(self):
        return self._get_field_value(0, 10)
    @overlay_nh.setter
    def overlay_nh(self, value):
        self._set_field_value('field overlay_nh', 0, 10, int, value)



class npl_l3_dlp_attributes_t(basic_npl_struct):
    def __init__(self, svi_dhcp_snooping=0, disabled=0, l3_dlp_encap_or_te_labels=0, nh_ene_macro_code=0, l3_dlp_qos_and_attributes=0, tx_to_rx_rcy_data=0):
        super().__init__(138)
        self.svi_dhcp_snooping = svi_dhcp_snooping
        self.disabled = disabled
        self.l3_dlp_encap_or_te_labels = l3_dlp_encap_or_te_labels
        self.nh_ene_macro_code = nh_ene_macro_code
        self.l3_dlp_qos_and_attributes = l3_dlp_qos_and_attributes
        self.tx_to_rx_rcy_data = tx_to_rx_rcy_data

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_dlp_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def svi_dhcp_snooping(self):
        return self._get_field_value(137, 1)
    @svi_dhcp_snooping.setter
    def svi_dhcp_snooping(self, value):
        self._set_field_value('field svi_dhcp_snooping', 137, 1, int, value)
    @property
    def disabled(self):
        return self._get_field_value(136, 1)
    @disabled.setter
    def disabled(self, value):
        self._set_field_value('field disabled', 136, 1, int, value)
    @property
    def l3_dlp_encap_or_te_labels(self):
        return npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t._get_as_sub_field(self._data, self._offset_in_data + 64)
    @l3_dlp_encap_or_te_labels.setter
    def l3_dlp_encap_or_te_labels(self, value):
        self._set_field_value('field l3_dlp_encap_or_te_labels', 64, 72, npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t, value)
    @property
    def nh_ene_macro_code(self):
        return self._get_field_value(62, 2)
    @nh_ene_macro_code.setter
    def nh_ene_macro_code(self, value):
        self._set_field_value('field nh_ene_macro_code', 62, 2, int, value)
    @property
    def l3_dlp_qos_and_attributes(self):
        return npl_l3_dlp_qos_and_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @l3_dlp_qos_and_attributes.setter
    def l3_dlp_qos_and_attributes(self, value):
        self._set_field_value('field l3_dlp_qos_and_attributes', 8, 54, npl_l3_dlp_qos_and_attributes_t, value)
    @property
    def tx_to_rx_rcy_data(self):
        return npl_tx_to_rx_rcy_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @tx_to_rx_rcy_data.setter
    def tx_to_rx_rcy_data(self, value):
        self._set_field_value('field tx_to_rx_rcy_data', 0, 8, npl_tx_to_rx_rcy_data_t, value)



class npl_l3_global_slp_t(basic_npl_struct):
    def __init__(self, id=0):
        super().__init__(16)
        self.id = id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_global_slp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id(self):
        return npl_l3_slp_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @id.setter
    def id(self, value):
        self._set_field_value('field id', 0, 14, npl_l3_slp_id_t, value)



class npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t(basic_npl_struct):
    def __init__(self):
        super().__init__(60)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def opt3(self):
        return npl_lsp_labels_opt3_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @opt3.setter
    def opt3(self, value):
        self._set_field_value('field opt3', 0, 60, npl_lsp_labels_opt3_t, value)
    @property
    def opt2(self):
        return npl_lsp_labels_opt2_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @opt2.setter
    def opt2(self, value):
        self._set_field_value('field opt2', 0, 60, npl_lsp_labels_opt2_t, value)
    @property
    def opt1(self):
        return npl_lsp_labels_opt1_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @opt1.setter
    def opt1(self, value):
        self._set_field_value('field opt1', 0, 60, npl_lsp_labels_opt1_t, value)



class npl_mac_qos_macro_pack_table_fields_t(basic_npl_struct):
    def __init__(self, pd_qos_mapping_7b=0, l3_qos_mapping_key=0):
        super().__init__(16)
        self.pd_qos_mapping_7b = pd_qos_mapping_7b
        self.l3_qos_mapping_key = l3_qos_mapping_key

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_qos_macro_pack_table_fields_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def pd_qos_mapping_7b(self):
        return self._get_field_value(8, 7)
    @pd_qos_mapping_7b.setter
    def pd_qos_mapping_7b(self, value):
        self._set_field_value('field pd_qos_mapping_7b', 8, 7, int, value)
    @property
    def l3_qos_mapping_key(self):
        return npl_qos_mapping_key_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_qos_mapping_key.setter
    def l3_qos_mapping_key(self, value):
        self._set_field_value('field l3_qos_mapping_key', 0, 8, npl_qos_mapping_key_t, value)



class npl_mc_em_db_result_t(basic_npl_struct):
    def __init__(self):
        super().__init__(72)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_mc_em_db_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rx(self):
        return npl_mc_em_db_result_rx_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @rx.setter
    def rx(self, value):
        self._set_field_value('field rx', 0, 72, npl_mc_em_db_result_rx_t, value)
    @property
    def tx(self):
        return npl_mc_em_db_result_tx_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @tx.setter
    def tx(self, value):
        self._set_field_value('field tx', 0, 72, npl_mc_em_db_result_tx_t, value)



class npl_minimal_l3_lp_attributes_t(basic_npl_struct):
    def __init__(self, disable_ipv6_mc=0, l3_relay_id=0, lp_set=0, ttl_mode=0, per_protocol_count=0, disable_ipv4_uc=0, p_counter=0, global_slp_id=0, disable_ipv4_mc=0, disable_mpls=0, disable_ipv6_uc=0):
        super().__init__(56)
        self.disable_ipv6_mc = disable_ipv6_mc
        self.l3_relay_id = l3_relay_id
        self.lp_set = lp_set
        self.ttl_mode = ttl_mode
        self.per_protocol_count = per_protocol_count
        self.disable_ipv4_uc = disable_ipv4_uc
        self.p_counter = p_counter
        self.global_slp_id = global_slp_id
        self.disable_ipv4_mc = disable_ipv4_mc
        self.disable_mpls = disable_mpls
        self.disable_ipv6_uc = disable_ipv6_uc

    def _get_as_sub_field(data, offset_in_data):
        result = npl_minimal_l3_lp_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def disable_ipv6_mc(self):
        return self._get_field_value(55, 1)
    @disable_ipv6_mc.setter
    def disable_ipv6_mc(self, value):
        self._set_field_value('field disable_ipv6_mc', 55, 1, int, value)
    @property
    def l3_relay_id(self):
        return npl_l3_relay_id_t._get_as_sub_field(self._data, self._offset_in_data + 44)
    @l3_relay_id.setter
    def l3_relay_id(self, value):
        self._set_field_value('field l3_relay_id', 44, 11, npl_l3_relay_id_t, value)
    @property
    def lp_set(self):
        return self._get_field_value(43, 1)
    @lp_set.setter
    def lp_set(self, value):
        self._set_field_value('field lp_set', 43, 1, int, value)
    @property
    def ttl_mode(self):
        return self._get_field_value(42, 1)
    @ttl_mode.setter
    def ttl_mode(self, value):
        self._set_field_value('field ttl_mode', 42, 1, int, value)
    @property
    def per_protocol_count(self):
        return self._get_field_value(41, 1)
    @per_protocol_count.setter
    def per_protocol_count(self, value):
        self._set_field_value('field per_protocol_count', 41, 1, int, value)
    @property
    def disable_ipv4_uc(self):
        return self._get_field_value(40, 1)
    @disable_ipv4_uc.setter
    def disable_ipv4_uc(self, value):
        self._set_field_value('field disable_ipv4_uc', 40, 1, int, value)
    @property
    def p_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @p_counter.setter
    def p_counter(self, value):
        self._set_field_value('field p_counter', 20, 20, npl_counter_ptr_t, value)
    @property
    def global_slp_id(self):
        return npl_l3_global_slp_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @global_slp_id.setter
    def global_slp_id(self, value):
        self._set_field_value('field global_slp_id', 4, 16, npl_l3_global_slp_t, value)
    @property
    def disable_ipv4_mc(self):
        return self._get_field_value(2, 1)
    @disable_ipv4_mc.setter
    def disable_ipv4_mc(self, value):
        self._set_field_value('field disable_ipv4_mc', 2, 1, int, value)
    @property
    def disable_mpls(self):
        return self._get_field_value(1, 1)
    @disable_mpls.setter
    def disable_mpls(self, value):
        self._set_field_value('field disable_mpls', 1, 1, int, value)
    @property
    def disable_ipv6_uc(self):
        return self._get_field_value(0, 1)
    @disable_ipv6_uc.setter
    def disable_ipv6_uc(self, value):
        self._set_field_value('field disable_ipv6_uc', 0, 1, int, value)



class npl_mpls_termination_l3vpn_t(basic_npl_struct):
    def __init__(self, l3_relay_id=0, vpn_mldp_info=0, vpn_p_counter=0):
        super().__init__(47)
        self.l3_relay_id = l3_relay_id
        self.vpn_mldp_info = vpn_mldp_info
        self.vpn_p_counter = vpn_p_counter

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mpls_termination_l3vpn_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_relay_id(self):
        return npl_l3_relay_id_t._get_as_sub_field(self._data, self._offset_in_data + 36)
    @l3_relay_id.setter
    def l3_relay_id(self, value):
        self._set_field_value('field l3_relay_id', 36, 11, npl_l3_relay_id_t, value)
    @property
    def vpn_mldp_info(self):
        return npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @vpn_mldp_info.setter
    def vpn_mldp_info(self, value):
        self._set_field_value('field vpn_mldp_info', 20, 16, npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t, value)
    @property
    def vpn_p_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @vpn_p_counter.setter
    def vpn_p_counter(self, value):
        self._set_field_value('field vpn_p_counter', 0, 20, npl_counter_ptr_t, value)



class npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t(basic_npl_struct):
    def __init__(self):
        super().__init__(47)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3vpn_info(self):
        return npl_mpls_termination_l3vpn_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3vpn_info.setter
    def l3vpn_info(self, value):
        self._set_field_value('field l3vpn_info', 0, 47, npl_mpls_termination_l3vpn_t, value)
    @property
    def pwe_info(self):
        return npl_mpls_termination_pwe_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @pwe_info.setter
    def pwe_info(self, value):
        self._set_field_value('field pwe_info', 0, 47, npl_mpls_termination_pwe_t, value)



class npl_nh_and_svi_payload_t(basic_npl_struct):
    def __init__(self, nh_payload=0, nh_da=0):
        super().__init__(119)
        self.nh_payload = nh_payload
        self.nh_da = nh_da

    def _get_as_sub_field(data, offset_in_data):
        result = npl_nh_and_svi_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def nh_payload(self):
        return npl_nh_payload_t._get_as_sub_field(self._data, self._offset_in_data + 48)
    @nh_payload.setter
    def nh_payload(self, value):
        self._set_field_value('field nh_payload', 48, 68, npl_nh_payload_t, value)
    @property
    def nh_da(self):
        return self._get_field_value(0, 48)
    @nh_da.setter
    def nh_da(self, value):
        self._set_field_value('field nh_da', 0, 48, int, value)



class npl_nhlfe_t_anonymous_union_nhlfe_payload_t(basic_npl_struct):
    def __init__(self):
        super().__init__(60)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_nhlfe_t_anonymous_union_nhlfe_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def te_headend(self):
        return npl_te_headend_nhlfe_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @te_headend.setter
    def te_headend(self, value):
        self._set_field_value('field te_headend', 0, 28, npl_te_headend_nhlfe_t, value)
    @property
    def te_midpoint(self):
        return npl_te_midpoint_nhlfe_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @te_midpoint.setter
    def te_midpoint(self, value):
        self._set_field_value('field te_midpoint', 0, 60, npl_te_midpoint_nhlfe_t, value)
    @property
    def l2_adj_sid(self):
        return npl_l2_adj_sid_nhlfe_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_adj_sid.setter
    def l2_adj_sid(self, value):
        self._set_field_value('field l2_adj_sid', 0, 60, npl_l2_adj_sid_nhlfe_t, value)



class npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t(basic_npl_struct):
    def __init__(self):
        super().__init__(64)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def host_nh_mac(self):
        return npl_host_nh_mac_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @host_nh_mac.setter
    def host_nh_mac(self, value):
        self._set_field_value('field host_nh_mac', 0, 64, npl_host_nh_mac_t, value)



class npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t(basic_npl_struct):
    def __init__(self):
        super().__init__(68)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ac(self):
        return npl_l2_ac_encap_t._get_as_sub_field(self._data, self._offset_in_data + 48)
    @ac.setter
    def ac(self, value):
        self._set_field_value('field ac', 48, 20, npl_l2_ac_encap_t, value)
    @property
    def pwe(self):
        return npl_l2_pwe_encap_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @pwe.setter
    def pwe(self, value):
        self._set_field_value('field pwe', 0, 68, npl_l2_pwe_encap_t, value)
    @property
    def vxlan(self):
        return npl_l2_vxlan_encap_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @vxlan.setter
    def vxlan(self, value):
        self._set_field_value('field vxlan', 8, 60, npl_l2_vxlan_encap_t, value)



class npl_npu_l3_common_encap_header_t(basic_npl_struct):
    def __init__(self, l3_encap_type=0, l3_dlp_nh_encap=0):
        super().__init__(32)
        self.l3_encap_type = l3_encap_type
        self.l3_dlp_nh_encap = l3_dlp_nh_encap

    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_l3_common_encap_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_encap_type(self):
        return self._get_field_value(28, 4)
    @l3_encap_type.setter
    def l3_encap_type(self, value):
        self._set_field_value('field l3_encap_type', 28, 4, int, value)
    @property
    def l3_dlp_nh_encap(self):
        return npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_dlp_nh_encap.setter
    def l3_dlp_nh_encap(self, value):
        self._set_field_value('field l3_dlp_nh_encap', 0, 28, npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t, value)



class npl_npu_l3_encap_header_t(basic_npl_struct):
    def __init__(self, l3_common_encap=0, encap_ext=0):
        super().__init__(80)
        self.l3_common_encap = l3_common_encap
        self.encap_ext = encap_ext

    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_l3_encap_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_common_encap(self):
        return npl_npu_l3_common_encap_header_t._get_as_sub_field(self._data, self._offset_in_data + 48)
    @l3_common_encap.setter
    def l3_common_encap(self, value):
        self._set_field_value('field l3_common_encap', 48, 32, npl_npu_l3_common_encap_header_t, value)
    @property
    def encap_ext(self):
        return npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @encap_ext.setter
    def encap_ext(self, value):
        self._set_field_value('field encap_ext', 0, 48, npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t, value)



class npl_og_em_result_t(basic_npl_struct):
    def __init__(self, result=0, result_type=0):
        super().__init__(64)
        self.result = result
        self.result_type = result_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_og_em_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def result(self):
        return npl_og_em_result_t_anonymous_union_result_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @result.setter
    def result(self, value):
        self._set_field_value('field result', 2, 62, npl_og_em_result_t_anonymous_union_result_t, value)
    @property
    def result_type(self):
        return self._get_field_value(0, 2)
    @result_type.setter
    def result_type(self, value):
        self._set_field_value('field result_type', 0, 2, int, value)



class npl_punt_eth_nw_common_encap_data_t(basic_npl_struct):
    def __init__(self, punt_host_da=0, sa_or_npuh=0, punt_eth_vid=0):
        super().__init__(108)
        self.punt_host_da = punt_host_da
        self.sa_or_npuh = sa_or_npuh
        self.punt_eth_vid = punt_eth_vid

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_eth_nw_common_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def punt_host_da(self):
        return npl_mac_addr_t._get_as_sub_field(self._data, self._offset_in_data + 60)
    @punt_host_da.setter
    def punt_host_da(self, value):
        self._set_field_value('field punt_host_da', 60, 48, npl_mac_addr_t, value)
    @property
    def sa_or_npuh(self):
        return npl_punt_if_sa_or_npu_host_data_t._get_as_sub_field(self._data, self._offset_in_data + 12)
    @sa_or_npuh.setter
    def sa_or_npuh(self, value):
        self._set_field_value('field sa_or_npuh', 12, 48, npl_punt_if_sa_or_npu_host_data_t, value)
    @property
    def punt_eth_vid(self):
        return npl_vlan_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_eth_vid.setter
    def punt_eth_vid(self, value):
        self._set_field_value('field punt_eth_vid', 0, 12, npl_vlan_id_t, value)



class npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t(basic_npl_struct):
    def __init__(self):
        super().__init__(16)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def punt_padding_id(self):
        return npl_punt_padding_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_padding_id.setter
    def punt_padding_id(self, value):
        self._set_field_value('field punt_padding_id', 0, 14, npl_punt_padding_id_t, value)
    @property
    def sw_pfc(self):
        return npl_l3_pfc_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @sw_pfc.setter
    def sw_pfc(self, value):
        self._set_field_value('field sw_pfc', 0, 15, npl_l3_pfc_data_t, value)



class npl_punt_msb_encap_t(basic_npl_struct):
    def __init__(self, punt_encap_msb=0, punt_lm_cmd=0):
        super().__init__(40)
        self.punt_encap_msb = punt_encap_msb
        self.punt_lm_cmd = punt_lm_cmd

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_msb_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def punt_encap_msb(self):
        return npl_ingress_punt_mc_expand_encap_t._get_as_sub_field(self._data, self._offset_in_data + 12)
    @punt_encap_msb.setter
    def punt_encap_msb(self, value):
        self._set_field_value('field punt_encap_msb', 12, 28, npl_ingress_punt_mc_expand_encap_t, value)
    @property
    def punt_lm_cmd(self):
        return npl_lm_command_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_lm_cmd.setter
    def punt_lm_cmd(self, value):
        self._set_field_value('field punt_lm_cmd', 0, 12, npl_lm_command_t, value)



class npl_rpf_compressed_destination_t(basic_npl_struct):
    def __init__(self, enable_mc_rpf=0, rpf_id_or_lp_id=0):
        super().__init__(20)
        self.enable_mc_rpf = enable_mc_rpf
        self.rpf_id_or_lp_id = rpf_id_or_lp_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rpf_compressed_destination_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def enable_mc_rpf(self):
        return self._get_field_value(19, 1)
    @enable_mc_rpf.setter
    def enable_mc_rpf(self, value):
        self._set_field_value('field enable_mc_rpf', 19, 1, int, value)
    @property
    def rpf_id_or_lp_id(self):
        return npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @rpf_id_or_lp_id.setter
    def rpf_id_or_lp_id(self, value):
        self._set_field_value('field rpf_id_or_lp_id', 0, 16, npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t, value)



class npl_rtf_payload_t(basic_npl_struct):
    def __init__(self, rtf_profile_index=0, rtf_result_profile=0):
        super().__init__(64)
        self.rtf_profile_index = rtf_profile_index
        self.rtf_result_profile = rtf_result_profile

    def _get_as_sub_field(data, offset_in_data):
        result = npl_rtf_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rtf_profile_index(self):
        return self._get_field_value(62, 1)
    @rtf_profile_index.setter
    def rtf_profile_index(self, value):
        self._set_field_value('field rtf_profile_index', 62, 1, int, value)
    @property
    def rtf_result_profile(self):
        return npl_rtf_payload_t_anonymous_union_rtf_result_profile_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @rtf_result_profile.setter
    def rtf_result_profile(self, value):
        self._set_field_value('field rtf_result_profile', 0, 62, npl_rtf_payload_t_anonymous_union_rtf_result_profile_t, value)



class npl_slp_info_t_anonymous_union_global_slp_id_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_slp_info_t_anonymous_union_global_slp_id_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2_slp(self):
        return npl_l2_global_slp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_slp.setter
    def l2_slp(self, value):
        self._set_field_value('field l2_slp', 0, 20, npl_l2_global_slp_t, value)
    @property
    def l3_slp(self):
        return npl_l3_global_slp_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @l3_slp.setter
    def l3_slp(self, value):
        self._set_field_value('field l3_slp', 4, 16, npl_l3_global_slp_t, value)
    @property
    def is_l2(self):
        return self._get_field_value(19, 1)
    @is_l2.setter
    def is_l2(self, value):
        self._set_field_value('field is_l2', 19, 1, int, value)



class npl_snoop_or_rcy_data_t(basic_npl_struct):
    def __init__(self, snoop_or_rcy_data=0):
        super().__init__(8)
        self.snoop_or_rcy_data = snoop_or_rcy_data

    def _get_as_sub_field(data, offset_in_data):
        result = npl_snoop_or_rcy_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def snoop_or_rcy_data(self):
        return npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @snoop_or_rcy_data.setter
    def snoop_or_rcy_data(self, value):
        self._set_field_value('field snoop_or_rcy_data', 0, 8, npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t, value)



class npl_std_ip_em_lpm_result_host_and_l3_dlp_t(basic_npl_struct):
    def __init__(self, host_nh_mac=0, destination=0):
        super().__init__(84)
        self.host_nh_mac = host_nh_mac
        self.destination = destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_std_ip_em_lpm_result_host_and_l3_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def host_nh_mac(self):
        return npl_host_nh_mac_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @host_nh_mac.setter
    def host_nh_mac(self, value):
        self._set_field_value('field host_nh_mac', 20, 64, npl_host_nh_mac_t, value)
    @property
    def destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 20, npl_destination_t, value)



class npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t(basic_npl_struct):
    def __init__(self, host_ptr=0, destination=0):
        super().__init__(84)
        self.host_ptr = host_ptr
        self.destination = destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def host_ptr(self):
        return npl_host_nh_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @host_ptr.setter
    def host_ptr(self, value):
        self._set_field_value('field host_ptr', 20, 36, npl_host_nh_ptr_t, value)
    @property
    def destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 20, npl_destination_t, value)



class npl_svi_eve_profile_and_data_t(basic_npl_struct):
    def __init__(self, main_type=0, sub_type_or_vid_2_plus_prf=0, vid1=0):
        super().__init__(28)
        self.main_type = main_type
        self.sub_type_or_vid_2_plus_prf = sub_type_or_vid_2_plus_prf
        self.vid1 = vid1

    def _get_as_sub_field(data, offset_in_data):
        result = npl_svi_eve_profile_and_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def main_type(self):
        return self._get_field_value(26, 2)
    @main_type.setter
    def main_type(self, value):
        self._set_field_value('field main_type', 26, 2, int, value)
    @property
    def sub_type_or_vid_2_plus_prf(self):
        return npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t._get_as_sub_field(self._data, self._offset_in_data + 12)
    @sub_type_or_vid_2_plus_prf.setter
    def sub_type_or_vid_2_plus_prf(self, value):
        self._set_field_value('field sub_type_or_vid_2_plus_prf', 12, 14, npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t, value)
    @property
    def vid1(self):
        return self._get_field_value(0, 12)
    @vid1.setter
    def vid1(self, value):
        self._set_field_value('field vid1', 0, 12, int, value)



class npl_tm_headers_template_t(basic_npl_struct):
    def __init__(self, u=0):
        super().__init__(48)
        self.u = u

    def _get_as_sub_field(data, offset_in_data):
        result = npl_tm_headers_template_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def u(self):
        return npl_tm_headers_template_t_anonymous_union_u_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @u.setter
    def u(self, value):
        self._set_field_value('field u', 0, 48, npl_tm_headers_template_t_anonymous_union_u_t, value)



class npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t(basic_npl_struct):
    def __init__(self):
        super().__init__(124)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def punt_eth_nw_encap_data(self):
        return npl_punt_eth_nw_common_encap_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_eth_nw_encap_data.setter
    def punt_eth_nw_encap_data(self, value):
        self._set_field_value('field punt_eth_nw_encap_data', 0, 108, npl_punt_eth_nw_common_encap_data_t, value)
    @property
    def punt_eth_transport_update(self):
        return npl_punt_eth_transport_update_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_eth_transport_update.setter
    def punt_eth_transport_update(self, value):
        self._set_field_value('field punt_eth_transport_update', 0, 124, npl_punt_eth_transport_update_t, value)
    @property
    def punt_npu_host_data(self):
        return npl_punt_npu_host_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_npu_host_data.setter
    def punt_npu_host_data(self, value):
        self._set_field_value('field punt_npu_host_data', 0, 48, npl_punt_npu_host_data_t, value)



class npl_ac_dlp_specific_t_anonymous_union_eve_types_t(basic_npl_struct):
    def __init__(self):
        super().__init__(28)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ac_dlp_specific_t_anonymous_union_eve_types_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def eve(self):
        return npl_ive_profile_and_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @eve.setter
    def eve(self, value):
        self._set_field_value('field eve', 0, 28, npl_ive_profile_and_data_t, value)
    @property
    def eve_svi(self):
        return npl_svi_eve_profile_and_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @eve_svi.setter
    def eve_svi(self, value):
        self._set_field_value('field eve_svi', 0, 28, npl_svi_eve_profile_and_data_t, value)



class npl_base_l3_lp_attributes_t(basic_npl_struct):
    def __init__(self, rtf_conf_set_and_stages_or_post_fwd_stage=0, uc_rpf_mode=0, mirror_cmd=0, minimal_l3_lp_attributes=0, l3_lp_mirror_type=0, acl_drop_offset=0, q_counter=0, m_counter=0):
        super().__init__(120)
        self.rtf_conf_set_and_stages_or_post_fwd_stage = rtf_conf_set_and_stages_or_post_fwd_stage
        self.uc_rpf_mode = uc_rpf_mode
        self.mirror_cmd = mirror_cmd
        self.minimal_l3_lp_attributes = minimal_l3_lp_attributes
        self.l3_lp_mirror_type = l3_lp_mirror_type
        self.acl_drop_offset = acl_drop_offset
        self.q_counter = q_counter
        self.m_counter = m_counter

    def _get_as_sub_field(data, offset_in_data):
        result = npl_base_l3_lp_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def rtf_conf_set_and_stages_or_post_fwd_stage(self):
        return npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t._get_as_sub_field(self._data, self._offset_in_data + 108)
    @rtf_conf_set_and_stages_or_post_fwd_stage.setter
    def rtf_conf_set_and_stages_or_post_fwd_stage(self, value):
        self._set_field_value('field rtf_conf_set_and_stages_or_post_fwd_stage', 108, 12, npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t, value)
    @property
    def uc_rpf_mode(self):
        return self._get_field_value(105, 2)
    @uc_rpf_mode.setter
    def uc_rpf_mode(self, value):
        self._set_field_value('field uc_rpf_mode', 105, 2, int, value)
    @property
    def mirror_cmd(self):
        return self._get_field_value(100, 5)
    @mirror_cmd.setter
    def mirror_cmd(self, value):
        self._set_field_value('field mirror_cmd', 100, 5, int, value)
    @property
    def minimal_l3_lp_attributes(self):
        return npl_minimal_l3_lp_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 44)
    @minimal_l3_lp_attributes.setter
    def minimal_l3_lp_attributes(self, value):
        self._set_field_value('field minimal_l3_lp_attributes', 44, 56, npl_minimal_l3_lp_attributes_t, value)
    @property
    def l3_lp_mirror_type(self):
        return self._get_field_value(43, 1)
    @l3_lp_mirror_type.setter
    def l3_lp_mirror_type(self, value):
        self._set_field_value('field l3_lp_mirror_type', 43, 1, int, value)
    @property
    def acl_drop_offset(self):
        return npl_common_cntr_offset_and_padding_t._get_as_sub_field(self._data, self._offset_in_data + 40)
    @acl_drop_offset.setter
    def acl_drop_offset(self, value):
        self._set_field_value('field acl_drop_offset', 40, 3, npl_common_cntr_offset_and_padding_t, value)
    @property
    def q_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @q_counter.setter
    def q_counter(self, value):
        self._set_field_value('field q_counter', 20, 20, npl_counter_ptr_t, value)
    @property
    def m_counter(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @m_counter.setter
    def m_counter(self, value):
        self._set_field_value('field m_counter', 0, 20, npl_counter_ptr_t, value)



class npl_em_result_ptr_and_l3_dlp_t(basic_npl_struct):
    def __init__(self, host_ptr=0, destination=0):
        super().__init__(62)
        self.host_ptr = host_ptr
        self.destination = destination

    def _get_as_sub_field(data, offset_in_data):
        result = npl_em_result_ptr_and_l3_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def host_ptr(self):
        return npl_host_nh_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 26)
    @host_ptr.setter
    def host_ptr(self, value):
        self._set_field_value('field host_ptr', 26, 36, npl_host_nh_ptr_t, value)
    @property
    def destination(self):
        return npl_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination.setter
    def destination(self, value):
        self._set_field_value('field destination', 0, 20, npl_destination_t, value)



class npl_inject_down_data_t(basic_npl_struct):
    def __init__(self, bfd_ih_down=0, inject_down=0, counter_ptr=0):
        super().__init__(80)
        self.bfd_ih_down = bfd_ih_down
        self.inject_down = inject_down
        self.counter_ptr = counter_ptr

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_down_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def bfd_ih_down(self):
        return npl_inject_down_encap_ptr_or_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 48)
    @bfd_ih_down.setter
    def bfd_ih_down(self, value):
        self._set_field_value('field bfd_ih_down', 48, 32, npl_inject_down_encap_ptr_or_dlp_t, value)
    @property
    def inject_down(self):
        return npl_inject_down_header_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @inject_down.setter
    def inject_down(self, value):
        self._set_field_value('field inject_down', 20, 28, npl_inject_down_header_t, value)
    @property
    def counter_ptr(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @counter_ptr.setter
    def counter_ptr(self, value):
        self._set_field_value('field counter_ptr', 0, 20, npl_counter_ptr_t, value)



class npl_inject_specific_data_t_anonymous_union_inject_data_t(basic_npl_struct):
    def __init__(self):
        super().__init__(36)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_specific_data_t_anonymous_union_inject_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inject_down_u(self):
        return npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @inject_down_u.setter
    def inject_down_u(self, value):
        self._set_field_value('field inject_down_u', 8, 28, npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t, value)
    @property
    def inject_up_eth(self):
        return npl_inject_up_eth_header_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @inject_up_eth.setter
    def inject_up_eth(self, value):
        self._set_field_value('field inject_up_eth', 0, 36, npl_inject_up_eth_header_t, value)
    @property
    def inject_up_none_routable_mc_lpts(self):
        return npl_inject_up_none_routable_mc_lpts_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @inject_up_none_routable_mc_lpts.setter
    def inject_up_none_routable_mc_lpts(self, value):
        self._set_field_value('field inject_up_none_routable_mc_lpts', 16, 20, npl_inject_up_none_routable_mc_lpts_t, value)
    @property
    def inject_vxlan_mc_up(self):
        return npl_inject_up_vxlan_mc_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @inject_vxlan_mc_up.setter
    def inject_vxlan_mc_up(self, value):
        self._set_field_value('field inject_vxlan_mc_up', 8, 28, npl_inject_up_vxlan_mc_t, value)



class npl_ip_mc_result_payload_t(basic_npl_struct):
    def __init__(self, global_mcid=0, rpf_destination=0, local_mcid=0, punt_on_rpf_fail=0, punt_and_fwd=0):
        super().__init__(62)
        self.global_mcid = global_mcid
        self.rpf_destination = rpf_destination
        self.local_mcid = local_mcid
        self.punt_on_rpf_fail = punt_on_rpf_fail
        self.punt_and_fwd = punt_and_fwd

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_mc_result_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def global_mcid(self):
        return npl_system_mcid_t._get_as_sub_field(self._data, self._offset_in_data + 38)
    @global_mcid.setter
    def global_mcid(self, value):
        self._set_field_value('field global_mcid', 38, 18, npl_system_mcid_t, value)
    @property
    def rpf_destination(self):
        return npl_rpf_compressed_destination_t._get_as_sub_field(self._data, self._offset_in_data + 18)
    @rpf_destination.setter
    def rpf_destination(self, value):
        self._set_field_value('field rpf_destination', 18, 20, npl_rpf_compressed_destination_t, value)
    @property
    def local_mcid(self):
        return npl_mcid_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @local_mcid.setter
    def local_mcid(self, value):
        self._set_field_value('field local_mcid', 2, 16, npl_mcid_t, value)
    @property
    def punt_on_rpf_fail(self):
        return self._get_field_value(1, 1)
    @punt_on_rpf_fail.setter
    def punt_on_rpf_fail(self, value):
        self._set_field_value('field punt_on_rpf_fail', 1, 1, int, value)
    @property
    def punt_and_fwd(self):
        return self._get_field_value(0, 1)
    @punt_and_fwd.setter
    def punt_and_fwd(self, value):
        self._set_field_value('field punt_and_fwd', 0, 1, int, value)



class npl_ip_mc_result_payload_with_format_t(basic_npl_struct):
    def __init__(self, mc_result_payload=0, format=0):
        super().__init__(64)
        self.mc_result_payload = mc_result_payload
        self.format = format

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_mc_result_payload_with_format_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mc_result_payload(self):
        return npl_ip_mc_result_payload_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @mc_result_payload.setter
    def mc_result_payload(self, value):
        self._set_field_value('field mc_result_payload', 2, 62, npl_ip_mc_result_payload_t, value)
    @property
    def format(self):
        return self._get_field_value(0, 2)
    @format.setter
    def format(self, value):
        self._set_field_value('field format', 0, 2, int, value)



class npl_l3_lp_attributes_t(basic_npl_struct):
    def __init__(self, additional=0, base=0):
        super().__init__(129)
        self.additional = additional
        self.base = base

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_lp_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def additional(self):
        return npl_l3_lp_additional_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 120)
    @additional.setter
    def additional(self, value):
        self._set_field_value('field additional', 120, 9, npl_l3_lp_additional_attributes_t, value)
    @property
    def base(self):
        return npl_base_l3_lp_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @base.setter
    def base(self, value):
        self._set_field_value('field base', 0, 120, npl_base_l3_lp_attributes_t, value)



class npl_lsp_encap_mapping_data_payload_t(basic_npl_struct):
    def __init__(self, label_stack=0, counter_and_flag=0):
        super().__init__(80)
        self.label_stack = label_stack
        self.counter_and_flag = counter_and_flag

    def _get_as_sub_field(data, offset_in_data):
        result = npl_lsp_encap_mapping_data_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def label_stack(self):
        return npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @label_stack.setter
    def label_stack(self, value):
        self._set_field_value('field label_stack', 20, 60, npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t, value)
    @property
    def counter_and_flag(self):
        return npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @counter_and_flag.setter
    def counter_and_flag(self, value):
        self._set_field_value('field counter_and_flag', 0, 20, npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t, value)



class npl_mac_l3_lp_attributes_t(basic_npl_struct):
    def __init__(self, l3_lp_mymac_da_prefix=0, mldp_budnode_terminate=0, l3_lp_mymac_da_lsb=0, base=0):
        super().__init__(142)
        self.l3_lp_mymac_da_prefix = l3_lp_mymac_da_prefix
        self.mldp_budnode_terminate = mldp_budnode_terminate
        self.l3_lp_mymac_da_lsb = l3_lp_mymac_da_lsb
        self.base = base

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_l3_lp_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_lp_mymac_da_prefix(self):
        return self._get_field_value(137, 5)
    @l3_lp_mymac_da_prefix.setter
    def l3_lp_mymac_da_prefix(self, value):
        self._set_field_value('field l3_lp_mymac_da_prefix', 137, 5, int, value)
    @property
    def mldp_budnode_terminate(self):
        return self._get_field_value(136, 1)
    @mldp_budnode_terminate.setter
    def mldp_budnode_terminate(self, value):
        self._set_field_value('field mldp_budnode_terminate', 136, 1, int, value)
    @property
    def l3_lp_mymac_da_lsb(self):
        return self._get_field_value(120, 16)
    @l3_lp_mymac_da_lsb.setter
    def l3_lp_mymac_da_lsb(self, value):
        self._set_field_value('field l3_lp_mymac_da_lsb', 120, 16, int, value)
    @property
    def base(self):
        return npl_base_l3_lp_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @base.setter
    def base(self, value):
        self._set_field_value('field base', 0, 120, npl_base_l3_lp_attributes_t, value)



class npl_mac_lp_attributes_payload_t_anonymous_union_layer_t(basic_npl_struct):
    def __init__(self):
        super().__init__(142)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_lp_attributes_payload_t_anonymous_union_layer_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def two(self):
        return npl_l2_lp_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @two.setter
    def two(self, value):
        self._set_field_value('field two', 0, 142, npl_l2_lp_attributes_t, value)
    @property
    def three(self):
        return npl_mac_l3_lp_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @three.setter
    def three(self, value):
        self._set_field_value('field three', 0, 142, npl_mac_l3_lp_attributes_t, value)
    @property
    def pd(self):
        return npl_pd_lp_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @pd.setter
    def pd(self, value):
        self._set_field_value('field pd', 0, 142, npl_pd_lp_attributes_t, value)



class npl_mpls_termination_result_t(basic_npl_struct):
    def __init__(self, service=0, pwe_vpn_mldp_info=0):
        super().__init__(49)
        self.service = service
        self.pwe_vpn_mldp_info = pwe_vpn_mldp_info

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mpls_termination_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def service(self):
        return self._get_field_value(47, 2)
    @service.setter
    def service(self, value):
        self._set_field_value('field service', 47, 2, int, value)
    @property
    def pwe_vpn_mldp_info(self):
        return npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @pwe_vpn_mldp_info.setter
    def pwe_vpn_mldp_info(self, value):
        self._set_field_value('field pwe_vpn_mldp_info', 0, 47, npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t, value)



class npl_nhlfe_t(basic_npl_struct):
    def __init__(self, type=0, nhlfe_payload=0):
        super().__init__(64)
        self.type = type
        self.nhlfe_payload = nhlfe_payload

    def _get_as_sub_field(data, offset_in_data):
        result = npl_nhlfe_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def type(self):
        return self._get_field_value(60, 4)
    @type.setter
    def type(self, value):
        self._set_field_value('field type', 60, 4, int, value)
    @property
    def nhlfe_payload(self):
        return npl_nhlfe_t_anonymous_union_nhlfe_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @nhlfe_payload.setter
    def nhlfe_payload(self, value):
        self._set_field_value('field nhlfe_payload', 0, 60, npl_nhlfe_t_anonymous_union_nhlfe_payload_t, value)



class npl_npu_encap_header_ip_host_t(basic_npl_struct):
    def __init__(self, l3_encapsulation_type=0, next_hop=0):
        super().__init__(68)
        self.l3_encapsulation_type = l3_encapsulation_type
        self.next_hop = next_hop

    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_encap_header_ip_host_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_encapsulation_type(self):
        return self._get_field_value(64, 4)
    @l3_encapsulation_type.setter
    def l3_encapsulation_type(self, value):
        self._set_field_value('field l3_encapsulation_type', 64, 4, int, value)
    @property
    def next_hop(self):
        return npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @next_hop.setter
    def next_hop(self, value):
        self._set_field_value('field next_hop', 0, 64, npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t, value)



class npl_npu_l2_encap_header_t(basic_npl_struct):
    def __init__(self, l2_encapsulation_type=0, l2_dlp_type=0, npu_pif_ifg=0):
        super().__init__(80)
        self.l2_encapsulation_type = l2_encapsulation_type
        self.l2_dlp_type = l2_dlp_type
        self.npu_pif_ifg = npu_pif_ifg

    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_l2_encap_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2_encapsulation_type(self):
        return self._get_field_value(76, 4)
    @l2_encapsulation_type.setter
    def l2_encapsulation_type(self, value):
        self._set_field_value('field l2_encapsulation_type', 76, 4, int, value)
    @property
    def l2_dlp_type(self):
        return npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @l2_dlp_type.setter
    def l2_dlp_type(self, value):
        self._set_field_value('field l2_dlp_type', 8, 68, npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t, value)
    @property
    def npu_pif_ifg(self):
        return npl_npu_dsp_pif_ifg_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @npu_pif_ifg.setter
    def npu_pif_ifg(self, value):
        self._set_field_value('field npu_pif_ifg', 0, 8, npl_npu_dsp_pif_ifg_t, value)



class npl_punt_encap_data_t(basic_npl_struct):
    def __init__(self, punt_msb_encap=0, punt_lsb_encap=0):
        super().__init__(80)
        self.punt_msb_encap = punt_msb_encap
        self.punt_lsb_encap = punt_lsb_encap

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def punt_msb_encap(self):
        return npl_punt_msb_encap_t._get_as_sub_field(self._data, self._offset_in_data + 40)
    @punt_msb_encap.setter
    def punt_msb_encap(self, value):
        self._set_field_value('field punt_msb_encap', 40, 40, npl_punt_msb_encap_t, value)
    @property
    def punt_lsb_encap(self):
        return npl_punt_lsb_encap_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_lsb_encap.setter
    def punt_lsb_encap(self, value):
        self._set_field_value('field punt_lsb_encap', 0, 40, npl_punt_lsb_encap_t, value)



class npl_punt_l3_lp_t(basic_npl_struct):
    def __init__(self, id_or_pfc=0):
        super().__init__(16)
        self.id_or_pfc = id_or_pfc

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_l3_lp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def id_or_pfc(self):
        return npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @id_or_pfc.setter
    def id_or_pfc(self, value):
        self._set_field_value('field id_or_pfc', 0, 16, npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t, value)



class npl_resolution_result_enc_data_t(basic_npl_struct):
    def __init__(self):
        super().__init__(80)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_resolution_result_enc_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2(self):
        return npl_npu_l2_encap_header_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2.setter
    def l2(self, value):
        self._set_field_value('field l2', 0, 80, npl_npu_l2_encap_header_t, value)
    @property
    def l3(self):
        return npl_npu_l3_encap_header_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3.setter
    def l3(self, value):
        self._set_field_value('field l3', 0, 80, npl_npu_l3_encap_header_t, value)
    @property
    def ip_collapsed_mc_encap_header(self):
        return npl_npu_ip_collapsed_mc_encap_header_t._get_as_sub_field(self._data, self._offset_in_data + 40)
    @ip_collapsed_mc_encap_header.setter
    def ip_collapsed_mc_encap_header(self, value):
        self._set_field_value('field ip_collapsed_mc_encap_header', 40, 40, npl_npu_ip_collapsed_mc_encap_header_t, value)
    @property
    def mpls_mc_host_encap_header(self):
        return npl_npu_encap_header_ip_host_t._get_as_sub_field(self._data, self._offset_in_data + 12)
    @mpls_mc_host_encap_header.setter
    def mpls_mc_host_encap_header(self, value):
        self._set_field_value('field mpls_mc_host_encap_header', 12, 68, npl_npu_encap_header_ip_host_t, value)
    @property
    def dlp_attributes(self):
        return npl_resolution_dlp_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dlp_attributes.setter
    def dlp_attributes(self, value):
        self._set_field_value('field dlp_attributes', 0, 8, npl_resolution_dlp_attributes_t, value)
    @property
    def pif_ifg_data(self):
        return npl_npu_dsp_pif_ifg_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @pif_ifg_data.setter
    def pif_ifg_data(self, value):
        self._set_field_value('field pif_ifg_data', 0, 8, npl_npu_dsp_pif_ifg_t, value)



class npl_slp_info_t(basic_npl_struct):
    def __init__(self, slp_profile=0, global_slp_id=0):
        super().__init__(22)
        self.slp_profile = slp_profile
        self.global_slp_id = global_slp_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_slp_info_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def slp_profile(self):
        return self._get_field_value(20, 2)
    @slp_profile.setter
    def slp_profile(self, value):
        self._set_field_value('field slp_profile', 20, 2, int, value)
    @property
    def global_slp_id(self):
        return npl_slp_info_t_anonymous_union_global_slp_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @global_slp_id.setter
    def global_slp_id(self, value):
        self._set_field_value('field global_slp_id', 0, 20, npl_slp_info_t_anonymous_union_global_slp_id_t, value)



class npl_std_ip_em_lpm_result_mc_t(basic_npl_struct):
    def __init__(self, mc_result=0):
        super().__init__(84)
        self.mc_result = mc_result

    def _get_as_sub_field(data, offset_in_data):
        result = npl_std_ip_em_lpm_result_mc_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mc_result(self):
        return npl_ip_mc_result_payload_with_format_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @mc_result.setter
    def mc_result(self, value):
        self._set_field_value('field mc_result', 20, 64, npl_ip_mc_result_payload_with_format_t, value)



class npl_wrap_nhlfe_t(basic_npl_struct):
    def __init__(self, nhlfe=0):
        super().__init__(64)
        self.nhlfe = nhlfe

    def _get_as_sub_field(data, offset_in_data):
        result = npl_wrap_nhlfe_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def nhlfe(self):
        return npl_nhlfe_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @nhlfe.setter
    def nhlfe(self, value):
        self._set_field_value('field nhlfe', 0, 64, npl_nhlfe_t, value)



class npl_ac_dlp_specific_t(basic_npl_struct):
    def __init__(self, vlan_after_eve_format=0, eve_types=0, mep_exists=0, max_mep_level=0):
        super().__init__(52)
        self.vlan_after_eve_format = vlan_after_eve_format
        self.eve_types = eve_types
        self.mep_exists = mep_exists
        self.max_mep_level = max_mep_level

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ac_dlp_specific_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def vlan_after_eve_format(self):
        return self._get_field_value(32, 20)
    @vlan_after_eve_format.setter
    def vlan_after_eve_format(self, value):
        self._set_field_value('field vlan_after_eve_format', 32, 20, int, value)
    @property
    def eve_types(self):
        return npl_ac_dlp_specific_t_anonymous_union_eve_types_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @eve_types.setter
    def eve_types(self, value):
        self._set_field_value('field eve_types', 4, 28, npl_ac_dlp_specific_t_anonymous_union_eve_types_t, value)
    @property
    def mep_exists(self):
        return self._get_field_value(3, 1)
    @mep_exists.setter
    def mep_exists(self, value):
        self._set_field_value('field mep_exists', 3, 1, int, value)
    @property
    def max_mep_level(self):
        return self._get_field_value(0, 3)
    @max_mep_level.setter
    def max_mep_level(self, value):
        self._set_field_value('field max_mep_level', 0, 3, int, value)



class npl_app_mc_cud_t(basic_npl_struct):
    def __init__(self, npu_encap_data=0):
        super().__init__(80)
        self.npu_encap_data = npu_encap_data

    def _get_as_sub_field(data, offset_in_data):
        result = npl_app_mc_cud_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def npu_encap_data(self):
        return npl_resolution_result_enc_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @npu_encap_data.setter
    def npu_encap_data(self, value):
        self._set_field_value('field npu_encap_data', 0, 80, npl_resolution_result_enc_data_t, value)



class npl_base_l3_lp_attr_union_t(basic_npl_struct):
    def __init__(self):
        super().__init__(120)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_base_l3_lp_attr_union_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def update(self):
        return npl_lp_attr_update_raw_bits_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @update.setter
    def update(self, value):
        self._set_field_value('field update', 0, 120, npl_lp_attr_update_raw_bits_t, value)
    @property
    def base(self):
        return npl_base_l3_lp_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @base.setter
    def base(self, value):
        self._set_field_value('field base', 0, 120, npl_base_l3_lp_attributes_t, value)



class npl_inject_specific_data_t(basic_npl_struct):
    def __init__(self, inject_data=0):
        super().__init__(36)
        self.inject_data = inject_data

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_specific_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inject_data(self):
        return npl_inject_specific_data_t_anonymous_union_inject_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @inject_data.setter
    def inject_data(self, value):
        self._set_field_value('field inject_data', 0, 36, npl_inject_specific_data_t_anonymous_union_inject_data_t, value)



class npl_ip_em_lpm_result_t_anonymous_union_result_t(basic_npl_struct):
    def __init__(self):
        super().__init__(84)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_em_lpm_result_t_anonymous_union_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def destination_from_em(self):
        return npl_std_ip_em_lpm_result_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination_from_em.setter
    def destination_from_em(self, value):
        self._set_field_value('field destination_from_em', 0, 84, npl_std_ip_em_lpm_result_destination_t, value)
    @property
    def ptr_and_l3_dlp(self):
        return npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ptr_and_l3_dlp.setter
    def ptr_and_l3_dlp(self, value):
        self._set_field_value('field ptr_and_l3_dlp', 0, 84, npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t, value)
    @property
    def host_and_l3_dlp(self):
        return npl_std_ip_em_lpm_result_host_and_l3_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @host_and_l3_dlp.setter
    def host_and_l3_dlp(self, value):
        self._set_field_value('field host_and_l3_dlp', 0, 84, npl_std_ip_em_lpm_result_host_and_l3_dlp_t, value)
    @property
    def destination_from_lpm(self):
        return npl_std_ip_em_lpm_result_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination_from_lpm.setter
    def destination_from_lpm(self, value):
        self._set_field_value('field destination_from_lpm', 0, 84, npl_std_ip_em_lpm_result_destination_t, value)
    @property
    def destination_with_default(self):
        return npl_std_ip_em_lpm_result_destination_with_default_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @destination_with_default.setter
    def destination_with_default(self, value):
        self._set_field_value('field destination_with_default', 0, 84, npl_std_ip_em_lpm_result_destination_with_default_t, value)
    @property
    def mc_std_result(self):
        return npl_std_ip_em_lpm_result_mc_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mc_std_result.setter
    def mc_std_result(self, value):
        self._set_field_value('field mc_std_result', 0, 84, npl_std_ip_em_lpm_result_mc_t, value)



class npl_ip_em_result_t_anonymous_union_result_t(basic_npl_struct):
    def __init__(self):
        super().__init__(62)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_em_result_t_anonymous_union_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def em_dest(self):
        return npl_em_destination_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @em_dest.setter
    def em_dest(self, value):
        self._set_field_value('field em_dest', 0, 62, npl_em_destination_t, value)
    @property
    def ptr_and_l3_dlp(self):
        return npl_em_result_ptr_and_l3_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ptr_and_l3_dlp.setter
    def ptr_and_l3_dlp(self, value):
        self._set_field_value('field ptr_and_l3_dlp', 0, 62, npl_em_result_ptr_and_l3_dlp_t, value)
    @property
    def dsp_host(self):
        return npl_em_result_dsp_host_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @dsp_host.setter
    def dsp_host(self, value):
        self._set_field_value('field dsp_host', 0, 62, npl_em_result_dsp_host_t, value)
    @property
    def mc_result(self):
        return npl_ip_mc_result_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mc_result.setter
    def mc_result(self, value):
        self._set_field_value('field mc_result', 0, 62, npl_ip_mc_result_payload_t, value)



class npl_ip_mc_result_em_payload_t(basic_npl_struct):
    def __init__(self, raw_payload=0):
        super().__init__(64)
        self.raw_payload = raw_payload

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_mc_result_em_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def raw_payload(self):
        return npl_ip_mc_result_payload_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @raw_payload.setter
    def raw_payload(self, value):
        self._set_field_value('field raw_payload', 2, 62, npl_ip_mc_result_payload_t, value)



class npl_l2_dlp_specific_t(basic_npl_struct):
    def __init__(self):
        super().__init__(52)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_dlp_specific_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ac(self):
        return npl_ac_dlp_specific_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ac.setter
    def ac(self, value):
        self._set_field_value('field ac', 0, 52, npl_ac_dlp_specific_t, value)
    @property
    def pwe(self):
        return npl_pwe_dlp_specific_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @pwe.setter
    def pwe(self, value):
        self._set_field_value('field pwe', 0, 52, npl_pwe_dlp_specific_t, value)



class npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_lp(self):
        return npl_punt_l3_lp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_lp.setter
    def l3_lp(self, value):
        self._set_field_value('field l3_lp', 0, 16, npl_punt_l3_lp_t, value)
    @property
    def pfc(self):
        return npl_l3_pfc_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @pfc.setter
    def pfc(self, value):
        self._set_field_value('field pfc', 0, 15, npl_l3_pfc_data_t, value)



class npl_l3_lp_with_padding_t(basic_npl_struct):
    def __init__(self, l3_lp=0):
        super().__init__(20)
        self.l3_lp = l3_lp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_lp_with_padding_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_lp(self):
        return npl_punt_l3_lp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_lp.setter
    def l3_lp(self, value):
        self._set_field_value('field l3_lp', 0, 16, npl_punt_l3_lp_t, value)



class npl_mac_lp_attributes_payload_t(basic_npl_struct):
    def __init__(self, mac_lp_type=0, layer=0):
        super().__init__(144)
        self.mac_lp_type = mac_lp_type
        self.layer = layer

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_lp_attributes_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mac_lp_type(self):
        return self._get_field_value(142, 1)
    @mac_lp_type.setter
    def mac_lp_type(self, value):
        self._set_field_value('field mac_lp_type', 142, 1, int, value)
    @property
    def layer(self):
        return npl_mac_lp_attributes_payload_t_anonymous_union_layer_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @layer.setter
    def layer(self, value):
        self._set_field_value('field layer', 0, 142, npl_mac_lp_attributes_payload_t_anonymous_union_layer_t, value)



class npl_mac_lp_attributes_t(basic_npl_struct):
    def __init__(self, payload=0, local_slp_id=0):
        super().__init__(160)
        self.payload = payload
        self.local_slp_id = local_slp_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_lp_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def payload(self):
        return npl_mac_lp_attributes_payload_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @payload.setter
    def payload(self, value):
        self._set_field_value('field payload', 16, 144, npl_mac_lp_attributes_payload_t, value)
    @property
    def local_slp_id(self):
        return npl_lp_id_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @local_slp_id.setter
    def local_slp_id(self, value):
        self._set_field_value('field local_slp_id', 0, 16, npl_lp_id_t, value)



class npl_mac_lp_attributes_table_payload_t(basic_npl_struct):
    def __init__(self):
        super().__init__(144)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_lp_attributes_table_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def lp_attr(self):
        return npl_mac_lp_attributes_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @lp_attr.setter
    def lp_attr(self, value):
        self._set_field_value('field lp_attr', 0, 144, npl_mac_lp_attributes_payload_t, value)



class npl_mac_relay_pack_table_payload_t(basic_npl_struct):
    def __init__(self, local_mapped_qos_group=0, muxed_slp_info=0):
        super().__init__(29)
        self.local_mapped_qos_group = local_mapped_qos_group
        self.muxed_slp_info = muxed_slp_info

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mac_relay_pack_table_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def local_mapped_qos_group(self):
        return self._get_field_value(22, 7)
    @local_mapped_qos_group.setter
    def local_mapped_qos_group(self, value):
        self._set_field_value('field local_mapped_qos_group', 22, 7, int, value)
    @property
    def muxed_slp_info(self):
        return npl_slp_info_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @muxed_slp_info.setter
    def muxed_slp_info(self, value):
        self._set_field_value('field muxed_slp_info', 0, 22, npl_slp_info_t, value)



class npl_mpls_termination_res_t(basic_npl_struct):
    def __init__(self, result=0):
        super().__init__(49)
        self.result = result

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mpls_termination_res_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def result(self):
        return npl_mpls_termination_result_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @result.setter
    def result(self, value):
        self._set_field_value('field result', 0, 49, npl_mpls_termination_result_t, value)



class npl_punt_app_encap_t(basic_npl_struct):
    def __init__(self):
        super().__init__(80)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_app_encap_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def punt_encap_data(self):
        return npl_punt_encap_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @punt_encap_data.setter
    def punt_encap_data(self, value):
        self._set_field_value('field punt_encap_data', 0, 80, npl_punt_encap_data_t, value)
    @property
    def fabric_mc_ibm_cmd(self):
        return npl_fabric_mc_ibm_cmd_t._get_as_sub_field(self._data, self._offset_in_data + 56)
    @fabric_mc_ibm_cmd.setter
    def fabric_mc_ibm_cmd(self, value):
        self._set_field_value('field fabric_mc_ibm_cmd', 56, 24, npl_fabric_mc_ibm_cmd_t, value)
    @property
    def dcf_data(self):
        return self._get_field_value(42, 38)
    @dcf_data.setter
    def dcf_data(self, value):
        self._set_field_value('field dcf_data', 42, 38, int, value)



class npl_punt_header_t_anonymous_union_slp_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_header_t_anonymous_union_slp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2_slp(self):
        return npl_l2_lp_with_padding_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_slp.setter
    def l2_slp(self, value):
        self._set_field_value('field l2_slp', 0, 20, npl_l2_lp_with_padding_t, value)
    @property
    def l3_slp(self):
        return npl_l3_lp_with_padding_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_slp.setter
    def l3_slp(self, value):
        self._set_field_value('field l3_slp', 0, 20, npl_l3_lp_with_padding_t, value)



class npl_raw_ip_mc_result_t(basic_npl_struct):
    def __init__(self, result_payload=0):
        super().__init__(64)
        self.result_payload = result_payload

    def _get_as_sub_field(data, offset_in_data):
        result = npl_raw_ip_mc_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def result_payload(self):
        return npl_ip_mc_result_em_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @result_payload.setter
    def result_payload(self, value):
        self._set_field_value('field result_payload', 0, 64, npl_ip_mc_result_em_payload_t, value)



class npl_app_mirror_cud_t(basic_npl_struct):
    def __init__(self):
        super().__init__(80)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_app_mirror_cud_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mirror_cud_encap(self):
        return npl_punt_app_encap_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mirror_cud_encap.setter
    def mirror_cud_encap(self, value):
        self._set_field_value('field mirror_cud_encap', 0, 80, npl_punt_app_encap_t, value)



class npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t(basic_npl_struct):
    def __init__(self):
        super().__init__(80)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def app_mc_cud(self):
        return npl_app_mc_cud_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @app_mc_cud.setter
    def app_mc_cud(self, value):
        self._set_field_value('field app_mc_cud', 0, 80, npl_app_mc_cud_t, value)
    @property
    def mirror(self):
        return npl_app_mirror_cud_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mirror.setter
    def mirror(self, value):
        self._set_field_value('field mirror', 0, 80, npl_app_mirror_cud_t, value)



class npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2_slp(self):
        return npl_l2_lp_with_padding_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_slp.setter
    def l2_slp(self, value):
        self._set_field_value('field l2_slp', 0, 20, npl_l2_lp_with_padding_t, value)
    @property
    def l3_slp(self):
        return npl_l3_lp_with_padding_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_slp.setter
    def l3_slp(self, value):
        self._set_field_value('field l3_slp', 0, 20, npl_l3_lp_with_padding_t, value)



class npl_ibm_encap_header_on_direct_t(basic_npl_struct):
    def __init__(self, wide_bit=0, ibm_encap_header=0):
        super().__init__(129)
        self.wide_bit = wide_bit
        self.ibm_encap_header = ibm_encap_header

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ibm_encap_header_on_direct_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def wide_bit(self):
        return self._get_field_value(128, 1)
    @wide_bit.setter
    def wide_bit(self, value):
        self._set_field_value('field wide_bit', 128, 1, int, value)
    @property
    def ibm_encap_header(self):
        return npl_punt_app_encap_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ibm_encap_header.setter
    def ibm_encap_header(self, value):
        self._set_field_value('field ibm_encap_header', 0, 80, npl_punt_app_encap_t, value)



class npl_inject_header_app_specific_data_t(basic_npl_struct):
    def __init__(self, inject_specific_data=0, counter_ptr=0):
        super().__init__(56)
        self.inject_specific_data = inject_specific_data
        self.counter_ptr = counter_ptr

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_header_app_specific_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inject_specific_data(self):
        return npl_inject_specific_data_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @inject_specific_data.setter
    def inject_specific_data(self, value):
        self._set_field_value('field inject_specific_data', 20, 36, npl_inject_specific_data_t, value)
    @property
    def counter_ptr(self):
        return npl_counter_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @counter_ptr.setter
    def counter_ptr(self, value):
        self._set_field_value('field counter_ptr', 0, 20, npl_counter_ptr_t, value)



class npl_inject_header_specific_data_t(basic_npl_struct):
    def __init__(self, inject_header_app_specific_data=0, inject_header_encap_hdr_ptr=0):
        super().__init__(88)
        self.inject_header_app_specific_data = inject_header_app_specific_data
        self.inject_header_encap_hdr_ptr = inject_header_encap_hdr_ptr

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_header_specific_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inject_header_app_specific_data(self):
        return npl_inject_header_app_specific_data_t._get_as_sub_field(self._data, self._offset_in_data + 32)
    @inject_header_app_specific_data.setter
    def inject_header_app_specific_data(self, value):
        self._set_field_value('field inject_header_app_specific_data', 32, 56, npl_inject_header_app_specific_data_t, value)
    @property
    def inject_header_encap_hdr_ptr(self):
        return npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @inject_header_encap_hdr_ptr.setter
    def inject_header_encap_hdr_ptr(self, value):
        self._set_field_value('field inject_header_encap_hdr_ptr', 0, 32, npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t, value)



class npl_inject_header_t(basic_npl_struct):
    def __init__(self, inject_header_type=0, inject_header_specific_data=0, ts_and_cntr_stamp_cmd=0, npl_internal_info=0, inject_header_trailer_type=0):
        super().__init__(136)
        self.inject_header_type = inject_header_type
        self.inject_header_specific_data = inject_header_specific_data
        self.ts_and_cntr_stamp_cmd = ts_and_cntr_stamp_cmd
        self.npl_internal_info = npl_internal_info
        self.inject_header_trailer_type = inject_header_trailer_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inject_header_type(self):
        return self._get_field_value(128, 8)
    @inject_header_type.setter
    def inject_header_type(self, value):
        self._set_field_value('field inject_header_type', 128, 8, int, value)
    @property
    def inject_header_specific_data(self):
        return npl_inject_header_specific_data_t._get_as_sub_field(self._data, self._offset_in_data + 40)
    @inject_header_specific_data.setter
    def inject_header_specific_data(self, value):
        self._set_field_value('field inject_header_specific_data', 40, 88, npl_inject_header_specific_data_t, value)
    @property
    def ts_and_cntr_stamp_cmd(self):
        return npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t._get_as_sub_field(self._data, self._offset_in_data + 16)
    @ts_and_cntr_stamp_cmd.setter
    def ts_and_cntr_stamp_cmd(self, value):
        self._set_field_value('field ts_and_cntr_stamp_cmd', 16, 24, npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t, value)
    @property
    def npl_internal_info(self):
        return npl_npl_internal_info_t._get_as_sub_field(self._data, self._offset_in_data + 8)
    @npl_internal_info.setter
    def npl_internal_info(self, value):
        self._set_field_value('field npl_internal_info', 8, 8, npl_npl_internal_info_t, value)
    @property
    def inject_header_trailer_type(self):
        return self._get_field_value(0, 8)
    @inject_header_trailer_type.setter
    def inject_header_trailer_type(self, value):
        self._set_field_value('field inject_header_trailer_type', 0, 8, int, value)



class npl_inject_header_with_time_t(basic_npl_struct):
    def __init__(self, base_inject_header=0, time_extension=0):
        super().__init__(168)
        self.base_inject_header = base_inject_header
        self.time_extension = time_extension

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_header_with_time_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def base_inject_header(self):
        return npl_inject_header_t._get_as_sub_field(self._data, self._offset_in_data + 32)
    @base_inject_header.setter
    def base_inject_header(self, value):
        self._set_field_value('field base_inject_header', 32, 136, npl_inject_header_t, value)
    @property
    def time_extension(self):
        return self._get_field_value(0, 32)
    @time_extension.setter
    def time_extension(self, value):
        self._set_field_value('field time_extension', 0, 32, int, value)



class npl_inject_up_data_t(basic_npl_struct):
    def __init__(self, bfd_ih_app=0, inject_vlan_id=0):
        super().__init__(80)
        self.bfd_ih_app = bfd_ih_app
        self.inject_vlan_id = inject_vlan_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_inject_up_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def bfd_ih_app(self):
        return npl_inject_header_app_specific_data_t._get_as_sub_field(self._data, self._offset_in_data + 24)
    @bfd_ih_app.setter
    def bfd_ih_app(self, value):
        self._set_field_value('field bfd_ih_app', 24, 56, npl_inject_header_app_specific_data_t, value)
    @property
    def inject_vlan_id(self):
        return self._get_field_value(0, 12)
    @inject_vlan_id.setter
    def inject_vlan_id(self, value):
        self._set_field_value('field inject_vlan_id', 0, 12, int, value)



class npl_ip_em_lpm_result_t(basic_npl_struct):
    def __init__(self, result=0, result_type=0, no_hbm_access=0, is_default_unused=0):
        super().__init__(88)
        self.result = result
        self.result_type = result_type
        self.no_hbm_access = no_hbm_access
        self.is_default_unused = is_default_unused

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_em_lpm_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def result(self):
        return npl_ip_em_lpm_result_t_anonymous_union_result_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @result.setter
    def result(self, value):
        self._set_field_value('field result', 4, 84, npl_ip_em_lpm_result_t_anonymous_union_result_t, value)
    @property
    def result_type(self):
        return self._get_field_value(2, 2)
    @result_type.setter
    def result_type(self, value):
        self._set_field_value('field result_type', 2, 2, int, value)
    @property
    def no_hbm_access(self):
        return self._get_field_value(1, 1)
    @no_hbm_access.setter
    def no_hbm_access(self, value):
        self._set_field_value('field no_hbm_access', 1, 1, int, value)
    @property
    def is_default_unused(self):
        return self._get_field_value(0, 1)
    @is_default_unused.setter
    def is_default_unused(self, value):
        self._set_field_value('field is_default_unused', 0, 1, int, value)



class npl_ip_em_result_t(basic_npl_struct):
    def __init__(self, result=0, result_type=0):
        super().__init__(64)
        self.result = result
        self.result_type = result_type

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ip_em_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def result(self):
        return npl_ip_em_result_t_anonymous_union_result_t._get_as_sub_field(self._data, self._offset_in_data + 2)
    @result.setter
    def result(self, value):
        self._set_field_value('field result', 2, 62, npl_ip_em_result_t_anonymous_union_result_t, value)
    @property
    def result_type(self):
        return self._get_field_value(0, 2)
    @result_type.setter
    def result_type(self, value):
        self._set_field_value('field result_type', 0, 2, int, value)



class npl_l2_dlp_attributes_t(basic_npl_struct):
    def __init__(self, disabled=0, stp_state_is_block=0, tx_to_rx_rcy_data=0, l2_dlp_specific=0, dlp_attributes=0, qos_attributes=0, acl_id=0):
        super().__init__(118)
        self.disabled = disabled
        self.stp_state_is_block = stp_state_is_block
        self.tx_to_rx_rcy_data = tx_to_rx_rcy_data
        self.l2_dlp_specific = l2_dlp_specific
        self.dlp_attributes = dlp_attributes
        self.qos_attributes = qos_attributes
        self.acl_id = acl_id

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l2_dlp_attributes_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def disabled(self):
        return self._get_field_value(117, 1)
    @disabled.setter
    def disabled(self, value):
        self._set_field_value('field disabled', 117, 1, int, value)
    @property
    def stp_state_is_block(self):
        return self._get_field_value(116, 1)
    @stp_state_is_block.setter
    def stp_state_is_block(self, value):
        self._set_field_value('field stp_state_is_block', 116, 1, int, value)
    @property
    def tx_to_rx_rcy_data(self):
        return npl_tx_to_rx_rcy_data_t._get_as_sub_field(self._data, self._offset_in_data + 108)
    @tx_to_rx_rcy_data.setter
    def tx_to_rx_rcy_data(self, value):
        self._set_field_value('field tx_to_rx_rcy_data', 108, 8, npl_tx_to_rx_rcy_data_t, value)
    @property
    def l2_dlp_specific(self):
        return npl_l2_dlp_specific_t._get_as_sub_field(self._data, self._offset_in_data + 56)
    @l2_dlp_specific.setter
    def l2_dlp_specific(self, value):
        self._set_field_value('field l2_dlp_specific', 56, 52, npl_l2_dlp_specific_t, value)
    @property
    def dlp_attributes(self):
        return npl_dlp_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 50)
    @dlp_attributes.setter
    def dlp_attributes(self, value):
        self._set_field_value('field dlp_attributes', 50, 6, npl_dlp_attributes_t, value)
    @property
    def qos_attributes(self):
        return npl_qos_attributes_t._get_as_sub_field(self._data, self._offset_in_data + 4)
    @qos_attributes.setter
    def qos_attributes(self, value):
        self._set_field_value('field qos_attributes', 4, 46, npl_qos_attributes_t, value)
    @property
    def acl_id(self):
        return self._get_field_value(0, 4)
    @acl_id.setter
    def acl_id(self, value):
        self._set_field_value('field acl_id', 0, 4, int, value)



class npl_l3_lp_extra_data_with_padding_t(basic_npl_struct):
    def __init__(self, l3_punt_info=0):
        super().__init__(20)
        self.l3_punt_info = l3_punt_info

    def _get_as_sub_field(data, offset_in_data):
        result = npl_l3_lp_extra_data_with_padding_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l3_punt_info(self):
        return npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_punt_info.setter
    def l3_punt_info(self, value):
        self._set_field_value('field l3_punt_info', 0, 20, npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t, value)



class npl_pfc_mp_table_shared_payload_t(basic_npl_struct):
    def __init__(self, inj_header=0, inject_ifg_id=0, profile=0):
        super().__init__(160)
        self.inj_header = inj_header
        self.inject_ifg_id = inject_ifg_id
        self.profile = profile

    def _get_as_sub_field(data, offset_in_data):
        result = npl_pfc_mp_table_shared_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inj_header(self):
        return npl_inject_header_t._get_as_sub_field(self._data, self._offset_in_data + 24)
    @inj_header.setter
    def inj_header(self, value):
        self._set_field_value('field inj_header', 24, 136, npl_inject_header_t, value)
    @property
    def inject_ifg_id(self):
        return self._get_field_value(20, 4)
    @inject_ifg_id.setter
    def inject_ifg_id(self, value):
        self._set_field_value('field inject_ifg_id', 20, 4, int, value)
    @property
    def profile(self):
        return self._get_field_value(16, 2)
    @profile.setter
    def profile(self, value):
        self._set_field_value('field profile', 16, 2, int, value)



class npl_punt_header_t_anonymous_union_dlp_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_header_t_anonymous_union_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2_dlp(self):
        return npl_l2_lp_with_padding_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_dlp.setter
    def l2_dlp(self, value):
        self._set_field_value('field l2_dlp', 0, 20, npl_l2_lp_with_padding_t, value)
    @property
    def l3_dlp(self):
        return npl_l3_lp_extra_data_with_padding_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_dlp.setter
    def l3_dlp(self, value):
        self._set_field_value('field l3_dlp', 0, 20, npl_l3_lp_extra_data_with_padding_t, value)



class npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t(basic_npl_struct):
    def __init__(self):
        super().__init__(80)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inject_down_data(self):
        return npl_inject_down_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @inject_down_data.setter
    def inject_down_data(self, value):
        self._set_field_value('field inject_down_data', 0, 80, npl_inject_down_data_t, value)
    @property
    def inject_up_data(self):
        return npl_inject_up_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @inject_up_data.setter
    def inject_up_data(self, value):
        self._set_field_value('field inject_up_data', 0, 80, npl_inject_up_data_t, value)



class npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t(basic_npl_struct):
    def __init__(self):
        super().__init__(20)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def l2_dlp(self):
        return npl_l2_lp_with_padding_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l2_dlp.setter
    def l2_dlp(self, value):
        self._set_field_value('field l2_dlp', 0, 20, npl_l2_lp_with_padding_t, value)
    @property
    def l3_dlp(self):
        return npl_l3_lp_extra_data_with_padding_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @l3_dlp.setter
    def l3_dlp(self, value):
        self._set_field_value('field l3_dlp', 0, 20, npl_l3_lp_extra_data_with_padding_t, value)



class npl_eth_mp_table_shared_payload_t(basic_npl_struct):
    def __init__(self, punt_code=0, meg_id_format=0, dmr_lmr_da=0, md_level=0, ccm_period=0, mep_address_lsb=0, per_tc_count=0, mep_address_prefix_index=0, inject_header_data=0):
        super().__init__(100)
        self.punt_code = punt_code
        self.meg_id_format = meg_id_format
        self.dmr_lmr_da = dmr_lmr_da
        self.md_level = md_level
        self.ccm_period = ccm_period
        self.mep_address_lsb = mep_address_lsb
        self.per_tc_count = per_tc_count
        self.mep_address_prefix_index = mep_address_prefix_index
        self.inject_header_data = inject_header_data

    def _get_as_sub_field(data, offset_in_data):
        result = npl_eth_mp_table_shared_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def punt_code(self):
        return npl_punt_code_t._get_as_sub_field(self._data, self._offset_in_data + 92)
    @punt_code.setter
    def punt_code(self, value):
        self._set_field_value('field punt_code', 92, 8, npl_punt_code_t, value)
    @property
    def meg_id_format(self):
        return self._get_field_value(88, 1)
    @meg_id_format.setter
    def meg_id_format(self, value):
        self._set_field_value('field meg_id_format', 88, 1, int, value)
    @property
    def dmr_lmr_da(self):
        return self._get_field_value(84, 1)
    @dmr_lmr_da.setter
    def dmr_lmr_da(self, value):
        self._set_field_value('field dmr_lmr_da', 84, 1, int, value)
    @property
    def md_level(self):
        return self._get_field_value(80, 3)
    @md_level.setter
    def md_level(self, value):
        self._set_field_value('field md_level', 80, 3, int, value)
    @property
    def ccm_period(self):
        return self._get_field_value(76, 3)
    @ccm_period.setter
    def ccm_period(self, value):
        self._set_field_value('field ccm_period', 76, 3, int, value)
    @property
    def mep_address_lsb(self):
        return self._get_field_value(60, 16)
    @mep_address_lsb.setter
    def mep_address_lsb(self, value):
        self._set_field_value('field mep_address_lsb', 60, 16, int, value)
    @property
    def per_tc_count(self):
        return self._get_field_value(58, 1)
    @per_tc_count.setter
    def per_tc_count(self, value):
        self._set_field_value('field per_tc_count', 58, 1, int, value)
    @property
    def mep_address_prefix_index(self):
        return self._get_field_value(56, 2)
    @mep_address_prefix_index.setter
    def mep_address_prefix_index(self, value):
        self._set_field_value('field mep_address_prefix_index', 56, 2, int, value)
    @property
    def inject_header_data(self):
        return npl_inject_header_app_specific_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @inject_header_data.setter
    def inject_header_data(self, value):
        self._set_field_value('field inject_header_data', 0, 56, npl_inject_header_app_specific_data_t, value)



class npl_punt_header_t(basic_npl_struct):
    def __init__(self, punt_next_header=0, punt_fwd_header_type=0, reserved=0, pl_header_offset=0, punt_src_and_code=0, punt_sub_code=0, ssp=0, dsp=0, slp=0, dlp=0, punt_relay_id=0, time_stamp_val=0, receive_time=0):
        super().__init__(224)
        self.punt_next_header = punt_next_header
        self.punt_fwd_header_type = punt_fwd_header_type
        self.reserved = reserved
        self.pl_header_offset = pl_header_offset
        self.punt_src_and_code = punt_src_and_code
        self.punt_sub_code = punt_sub_code
        self.ssp = ssp
        self.dsp = dsp
        self.slp = slp
        self.dlp = dlp
        self.punt_relay_id = punt_relay_id
        self.time_stamp_val = time_stamp_val
        self.receive_time = receive_time

    def _get_as_sub_field(data, offset_in_data):
        result = npl_punt_header_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def punt_next_header(self):
        return self._get_field_value(219, 5)
    @punt_next_header.setter
    def punt_next_header(self, value):
        self._set_field_value('field punt_next_header', 219, 5, int, value)
    @property
    def punt_fwd_header_type(self):
        return self._get_field_value(215, 4)
    @punt_fwd_header_type.setter
    def punt_fwd_header_type(self, value):
        self._set_field_value('field punt_fwd_header_type', 215, 4, int, value)
    @property
    def reserved(self):
        return self._get_field_value(212, 3)
    @reserved.setter
    def reserved(self, value):
        self._set_field_value('field reserved', 212, 3, int, value)
    @property
    def pl_header_offset(self):
        return npl_punt_header_t_anonymous_union_pl_header_offset_t._get_as_sub_field(self._data, self._offset_in_data + 204)
    @pl_header_offset.setter
    def pl_header_offset(self, value):
        self._set_field_value('field pl_header_offset', 204, 8, npl_punt_header_t_anonymous_union_pl_header_offset_t, value)
    @property
    def punt_src_and_code(self):
        return npl_punt_src_and_code_t._get_as_sub_field(self._data, self._offset_in_data + 192)
    @punt_src_and_code.setter
    def punt_src_and_code(self, value):
        self._set_field_value('field punt_src_and_code', 192, 12, npl_punt_src_and_code_t, value)
    @property
    def punt_sub_code(self):
        return npl_punt_sub_code_with_padding_t._get_as_sub_field(self._data, self._offset_in_data + 184)
    @punt_sub_code.setter
    def punt_sub_code(self, value):
        self._set_field_value('field punt_sub_code', 184, 8, npl_punt_sub_code_with_padding_t, value)
    @property
    def ssp(self):
        return self._get_field_value(168, 16)
    @ssp.setter
    def ssp(self, value):
        self._set_field_value('field ssp', 168, 16, int, value)
    @property
    def dsp(self):
        return self._get_field_value(152, 16)
    @dsp.setter
    def dsp(self, value):
        self._set_field_value('field dsp', 152, 16, int, value)
    @property
    def slp(self):
        return npl_punt_header_t_anonymous_union_slp_t._get_as_sub_field(self._data, self._offset_in_data + 132)
    @slp.setter
    def slp(self, value):
        self._set_field_value('field slp', 132, 20, npl_punt_header_t_anonymous_union_slp_t, value)
    @property
    def dlp(self):
        return npl_punt_header_t_anonymous_union_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 112)
    @dlp.setter
    def dlp(self, value):
        self._set_field_value('field dlp', 112, 20, npl_punt_header_t_anonymous_union_dlp_t, value)
    @property
    def punt_relay_id(self):
        return npl_app_relay_id_t._get_as_sub_field(self._data, self._offset_in_data + 96)
    @punt_relay_id.setter
    def punt_relay_id(self, value):
        self._set_field_value('field punt_relay_id', 96, 14, npl_app_relay_id_t, value)
    @property
    def time_stamp_val(self):
        return self._get_field_value(32, 64)
    @time_stamp_val.setter
    def time_stamp_val(self, value):
        self._set_field_value('field time_stamp_val', 32, 64, int, value)
    @property
    def receive_time(self):
        return self._get_field_value(0, 32)
    @receive_time.setter
    def receive_time(self, value):
        self._set_field_value('field receive_time', 0, 32, int, value)



class npl_bfd_mp_table_shared_lsb_t(basic_npl_struct):
    def __init__(self, inject_ifg_id=0, udp_checksum=0, inject_data=0):
        super().__init__(100)
        self.inject_ifg_id = inject_ifg_id
        self.udp_checksum = udp_checksum
        self.inject_data = inject_data

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_mp_table_shared_lsb_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def inject_ifg_id(self):
        return self._get_field_value(96, 4)
    @inject_ifg_id.setter
    def inject_ifg_id(self, value):
        self._set_field_value('field inject_ifg_id', 96, 4, int, value)
    @property
    def udp_checksum(self):
        return self._get_field_value(80, 16)
    @udp_checksum.setter
    def udp_checksum(self, value):
        self._set_field_value('field udp_checksum', 80, 16, int, value)
    @property
    def inject_data(self):
        return npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @inject_data.setter
    def inject_data(self, value):
        self._set_field_value('field inject_data', 0, 80, npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t, value)



class npl_bfd_mp_table_shared_payload_t(basic_npl_struct):
    def __init__(self, shared_msb=0, shared_lsb=0):
        super().__init__(160)
        self.shared_msb = shared_msb
        self.shared_lsb = shared_lsb

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_mp_table_shared_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def shared_msb(self):
        return npl_bfd_mp_table_shared_msb_t._get_as_sub_field(self._data, self._offset_in_data + 100)
    @shared_msb.setter
    def shared_msb(self, value):
        self._set_field_value('field shared_msb', 100, 60, npl_bfd_mp_table_shared_msb_t, value)
    @property
    def shared_lsb(self):
        return npl_bfd_mp_table_shared_lsb_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @shared_lsb.setter
    def shared_lsb(self, value):
        self._set_field_value('field shared_lsb', 0, 100, npl_bfd_mp_table_shared_lsb_t, value)



class npl_ene_punt_dlp_and_slp_t(basic_npl_struct):
    def __init__(self, ene_slp=0, ene_dlp=0):
        super().__init__(40)
        self.ene_slp = ene_slp
        self.ene_dlp = ene_dlp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ene_punt_dlp_and_slp_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ene_slp(self):
        return npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @ene_slp.setter
    def ene_slp(self, value):
        self._set_field_value('field ene_slp', 20, 20, npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t, value)
    @property
    def ene_dlp(self):
        return npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ene_dlp.setter
    def ene_dlp(self, value):
        self._set_field_value('field ene_dlp', 0, 20, npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t, value)



class npl_ene_punt_encap_data_t(basic_npl_struct):
    def __init__(self, ene_punt_dlp_and_slp=0):
        super().__init__(40)
        self.ene_punt_dlp_and_slp = ene_punt_dlp_and_slp

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ene_punt_encap_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ene_punt_dlp_and_slp(self):
        return npl_ene_punt_dlp_and_slp_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ene_punt_dlp_and_slp.setter
    def ene_punt_dlp_and_slp(self, value):
        self._set_field_value('field ene_punt_dlp_and_slp', 0, 40, npl_ene_punt_dlp_and_slp_t, value)



class npl_eth_mp_table_app_t(basic_npl_struct):
    def __init__(self, transmit_a=0, shared=0):
        super().__init__(160)
        self.transmit_a = transmit_a
        self.shared = shared

    def _get_as_sub_field(data, offset_in_data):
        result = npl_eth_mp_table_app_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def transmit_a(self):
        return npl_eth_mp_table_transmit_a_payload_t._get_as_sub_field(self._data, self._offset_in_data + 100)
    @transmit_a.setter
    def transmit_a(self, value):
        self._set_field_value('field transmit_a', 100, 60, npl_eth_mp_table_transmit_a_payload_t, value)
    @property
    def shared(self):
        return npl_eth_mp_table_shared_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @shared.setter
    def shared(self, value):
        self._set_field_value('field shared', 0, 100, npl_eth_mp_table_shared_payload_t, value)



class npl_bfd_mp_table_app_t(basic_npl_struct):
    def __init__(self, shared=0):
        super().__init__(160)
        self.shared = shared

    def _get_as_sub_field(data, offset_in_data):
        result = npl_bfd_mp_table_app_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def shared(self):
        return npl_bfd_mp_table_shared_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @shared.setter
    def shared(self, value):
        self._set_field_value('field shared', 0, 160, npl_bfd_mp_table_shared_payload_t, value)



class npl_ene_punt_encap_data_and_misc_pack_payload_t(basic_npl_struct):
    def __init__(self, ene_bytes_to_remove=0, ene_punt_encap_data=0):
        super().__init__(48)
        self.ene_bytes_to_remove = ene_bytes_to_remove
        self.ene_punt_encap_data = ene_punt_encap_data

    def _get_as_sub_field(data, offset_in_data):
        result = npl_ene_punt_encap_data_and_misc_pack_payload_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def ene_bytes_to_remove(self):
        return self._get_field_value(40, 8)
    @ene_bytes_to_remove.setter
    def ene_bytes_to_remove(self, value):
        self._set_field_value('field ene_bytes_to_remove', 40, 8, int, value)
    @property
    def ene_punt_encap_data(self):
        return npl_ene_punt_encap_data_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @ene_punt_encap_data.setter
    def ene_punt_encap_data(self, value):
        self._set_field_value('field ene_punt_encap_data', 0, 40, npl_ene_punt_encap_data_t, value)



class npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t(basic_npl_struct):
    def __init__(self):
        super().__init__(160)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def eth(self):
        return npl_eth_mp_table_app_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @eth.setter
    def eth(self, value):
        self._set_field_value('field eth', 0, 160, npl_eth_mp_table_app_t, value)
    @property
    def bfd(self):
        return npl_bfd_mp_table_app_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @bfd.setter
    def bfd(self, value):
        self._set_field_value('field bfd', 0, 160, npl_bfd_mp_table_app_t, value)
    @property
    def bfd_extra(self):
        return npl_bfd_mp_table_extra_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @bfd_extra.setter
    def bfd_extra(self, value):
        self._set_field_value('field bfd_extra', 0, 48, npl_bfd_mp_table_extra_payload_t, value)
    @property
    def pfc(self):
        return npl_pfc_mp_table_shared_payload_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @pfc.setter
    def pfc(self, value):
        self._set_field_value('field pfc', 0, 160, npl_pfc_mp_table_shared_payload_t, value)



class npl_mp_table_rd_app_t(basic_npl_struct):
    def __init__(self, mp_data_union=0):
        super().__init__(160)
        self.mp_data_union = mp_data_union

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mp_table_rd_app_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mp_data_union(self):
        return npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mp_data_union.setter
    def mp_data_union(self, value):
        self._set_field_value('field mp_data_union', 0, 160, npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t, value)



class npl_mp_table_app_t(basic_npl_struct):
    def __init__(self, mp_rd_data=0, mp_type=0, mp2_data_union=0):
        super().__init__(180)
        self.mp_rd_data = mp_rd_data
        self.mp_type = mp_type
        self.mp2_data_union = mp2_data_union

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mp_table_app_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def mp_rd_data(self):
        return npl_mp_table_rd_app_t._get_as_sub_field(self._data, self._offset_in_data + 20)
    @mp_rd_data.setter
    def mp_rd_data(self, value):
        self._set_field_value('field mp_rd_data', 20, 160, npl_mp_table_rd_app_t, value)
    @property
    def mp_type(self):
        return self._get_field_value(16, 4)
    @mp_type.setter
    def mp_type(self, value):
        self._set_field_value('field mp_type', 16, 4, int, value)
    @property
    def mp2_data_union(self):
        return npl_mp_table_app_t_anonymous_union_mp2_data_union_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @mp2_data_union.setter
    def mp2_data_union(self, value):
        self._set_field_value('field mp2_data_union', 0, 16, npl_mp_table_app_t_anonymous_union_mp2_data_union_t, value)



class npl_overload_union_npu_host_mp_data_t_app_defined_t(basic_npl_struct):
    def __init__(self):
        super().__init__(180)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_overload_union_npu_host_mp_data_t_app_defined_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def app(self):
        return npl_mp_table_app_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @app.setter
    def app(self, value):
        self._set_field_value('field app', 0, 180, npl_mp_table_app_t, value)
    @property
    def app_defined(self):
        return self._get_field_value(0, 180)
    @app_defined.setter
    def app_defined(self, value):
        self._set_field_value('field app_defined', 0, 180, int, value)



class npl_npu_host_mp_data_t(basic_npl_struct):
    def __init__(self):
        super().__init__(180)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_host_mp_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def overload_union_app_defined(self):
        return npl_overload_union_npu_host_mp_data_t_app_defined_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @overload_union_app_defined.setter
    def overload_union_app_defined(self, value):
        self._set_field_value('field overload_union_app_defined', 0, 180, npl_overload_union_npu_host_mp_data_t_app_defined_t, value)
    @property
    def raw(self):
        return self._get_field_value(0, 180)
    @raw.setter
    def raw(self, value):
        self._set_field_value('field raw', 0, 180, int, value)



class npl_npu_host_mp_data_with_padding_t(basic_npl_struct):
    def __init__(self, host_data=0):
        super().__init__(181)
        self.host_data = host_data

    def _get_as_sub_field(data, offset_in_data):
        result = npl_npu_host_mp_data_with_padding_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def host_data(self):
        return npl_npu_host_mp_data_t._get_as_sub_field(self._data, self._offset_in_data + 1)
    @host_data.setter
    def host_data(self, value):
        self._set_field_value('field host_data', 1, 180, npl_npu_host_mp_data_t, value)



class npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t(basic_npl_struct):
    def __init__(self):
        super().__init__(181)


    def _get_as_sub_field(data, offset_in_data):
        result = npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def npu_host_mp_data(self):
        return npl_npu_host_mp_data_with_padding_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @npu_host_mp_data.setter
    def npu_host_mp_data(self, value):
        self._set_field_value('field npu_host_mp_data', 0, 181, npl_npu_host_mp_data_with_padding_t, value)
    @property
    def npu_host_data_res_count_phase(self):
        return npl_npu_host_data_result_count_phase_t._get_as_sub_field(self._data, self._offset_in_data + 0)
    @npu_host_data_res_count_phase.setter
    def npu_host_data_res_count_phase(self, value):
        self._set_field_value('field npu_host_data_res_count_phase', 0, 181, npl_npu_host_data_result_count_phase_t, value)



class npl_mp_data_result_t(basic_npl_struct):
    def __init__(self, npu_host_mp_data=0, ccm_period=0, dm_valid=0, lm_valid=0, ccm_valid=0, aux_ptr=0, mp_valid=0):
        super().__init__(200)
        self.npu_host_mp_data = npu_host_mp_data
        self.ccm_period = ccm_period
        self.dm_valid = dm_valid
        self.lm_valid = lm_valid
        self.ccm_valid = ccm_valid
        self.aux_ptr = aux_ptr
        self.mp_valid = mp_valid

    def _get_as_sub_field(data, offset_in_data):
        result = npl_mp_data_result_t()
        result._set_data_pointer(data, offset_in_data)
        return result
    @property
    def npu_host_mp_data(self):
        return npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t._get_as_sub_field(self._data, self._offset_in_data + 19)
    @npu_host_mp_data.setter
    def npu_host_mp_data(self, value):
        self._set_field_value('field npu_host_mp_data', 19, 181, npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t, value)
    @property
    def ccm_period(self):
        return self._get_field_value(16, 3)
    @ccm_period.setter
    def ccm_period(self, value):
        self._set_field_value('field ccm_period', 16, 3, int, value)
    @property
    def dm_valid(self):
        return self._get_field_value(15, 1)
    @dm_valid.setter
    def dm_valid(self, value):
        self._set_field_value('field dm_valid', 15, 1, int, value)
    @property
    def lm_valid(self):
        return self._get_field_value(14, 1)
    @lm_valid.setter
    def lm_valid(self, value):
        self._set_field_value('field lm_valid', 14, 1, int, value)
    @property
    def ccm_valid(self):
        return self._get_field_value(13, 1)
    @ccm_valid.setter
    def ccm_valid(self, value):
        self._set_field_value('field ccm_valid', 13, 1, int, value)
    @property
    def aux_ptr(self):
        return self._get_field_value(1, 12)
    @aux_ptr.setter
    def aux_ptr(self, value):
        self._set_field_value('field aux_ptr', 1, 12, int, value)
    @property
    def mp_valid(self):
        return self._get_field_value(0, 1)
    @mp_valid.setter
    def mp_valid(self, value):
        self._set_field_value('field mp_valid', 0, 1, int, value)




