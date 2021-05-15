# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

ifeq ($(SDK_ROOT),)
    $(error SDK_ROOT environment variable must be set and pointing to SDK binary release directory!)
endif

include $(SDK_ROOT)/Makefile.envsetup

ifeq ($(GCC_DIR),)
    $(error GCC_DIR environment variable must be set and pointing to valid GCC base directory location!)
endif

ifeq ($(FFI_LIB_DIR),)
    $(error FFI_LIB_DIR environment variable must be set and pointing to libffi library location!)
endif

PY-TEST-ENV ?= LD_LIBRARY_PATH=$(SDK_ROOT)/lib:$(GCC_DIR)/lib64:$(FFI_LIB_DIR) PYTHONPATH=test/api:test/utils:test/api/snake:examples/sanity:$(SDK_ROOT)/pylib BASE_OUTPUT_DIR=$(SDK_ROOT) SDK_DEVICE_NAME='/dev/uio0'

ifeq ($(RUN_SLOW_TESTS), 1)
    PY-TEST-ENV := $(PY-TEST-ENV) RUN_SLOW_TESTS=True
endif

ifeq ($(SKIP_SLOW_TESTS), 1)
    PY-TEST-ENV := $(PY-TEST-ENV) SKIP_SLOW_TESTS=True
endif

ifdef ($(MATILDA_TEST_MODE))
    PY-TEST-ENV := $(PY-TEST-ENV) MATILDA_TEST_MODE_ENV=$(MATILDA_TEST_MODE)
endif

BASE-TEST-DIR = test/api
OUT_DIR = $(SDK_ROOT)/test/out

HW_PY_TESTS = $(shell find $(BASE-TEST-DIR) -name "test*py" | cut -sd / -f 3-)

HW_PY_WB_UR_TESTS = $(shell find $(BASE-TEST-DIR)/warm_boot_upgrade_rollback -name "test*py" | cut -sd / -f 3-)

HW_TEST_PASSED = $(patsubst %.py,$(OUT_DIR)/%.passed,$(HW_PY_TESTS))

ifeq ($(WB_ALL_TESTS),1)
	# Run all API tests with auto-WB enabled
	WB_PASSED_EXT := all_tests_warmboot_passed
	HW_TEST_WB_PASSED := $(patsubst %.py,$(OUT_DIR)/%.$(WB_PASSED_EXT),$(HW_PY_TESTS))
else
	# Run only predefined tests

	# List format:
	#   WB-TESTS = (<test_line>\;)+
	#   <test_line> = <test_file>(\:<test_cases>)?
	#   <test_cases> = <test_case>(\-<test_case>)*
	#   <test_case> = <test_class>(\.<test_method>)?
	WB-TESTS := l2_qos_remark/test_ip_dscp_qos_remark_untagged.py:l2_untagged_packet_dscp_remark_ipv4_test;\
		traps/test_cisco_protocols.py:test_cisco_protocols.test_L2PT;\
		mac_and_serdes/test_serdes_swap.py;\
		mac_port/test_mac_port_create_and_lookup.py;\
		qos_profile/test_qos_profile.py;\
		l2_vlan_editing/test_l2_vlan_editing.py:test_l2_vlan_editing.test_port_default_pcpdei-test_l2_vlan_editing.test_access_to_trunk;\
		traps/test_l2cp.py:TrapsL2CP.test_l2cp_dmac_match;\
		ip_routing/test_ipv4_svi_eve.py:test_ipv4_svi_eve.test_access_to_trunk;\
		ip_routing/test_ipv6_svi_eve.py:test_ipv6_svi_eve.test_access_to_trunk;\
		tm_credit_scheduler/test_ifg_credit_scheduler.py;\
		tm_credit_scheduler/test_system_port_credit_scheduler.py;\
		npu_getters/test_l2_punt_destination.py;\
		npu_getters/test_l2_service_port_getters.py;\
		npu_getters/test_get_egress_vlan_tag_l3.py;\
		ip_routing/test_ipv4_l3_ac_routing.py:test_ipv4_l3_ac_routing.test_get_host_route-test_ipv4_l3_ac_routing.test_get_hosts-test_ipv4_l3_ac_routing.test_get_route-test_ipv4_l3_ac_routing.test_get_routing_entry-test_ipv4_l3_ac_routing.test_get_subnets-test_ipv4_l3_ac_routing.test_ipv4_routing_32_bit_prefix;\
		npu_getters/test_ac_port_get_active.py;\
		l2_qos_remark/test_l2_qos_remark.py:test_l2_qos_remark_base.test_set_get_qos_profile;\
		erspan/test_getters.py;\
		mac_port/test_mac_port_packet_size_sa.py;\
		mac_port/test_mac_port_counters.py;\
		ostc/test_port_tc.py;\
		tm_credit_scheduler/test_out_queue_credit_scheduler.py;\
		mpls_midpoint/test_mpls_l2_adj.py:mpls_l2_adj.test_l2_adj;\
		mpls_headend/test_headend_ipv4_l3_ac.py:ipv4_l3_ac.test_clear_prefix_ldp_tenh_lsp_properties:ipv4_l3_ac.test_prefix_object_vpn_properties:ipv4_l3_ac.test_mpls_headend_getter;\
		npu_getters/test_get_egress_vlan_tag_svi.py;\
		l2_switch/test_l2_switch_forwarding_and_flooding.py:l2_switch_forwarding_and_flooding.test_l2_switch_getter-l2_switch_forwarding_and_flooding.test_l2_switch_mac_table_scaling;\
		ip_routing/test_ipv4_svi_routing.py:test_ipv4_svi_routing.test_get_host_route-test_ipv4_svi_routing.test_get_route-test_ipv4_svi_routing.test_get_subnets-test_ipv4_svi_routing.test_get_routing_entry;\
		tc_profile/test_set_tc_profile.py;\
		tm_transmit_scheduler/test_system_port_transmit_scheduler.py:system_port_transmit_scheduler.test_system_port_transmit_scheduler;\
		tc_profile/test_set_get_mapping.py;\
		voq_cgm_profile/test_voq_profile_setting_sms_bytes_quantization.py;\
		voq_counters/test_voq_counters.py;\
		ip_routing/test_ipv4_l3_ac_routing2.py:test_ipv4_l3_ac_routing2.test_modify_route;\
		ip_routing/test_ipv6_l3_ac_routing.py:test_ipv6_l3_ac_routing.test_modify_route;\
		test_ipv4_routing_l3_ac_qos_remark.py:ipv4_rx_l3_ac_untagged_ip_routing_qos_remark_test.test_ecn_remark_control;\
		test_ipv4_routing_svi_qos_remark.py:ipv4_rx_svi_untagged_ip_routing_qos_remark_test.test_ecn_remark_control;\
		test_ipv6_routing_l3_ac_qos_remark.py:ipv6_rx_l3_ac_untagged_ip_routing_qos_remark_test.test_ecn_remark_control;\
		test_ipv6_routing_svi_qos_remark.py:ipv6_rx_svi_untagged_ip_routing_qos_remark_test.test_ecn_remark_control;\
		ipv4_lpts/test_lpts_scale.py;

    define PARSE_TEST_LIST
        WB-TEST-FILE := $(word 1,$(subst :, ,$(1)))
        WB-TEST-CASES := $(word 2,$(subst :, ,$(1)))
        WB-TEST-FILES := $$(WB-TEST-FILES) $$(WB-TEST-FILE)
        $$(WB-TEST-FILE)-TEST-CASES := $$(subst -, ,$$(WB-TEST-CASES))
    endef

    $(foreach line,$(subst ;, ,$(WB-TESTS)),$(eval $(call PARSE_TEST_LIST,$(line))))
    WB_PASSED_EXT := warmboot_passed
    HW_TEST_WB_PASSED := $(patsubst %.py, $(OUT_DIR)/%.$(WB_PASSED_EXT), $(WB-TEST-FILES))
endif

HW_TEST_WB_UR_PASSED := $(patsubst %.py,$(OUT_DIR)/%.warmboot_ur_passed,$(HW_PY_WB_UR_TESTS))

# Regular sanity
$(OUT_DIR)/%.passed: ERR-LOG = $(OUT_DIR)/$*.api_test.log
$(OUT_DIR)/%.passed: $(BASE-TEST-DIR)/%.py
	$(SILENT)echo "Api Testing $$(basename $${PWD}) $< ..."
	$(SILENT)mkdir -p $(@D)
	$(SILENT)mkdir -p $(dir $(ERR-LOG)) ; \
	    rm -rf $(ERR-LOG) ; \
	    echo "env $(PY-TEST-ENV) $(PYTHON_BIN) -u $^ -v" > $(ERR-LOG)
	$(SILENT)env $(PY-TEST-ENV) $(PYTHON_BIN) -u $^ -v &>> $(ERR-LOG) || ( \
	    echo "$$$$: ERROR_LOG $$(basename $${PWD}) $(ERR-LOG)" ; \
	    cat $(ERR-LOG) | sed "s/^/$$$$: /" ; \
	    exit 1 )
	$(SILENT)rm -rf $(ERR-LOG) ; \
	    rm -rf $@ ; \
	    echo "env $(PY-TEST-ENV) $(PYTHON_BIN) -u $^ -v" > $@


BUILD_OUTPUT_DIR = $(OUT_DIR)
PKG-PATH = /
include $(SDK_ROOT)/test/api/Makefile.def_doa_test

# Dead or Alive (DOA) sanity
$(OUT_DIR)/%.$(DOA_PASSED_EXT): ERR-LOG = $(OUT_DIR)/$*.doa_py_tests.log
$(OUT_DIR)/%.$(DOA_PASSED_EXT): TEST-CASES = $($*.py-TEST-CASES)
$(OUT_DIR)/%.$(DOA_PASSED_EXT): $(BASE-TEST-DIR)/%.py
	$(SILENT)echo "Api DOA Testing $$(basename $${PWD}) $< ..."
	$(SILENT)mkdir -p $(@D)
	$(SILENT)mkdir -p $(dir $(ERR-LOG)) ; \
	    rm -rf $(ERR-LOG) ; \
	    echo "env $(PY-TEST-ENV) $(PYTHON_BIN) -u $^ $(TEST-CASES) -v" > $(ERR-LOG)
	$(SILENT)env $(PY-TEST-ENV) $(PYTHON_BIN) -u $^ $(TEST-CASES) -v &>> $(ERR-LOG) || ( \
	    echo "$$$$: ERROR_LOG $$(basename $${PWD}) $(ERR-LOG)" ; \
	    cat $(ERR-LOG) | sed "s/^/$$$$: /" ; \
	    exit 1 )
	$(SILENT)rm -rf $(ERR-LOG) ; \
	    rm -rf $@ ; \
	    echo "env $(PY-TEST-ENV) $(PYTHON_BIN) -u $^ $(TEST-CASES) -v" > $@



# Warm Boot sanity
$(OUT_DIR)/%.$(WB_PASSED_EXT): ERR-LOG = $(OUT_DIR)/$*.api_warmboot_test.log
$(OUT_DIR)/%.$(WB_PASSED_EXT): LEABA_KERNEL_MODULE_PATH ?= $(SDK_ROOT)/modules/leaba_module/leaba_module.ko
$(OUT_DIR)/%.$(WB_PASSED_EXT): PY-TEST-WB-ENV = $(PY-TEST-ENV) ENABLE_AUTO_WB=1 LEABA_KERNEL_MODULE_PATH=$(LEABA_KERNEL_MODULE_PATH)
$(OUT_DIR)/%.$(WB_PASSED_EXT): TEST-CASES = $($*.py-TEST-CASES)
$(OUT_DIR)/%.$(WB_PASSED_EXT): $(BASE-TEST-DIR)/%.py
	$(SILENT)echo "Api WarmBoot Testing $$(basename $${PWD}) $< ..."
	$(SILENT)cat /proc/meminfo
	$(SILENT)mkdir -p $(@D)
	$(SILENT)mkdir -p $(dir $(ERR-LOG)) ; \
	    rm -rf $(ERR-LOG) ; \
	    echo "env $(PY-TEST-WB-ENV) $(PYTHON_BIN) -u $^ $(TEST-CASES) -v" > $(ERR-LOG)
	$(SILENT)env $(PY-TEST-WB-ENV) $(PYTHON_BIN) -u $^ $(TEST-CASES) -v &>> $(ERR-LOG) || ( \
	    echo "$$$$: ERROR_LOG $$(basename $${PWD}) $(ERR-LOG)" ; \
	    cat $(ERR-LOG) | sed "s/^/$$$$: /" ; \
	    exit 1 )
	$(SILENT)rm -rf $(ERR-LOG) ; \
	    rm -rf $@ ; \
	    echo "env $(PY-TEST-WB-ENV) $(PYTHON_BIN) -u $^ $(TEST-CASES) -v" > $@


# Warm Boot Upgrade/Rollback sanity
$(OUT_DIR)/%.warmboot_ur_passed: ERR-LOG = $(OUT_DIR)/$*.api_warmboot_ur_test.log
$(OUT_DIR)/%.warmboot_ur_passed: PY-TEST-WB-ENV = $(PY-TEST-ENV) ENABLE_WB_UPGRADE_ROLLBACK=1
$(OUT_DIR)/%.warmboot_ur_passed: $(BASE-TEST-DIR)/%.py
	$(SILENT)echo "Api WarmBoot Testing $$(basename $${PWD}) $< ..."
	$(SILENT)mkdir -p $(@D)
	$(SILENT)mkdir -p $(dir $(ERR-LOG)) ; \
	    rm -rf $(ERR-LOG) ; \
	    echo "env $(PY-TEST-WB-ENV) $(PYTHON_BIN) -u $^ -v" > $(ERR-LOG)
	$(SILENT)env $(PY-TEST-WB-ENV) $(PYTHON_BIN) -u $^ -v &>> $(ERR-LOG) || ( \
	    echo "$$$$: ERROR_LOG $$(basename $${PWD}) $(ERR-LOG)" ; \
	    cat $(ERR-LOG) | sed "s/^/$$$$: /" ; \
	    exit 1 )
	$(SILENT)rm -rf $(ERR-LOG) ; \
	    rm -rf $@ ; \
	    echo "env $(PY-TEST-WB-ENV) $(PYTHON_BIN) -u $^ -v" > $@


.PHONY: sanity test-warmboot test-warmboot-upgrade-rollback test-dead-or-alive clean

# default target
sanity: $(HW_TEST_PASSED)

test-warmboot: $(HW_TEST_WB_PASSED)

test-warmboot-upgrade-rollback: $(HW_TEST_WB_UR_PASSED)

test-dead-or-alive: $(DEAD_OR_ALIVE_TESTS)

clean:
	$(SILENT)rm -f $(HW_TEST_PASSED)
	$(SILENT)rm -f $(HW_TEST_WB_PASSED)
	$(SILENT)rm -f $(HW_TEST_WB_UR_PASSED)
	$(SILENT)rm -f $(HW_TEST_DOA_PASSED)
	$(SILENT)rm -f $(DEAD_OR_ALIVE_TESTS)



