
// This file has been automatically generated using nplc.py. Do not edit it manually.
// Version: 1.76.2_0.0.0.0 generated on devsrv15.leaba.local at 2021-05-12 16:09:15


#include "nplapi/la_event.h"

/// @file
/// @brief Leaba Event definitions.
///
/// Defines Event names used by the Leaba API.

/// @addtogroup EVENTS
/// @{
    
    
    const char* la_event_names[] = {
        "LA_EVENT_ETHERNET_ACL_DROP",
        "LA_EVENT_ETHERNET_ACL_FORCE_PUNT",
        "LA_EVENT_ETHERNET_VLAN_MEMBERSHIP",
        "LA_EVENT_ETHERNET_ACCEPTABLE_FORMAT",
        "LA_EVENT_ETHERNET_NO_SERVICE_MAPPING",
        "LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT",
        "LA_EVENT_ETHERNET_NO_SIP_MAPPING",
        "LA_EVENT_ETHERNET_NO_VNI_MAPPING",
        "LA_EVENT_ETHERNET_NO_VSID_MAPPING",
        "LA_EVENT_ETHERNET_ARP",
        "LA_EVENT_ETHERNET_SA_DA_ERROR",
        "LA_EVENT_ETHERNET_SA_ERROR",
        "LA_EVENT_ETHERNET_DA_ERROR",
        "LA_EVENT_ETHERNET_SA_MULTICAST",
        "LA_EVENT_ETHERNET_DHCPV4_SERVER",
        "LA_EVENT_ETHERNET_DHCPV4_CLIENT",
        "LA_EVENT_ETHERNET_DHCPV6_SERVER",
        "LA_EVENT_ETHERNET_DHCPV6_CLIENT",
        "LA_EVENT_ETHERNET_INGRESS_STP_BLOCK",
        "LA_EVENT_ETHERNET_PTP_OVER_ETH",
        "LA_EVENT_ETHERNET_ISIS_OVER_L2",
        "LA_EVENT_ETHERNET_L2CP0",
        "LA_EVENT_ETHERNET_L2CP1",
        "LA_EVENT_ETHERNET_L2CP2",
        "LA_EVENT_ETHERNET_L2CP3",
        "LA_EVENT_ETHERNET_L2CP4",
        "LA_EVENT_ETHERNET_L2CP5",
        "LA_EVENT_ETHERNET_L2CP6",
        "LA_EVENT_ETHERNET_L2CP7",
        "LA_EVENT_ETHERNET_LACP",
        "LA_EVENT_ETHERNET_CISCO_PROTOCOLS",
        "LA_EVENT_ETHERNET_MACSEC",
        "LA_EVENT_ETHERNET_UNKNOWN_L3",
        "LA_EVENT_ETHERNET_TEST_OAM_AC_MEP",
        "LA_EVENT_ETHERNET_TEST_OAM_AC_MIP",
        "LA_EVENT_ETHERNET_TEST_OAM_CFM_LINK_MDL0",
        "LA_EVENT_ETHERNET_SYSTEM_MYMAC",
        "LA_EVENT_ETHERNET_UNKNOWN_BC",
        "LA_EVENT_ETHERNET_UNKNOWN_MC",
        "LA_EVENT_ETHERNET_UNKNOWN_UC",
        "LA_EVENT_ETHERNET_LEARN_PUNT",
        "LA_EVENT_ETHERNET_BCAST_PKT",
        "LA_EVENT_ETHERNET_PFC_SAMPLE",
        "LA_EVENT_ETHERNET_HOP_BY_HOP",
        "LA_EVENT_ETHERNET_L2_DLP_NOT_FOUND",
        "LA_EVENT_ETHERNET_SAME_INTERFACE",
        "LA_EVENT_ETHERNET_DSPA_MC_TRIM",
        "LA_EVENT_ETHERNET_EGRESS_STP_BLOCK",
        "LA_EVENT_ETHERNET_SPLIT_HORIZON",
        "LA_EVENT_ETHERNET_DISABLED",
        "LA_EVENT_ETHERNET_INCOMPATIBLE_EVE_CMD",
        "LA_EVENT_ETHERNET_PADDING_RESIDUE_IN_SECOND_LINE",
        "LA_EVENT_ETHERNET_PFC_DIRECT_SAMPLE",
        "LA_EVENT_ETHERNET_SVI_EGRESS_DHCP",
        "LA_EVENT_ETHERNET_NO_PWE_L3_DEST",
        "LA_EVENT_IPV4_MC_FORWARDING_DISABLED",
        "LA_EVENT_IPV4_UC_FORWARDING_DISABLED",
        "LA_EVENT_IPV4_CHECKSUM",
        "LA_EVENT_IPV4_HEADER_ERROR",
        "LA_EVENT_IPV4_UNKNOWN_PROTOCOL",
        "LA_EVENT_IPV4_OPTIONS_EXIST",
        "LA_EVENT_IPV4_NON_COMP_MC",
        "LA_EVENT_IPV6_MC_FORWARDING_DISABLED",
        "LA_EVENT_IPV6_UC_FORWARDING_DISABLED",
        "LA_EVENT_IPV6_HOP_BY_HOP",
        "LA_EVENT_IPV6_HEADER_ERROR",
        "LA_EVENT_IPV6_ILLEGAL_SIP",
        "LA_EVENT_IPV6_ILLEGAL_DIP",
        "LA_EVENT_IPV6_ZERO_PAYLOAD",
        "LA_EVENT_IPV6_NEXT_HEADER_CHECK",
        "LA_EVENT_IPV6_NON_COMP_MC",
        "LA_EVENT_MPLS_UNKNOWN_PROTOCOL_AFTER_BOS",
        "LA_EVENT_MPLS_TTL_IS_ZERO",
        "LA_EVENT_MPLS_BFD_OVER_PWE_TTL",
        "LA_EVENT_MPLS_BFD_OVER_PWE_RAW",
        "LA_EVENT_MPLS_BFD_OVER_PWE_IPV4",
        "LA_EVENT_MPLS_BFD_OVER_PWE_IPV6",
        "LA_EVENT_MPLS_UNKNOWN_BFD_G_ACH_CHANNEL_TYPE",
        "LA_EVENT_MPLS_BFD_OVER_PWE_RA",
        "LA_EVENT_MPLS_MPLS_TP_OVER_PWE",
        "LA_EVENT_MPLS_UNKNOWN_G_ACH",
        "LA_EVENT_MPLS_MPLS_TP_OVER_LSP",
        "LA_EVENT_MPLS_OAM_ALERT_LABEL",
        "LA_EVENT_MPLS_EXTENSION_LABEL",
        "LA_EVENT_MPLS_ROUTER_ALERT_LABEL",
        "LA_EVENT_MPLS_UNEXPECTED_RESERVED_LABEL",
        "LA_EVENT_MPLS_FORWARDING_DISABLED",
        "LA_EVENT_MPLS_ILM_MISS",
        "LA_EVENT_MPLS_IPV4_OVER_IPV6_EXPLICIT_NULL",
        "LA_EVENT_MPLS_INVALID_TTL",
        "LA_EVENT_MPLS_TE_MIDPOPINT_LDP_LABELS_MISS",
        "LA_EVENT_MPLS_ASBR_LABEL_MISS",
        "LA_EVENT_MPLS_ILM_VRF_LABEL_MISS",
        "LA_EVENT_MPLS_PWE_PWACH",
        "LA_EVENT_MPLS_VPN_TTL_ONE",
        "LA_EVENT_MPLS_MISSING_FWD_LABEL_AFTER_POP",
        "LA_EVENT_L3_IP_UNICAST_RPF",
        "LA_EVENT_L3_IP_MULTICAST_RPF",
        "LA_EVENT_L3_IP_MC_DROP",
        "LA_EVENT_L3_IP_MC_PUNT_DC_PASS",
        "LA_EVENT_L3_IP_MC_SNOOP_DC_PASS",
        "LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL",
        "LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL",
        "LA_EVENT_L3_IP_MC_SNOOP_LOOKUP_MISS",
        "LA_EVENT_L3_IP_MULTICAST_NOT_FOUND",
        "LA_EVENT_L3_IP_MC_S_G_PUNT_MEMBER",
        "LA_EVENT_L3_IP_MC_G_PUNT_MEMBER",
        "LA_EVENT_L3_IP_MC_EGRESS_PUNT",
        "LA_EVENT_L3_ISIS_OVER_L3",
        "LA_EVENT_L3_ISIS_DRAIN",
        "LA_EVENT_L3_NO_HBM_ACCESS_DIP",
        "LA_EVENT_L3_NO_HBM_ACCESS_SIP",
        "LA_EVENT_L3_LPM_ERROR",
        "LA_EVENT_L3_LPM_DROP",
        "LA_EVENT_L3_LOCAL_SUBNET",
        "LA_EVENT_L3_ICMP_REDIRECT",
        "LA_EVENT_L3_NO_LP_OVER_LAG_MAPPING",
        "LA_EVENT_L3_INGRESS_MONITOR",
        "LA_EVENT_L3_EGRESS_MONITOR",
        "LA_EVENT_L3_ACL_DROP",
        "LA_EVENT_L3_ACL_FORCE_PUNT",
        "LA_EVENT_L3_ACL_FORCE_PUNT1",
        "LA_EVENT_L3_ACL_FORCE_PUNT2",
        "LA_EVENT_L3_ACL_FORCE_PUNT3",
        "LA_EVENT_L3_ACL_FORCE_PUNT4",
        "LA_EVENT_L3_ACL_FORCE_PUNT5",
        "LA_EVENT_L3_ACL_FORCE_PUNT6",
        "LA_EVENT_L3_ACL_FORCE_PUNT7",
        "LA_EVENT_L3_GLEAN_ADJ",
        "LA_EVENT_L3_DROP_ADJ",
        "LA_EVENT_L3_DROP_ADJ_NON_INJECT",
        "LA_EVENT_L3_NULL_ADJ",
        "LA_EVENT_L3_USER_TRAP1",
        "LA_EVENT_L3_USER_TRAP2",
        "LA_EVENT_L3_LPM_DEFAULT_DROP",
        "LA_EVENT_L3_LPM_INCOMPLETE0",
        "LA_EVENT_L3_LPM_INCOMPLETE2",
        "LA_EVENT_L3_BFD_MICRO_IP_DISABLED",
        "LA_EVENT_L3_NO_VNI_MAPPING",
        "LA_EVENT_L3_NO_HBM_ACCESS_OG_SIP",
        "LA_EVENT_L3_NO_HBM_ACCESS_OG_DIP",
        "LA_EVENT_L3_NO_L3_DLP_MAPPING",
        "LA_EVENT_L3_L3_DLP_DISABLED",
        "LA_EVENT_L3_SPLIT_HORIZON",
        "LA_EVENT_L3_MC_SAME_INTERFACE",
        "LA_EVENT_L3_NO_VPN_LABEL_FOUND",
        "LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE",
        "LA_EVENT_L3_TX_MTU_FAILURE",
        "LA_EVENT_L3_TX_FRR_DROP",
        "LA_EVENT_OAMP_ETH_UNKNOWN_PUNT_REASON",
        "LA_EVENT_OAMP_ETH_MEP_MAPPING_FAILED",
        "LA_EVENT_OAMP_ETH_MP_TYPE_MISMATCH",
        "LA_EVENT_OAMP_ETH_MEG_LEVEL_MISMATCH",
        "LA_EVENT_OAMP_ETH_BAD_MD_NAME_FORMAT",
        "LA_EVENT_OAMP_ETH_UNICAST_DA_NO_MATCH",
        "LA_EVENT_OAMP_ETH_MULTICAST_DA_NO_MATCH",
        "LA_EVENT_OAMP_ETH_WRONG_MEG_ID_FORMAT",
        "LA_EVENT_OAMP_ETH_MEG_ID_NO_MATCH",
        "LA_EVENT_OAMP_ETH_CCM_PERIOD_NO_MATCH",
        "LA_EVENT_OAMP_ETH_CCM_TLV_NO_MATCH",
        "LA_EVENT_OAMP_ETH_LMM_TLV_NO_MATCH",
        "LA_EVENT_OAMP_ETH_NOT_SUPPORTED_OAM_OPCODE",
        "LA_EVENT_OAMP_BFD_TRANSPORT_NOT_SUPPORTED",
        "LA_EVENT_OAMP_BFD_SESSION_LOOKUP_FAILED",
        "LA_EVENT_OAMP_BFD_INCORRECT_TTL",
        "LA_EVENT_OAMP_BFD_INVALID_PROTOCOL",
        "LA_EVENT_OAMP_BFD_INVALID_UDP_PORT",
        "LA_EVENT_OAMP_BFD_INCORRECT_VERSION",
        "LA_EVENT_OAMP_BFD_INCORRECT_ADDRESS",
        "LA_EVENT_OAMP_BFD_MISMATCH_DISCR",
        "LA_EVENT_OAMP_BFD_STATE_FLAG_CHANGE",
        "LA_EVENT_OAMP_BFD_SESSION_RECEIVED",
        "LA_EVENT_OAMP_PFC_LOOKUP_FAILED",
        "LA_EVENT_OAMP_PFC_DROP_INVALID_RX",
        "LA_EVENT_APP_SGACL_DROP",
        "LA_EVENT_APP_SGACL_LOG",
        "LA_EVENT_APP_IP_INACTIVITY",
        "LA_EVENT_SVL_CONTROL_PROTOCOL",
        "LA_EVENT_SVL_CONTROL_IPC",
        "LA_EVENT_SVL_SVL_MC_PRUNE",
        "LA_EVENT_L2_LPTS_TRAP0",
        "LA_EVENT_L2_LPTS_TRAP1",
        "LA_EVENT_L2_LPTS_TRAP2",
        "LA_EVENT_L2_LPTS_TRAP3",
        "LA_EVENT_L2_LPTS_TRAP4",
        "LA_EVENT_L2_LPTS_TRAP5",
        "LA_EVENT_L2_LPTS_TRAP6",
        "LA_EVENT_L2_LPTS_TRAP7",
        "LA_EVENT_L2_LPTS_TRAP8",
        "LA_EVENT_L2_LPTS_TRAP9",
        "LA_EVENT_L2_LPTS_TRAP10",
        "LA_EVENT_L2_LPTS_TRAP11",
        "LA_EVENT_INTERNAL_L3_LPM_LPTS",
        "LA_EVENT_INTERNAL_IPV4_NON_ROUTABLE_MC_ROUTING",
        "LA_EVENT_INTERNAL_IPV4_NON_ROUTABLE_MC_BRIDGING",
        "LA_EVENT_INTERNAL_IPV6_NON_ROUTABLE_MC_ROUTING",
        "LA_EVENT_INTERNAL_IPV6_NON_ROUTABLE_MC_BRIDGING"
    };
    
    
    std::string get_event_description(const la_event_e event)
    {
        switch(event) {
            case LA_EVENT_ETHERNET_ACL_DROP:
            {
                return " l2 forwarding pkts sec or udf acls result with deny action, trapped at fwd stage or transmit stage";
            }
            case LA_EVENT_ETHERNET_ACL_FORCE_PUNT:
            {
                return " l2 forwarding pkts sec or udf acls result with punt to host action, trapped at fwd stage or transmit stage";
            }
            case LA_EVENT_ETHERNET_VLAN_MEMBERSHIP:
            {
                return " check vlan membership for a given eth port, trapped at ternination stage";
            }
            case LA_EVENT_ETHERNET_ACCEPTABLE_FORMAT:
            {
                return " for a given eth port verify the port profile and the packet tpid's format, trapped at ternination stage";
            }
            case LA_EVENT_ETHERNET_NO_SERVICE_MAPPING:
            {
                return " for a given ethernet port, failed to clasify the L2 or L3 ACs per port x vlan, trapped at ternination stage";
            }
            case LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT:
            {
                return " failed to terminate l3-AC ports (mis-match pkt and port DA), trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_NO_SIP_MAPPING:
            {
                return " for VXLAN decap tunnels (dip is local interface dip), could not terminate tunnel SIP in termination database trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_NO_VNI_MAPPING:
            {
                return " for VXLAN decap tunnels (dip is local interface dip), could not resolve VNI to l2 attributes in termination database. trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_NO_VSID_MAPPING:
            {
                return " for VXLAN decap tunnels (dip is local interface dip), could not resolve VSID to l2 relay id in termination database. trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_ARP:
            {
                return " for ARP pkts, and if ethernet port support arp handlng, trap or snoop arp pkts when eth, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_SA_DA_ERROR:
            {
                return " ethernet header pkt format error, SA is equal DA, DA is 48'b0 or SA is 48'b0, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_SA_ERROR:
            {
                return " ethernet header pkt format error, SA is equal to zero.";
            }
            case LA_EVENT_ETHERNET_DA_ERROR:
            {
                return " ethernet header pkt format error, DA is equal to zero.";
            }
            case LA_EVENT_ETHERNET_SA_MULTICAST:
            {
                return " ethernet header pkt format error, SA is MC address, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_DHCPV4_SERVER:
            {
                return " for dhcp pkts over ipv4, trapped if dhcp port is d'67, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_DHCPV4_CLIENT:
            {
                return " for dhcp pkts over ipv4, trapped if dhcp port is d'68, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_DHCPV6_SERVER:
            {
                return " for dhcp pkts over ipv6, trapped if dhcp port is d'67, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_DHCPV6_CLIENT:
            {
                return " for dhcp pkts over ipv6, trapped if dhcp port is d'68, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_INGRESS_STP_BLOCK:
            {
                return " for l2 packet, trap ingress l2-lp if stp is blocked, trapped at fwd stage";
            }
            case LA_EVENT_ETHERNET_PTP_OVER_ETH:
            {
                return " for ptp over l2 ethernet pkts, trap ptp pkt if boundery router, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_ISIS_OVER_L2:
            {
                return " ISIS pkts over L2-AC interface, trapped at the termination stage";
            }
            case LA_EVENT_ETHERNET_L2CP0:
            {
                return " trap L2CP protocol pkts based on configurable mapping by the control, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_L2CP1:
            {
                return " trap L2CP protocol pkts based on configurable mapping by the control, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_L2CP2:
            {
                return " trap L2CP protocol pkts based on configurable mapping by the control, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_L2CP3:
            {
                return " trap L2CP protocol pkts based on configurable mapping by the control, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_L2CP4:
            {
                return " trap L2CP protocol pkts based on configurable mapping by the control, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_L2CP5:
            {
                return " trap L2CP protocol pkts based on configurable mapping by the control, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_L2CP6:
            {
                return " trap L2CP protocol pkts based on configurable mapping by the control, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_L2CP7:
            {
                return " trap L2CP protocol pkts based on configurable mapping by the control, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_LACP:
            {
                return " trap LACP (link aggregation) protocol pkts over ethernet for ant LP type, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_CISCO_PROTOCOLS:
            {
                return " trap cisco specific control protocol (CDP VTP DTP PAgP UDLD PVSTP+), trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_MACSEC:
            {
                return " trap MACSEC over ethernet pkts, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_UNKNOWN_L3:
            {
                return " unknow overlay packet protocol following MAC termination of ethernet header, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_TEST_OAM_AC_MEP:
            {
                return " OAM endpoint MEP trap, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_TEST_OAM_AC_MIP:
            {
                return " OAM midpoint MIP trap, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_TEST_OAM_CFM_LINK_MDL0:
            {
                return " trap CFM (connectivity fault managment) protocol pkts over ethernet with md = 0 (maintenance domain), trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_SYSTEM_MYMAC:
            {
                return " global My-MAC termination of ethernet header, should be weaker than OAM, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_UNKNOWN_BC:
            {
                return " for BC l2, trap / drop unknow BC pkts, based on L2 LP drop BC configuration, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_UNKNOWN_MC:
            {
                return " for MC l2, trap / drop unknow MC pkts, based on L2 LP drop MC configuration, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_UNKNOWN_UC:
            {
                return " for UC l2, trap / drop unknow UC pkts, based on L2 LP drop UC configuration, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_LEARN_PUNT:
            {
                return " for inject up special learn record processing, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_BCAST_PKT:
            {
                return " for L3 AC LP and DA is BC, punt this packet to control plane, trapped at termination stage";
            }
            case LA_EVENT_ETHERNET_PFC_SAMPLE:
            {
                return " PFC measurement mirror. When PFC is enabled will select this mirror 1 in every 16 packets. Snoop set at the termination stage.";
            }
            case LA_EVENT_ETHERNET_HOP_BY_HOP:
            {
                return " ipv6 next EH header is hop-by-hop, trapped at fwd stage (MAC_FWD macro)";
            }
            case LA_EVENT_ETHERNET_L2_DLP_NOT_FOUND:
            {
                return " All egress l2 encapsulation processing , failed to map l2-dlp in encapsulation database, trapped at transmit stage";
            }
            case LA_EVENT_ETHERNET_SAME_INTERFACE:
            {
                return " when resolved l2_dlp equals to l2_slp, trap pkt, trapped at transmit stage";
            }
            case LA_EVENT_ETHERNET_DSPA_MC_TRIM:
            {
                return " L2 mc fwd, test for mc pruning of flood copies to LAGs, trapped at transmit stage";
            }
            case LA_EVENT_ETHERNET_EGRESS_STP_BLOCK:
            {
                return " for l2 packet, trap egress l2-lp if stp is blocked, trapped at fwd stage";
            }
            case LA_EVENT_ETHERNET_SPLIT_HORIZON:
            {
                return " l2 interface egress split horizon filter (based on slp and dlp profile matching), trapped at transmit stage";
            }
            case LA_EVENT_ETHERNET_DISABLED:
            {
                return " filter if lp port is disabled to allow 1+1 protection, trapped at transmit stage";
            }
            case LA_EVENT_ETHERNET_INCOMPATIBLE_EVE_CMD:
            {
                return " (eg, pop 2 tags in case pkt is with non or one tag), trapped at transmit stage";
            }
            case LA_EVENT_ETHERNET_PADDING_RESIDUE_IN_SECOND_LINE:
            {
                return " Pacific B0, failed to handle padding in special cases, punt this packet to control plane, trapped at transmit stage";
            }
            case LA_EVENT_ETHERNET_PFC_DIRECT_SAMPLE:
            {
                return " PFC pilot mirror. When PFC is enabled will select this mirror 1 in every 16 packets. Snoop set at the termination stage.";
            }
            case LA_EVENT_ETHERNET_SVI_EGRESS_DHCP:
            {
                return " IP packet whose L4 protocol is DHCP that is egressing an SVI port";
            }
            case LA_EVENT_ETHERNET_NO_PWE_L3_DEST:
            {
                return " PWE VPLS, failed to find PWE -> L3 Destination mapping for PWE imposition path. Trapped at Forwarding Stage.";
            }
            case LA_EVENT_IPV4_MC_FORWARDING_DISABLED:
            {
                return " ipv4 ingress l3-lp is disabled for MC, trapped at termination stage or fwd stage after tunnel termination";
            }
            case LA_EVENT_IPV4_UC_FORWARDING_DISABLED:
            {
                return " ipv4 ingress l3-lp is disabled for UC, trapped at termination stage or fwd stage after tunnel termination";
            }
            case LA_EVENT_IPV4_CHECKSUM:
            {
                return " ipv4 header checksum error, trapped at termination stage or fwd stage after tunnel termination";
            }
            case LA_EVENT_IPV4_HEADER_ERROR:
            {
                return "      trapped at termination stage or fwd stage after tunnel termination";
            }
            case LA_EVENT_IPV4_UNKNOWN_PROTOCOL:
            {
                return " ipv4 after tunnel termination, unknown overlay pkt headers / protocol, trapped at termination stage";
            }
            case LA_EVENT_IPV4_OPTIONS_EXIST:
            {
                return " ipv4 hln > 5, indicates options headers, trapped at termination stage or fwd stage after tunnel termination";
            }
            case LA_EVENT_IPV4_NON_COMP_MC:
            {
                return "";
            }
            case LA_EVENT_IPV6_MC_FORWARDING_DISABLED:
            {
                return " ipv6 ingress l3-lp is disabled for MC, trapped at termination stage or fwd stage after tunnel termination";
            }
            case LA_EVENT_IPV6_UC_FORWARDING_DISABLED:
            {
                return " ipv6 ingress l3-lp is disabled for UC, trapped at termination stage or fwd stage after tunnel termination";
            }
            case LA_EVENT_IPV6_HOP_BY_HOP:
            {
                return " ipv6 next EH header is hop-by-hop, trapped at fwd stage first IPv6 macro";
            }
            case LA_EVENT_IPV6_HEADER_ERROR:
            {
                return "      trapped at fwd stage first IPv6 macro";
            }
            case LA_EVENT_IPV6_ILLEGAL_SIP:
            {
                return " ipv6 illegal sip address, sip msb (16-msbs) are equal 16'h0, trapped at fwd stage first IPv6 macro";
            }
            case LA_EVENT_IPV6_ILLEGAL_DIP:
            {
                return " ipv6 illegal dip address, equal 0::0, trapped at fwd stage first IPv6 macro";
            }
            case LA_EVENT_IPV6_ZERO_PAYLOAD:
            {
                return "  ipv6 illegal payload, payload_length is 0 and not hop-by-hop packet, trapped at fwd stage first IPv6 macro";
            }
            case LA_EVENT_IPV6_NEXT_HEADER_CHECK:
            {
                return " Gibraltar: set if next header is hop_by_hop or destination options header";
            }
            case LA_EVENT_IPV6_NON_COMP_MC:
            {
                return " Internal trap signaling, for MC for-us packets";
            }
            case LA_EVENT_MPLS_UNKNOWN_PROTOCOL_AFTER_BOS:
            {
                return " after mpls label pop, unable to resolve the overlay header format, trapped at termination stage";
            }
            case LA_EVENT_MPLS_TTL_IS_ZERO:
            {
                return " ipv4 pkts ingress with ttl equal 1, trapped at termination stage";
            }
            case LA_EVENT_MPLS_BFD_OVER_PWE_TTL:
            {
                return " bfd over pwe and mpls ttl is set to 1, trapped at termination stage";
            }
            case LA_EVENT_MPLS_BFD_OVER_PWE_RAW:
            {
                return " bfd gal over pwe, and BFD channel is raw, trapped at termination stage";
            }
            case LA_EVENT_MPLS_BFD_OVER_PWE_IPV4:
            {
                return " bfd gal over pwe, and BFD channel is ipv4, trapped at termination stage";
            }
            case LA_EVENT_MPLS_BFD_OVER_PWE_IPV6:
            {
                return " bfd gal over pwe, and BFD channel is ipv6, trapped at termination stage";
            }
            case LA_EVENT_MPLS_UNKNOWN_BFD_G_ACH_CHANNEL_TYPE:
            {
                return " bfd gal over pwe, and failed to resole BFD channel, trapped at termination stage";
            }
            case LA_EVENT_MPLS_BFD_OVER_PWE_RA:
            {
                return " bfd over pwe and BFD channel router alert, trapped at termination stage";
            }
            case LA_EVENT_MPLS_MPLS_TP_OVER_PWE:
            {
                return " general mpls-tp over pwe (un-resolved the specific mpls-tp msg from teh cw ), trapped at termination stage";
            }
            case LA_EVENT_MPLS_UNKNOWN_G_ACH:
            {
                return " bfd over pwe, failed to resolve bfd any gal format, trapped at termination stage";
            }
            case LA_EVENT_MPLS_MPLS_TP_OVER_LSP:
            {
                return " MPLS label is reserved GAL label, trapped at termination stage";
            }
            case LA_EVENT_MPLS_OAM_ALERT_LABEL:
            {
                return " MPLS label is reserved OAM alert label, trapped at termination stage";
            }
            case LA_EVENT_MPLS_EXTENSION_LABEL:
            {
                return " MPLS label is reserved extention label, trapped at termination stage";
            }
            case LA_EVENT_MPLS_ROUTER_ALERT_LABEL:
            {
                return " MPLS label is reserved router alert label, trapped at termination stage";
            }
            case LA_EVENT_MPLS_UNEXPECTED_RESERVED_LABEL:
            {
                return " MPLS unknow reserved label, trapped at termination stage";
            }
            case LA_EVENT_MPLS_FORWARDING_DISABLED:
            {
                return " MPLS pkt ingress l3-lp is disabled for mpls, trapped at termination stage";
            }
            case LA_EVENT_MPLS_ILM_MISS:
            {
                return " MPLS fwd lookup failed in EM database, trapped at fwd stage";
            }
            case LA_EVENT_MPLS_IPV4_OVER_IPV6_EXPLICIT_NULL:
            {
                return " error packet format, IPv4 packet overlay MPLS IPv6 explicit null label, trapped at termination stage";
            }
            case LA_EVENT_MPLS_INVALID_TTL:
            {
                return " mpls outgoing transmit packet ttl is 0, trapped at transmit stage";
            }
            case LA_EVENT_MPLS_TE_MIDPOPINT_LDP_LABELS_MISS:
            {
                return " on egress failed to resolve the midpoint te or ldp label(s) in encapsulation databaes, trapped at transmit stage";
            }
            case LA_EVENT_MPLS_ASBR_LABEL_MISS:
            {
                return " on egress failed to resolve the BGP LU ASBR label in encapsulation databaes, trapped at transmit stage";
            }
            case LA_EVENT_MPLS_ILM_VRF_LABEL_MISS:
            {
                return " Label lookup in vrf fails on a CsC interface., miss in EM database, trapped at mpls fwd stage.";
            }
            case LA_EVENT_MPLS_PWE_PWACH:
            {
                return " PWE VCCV ping case, CW identifies the PWACH, trapped at mpls termination stage";
            }
            case LA_EVENT_MPLS_VPN_TTL_ONE:
            {
                return " L2/L3 VPN TTL = 1 case (VPN termination), trapped at mpls termination stage";
            }
            case LA_EVENT_MPLS_MISSING_FWD_LABEL_AFTER_POP:
            {
                return " Cannot pop and forward when forward label is missing, terminated label is BOS";
            }
            case LA_EVENT_L3_IP_UNICAST_RPF:
            {
                return " ip unicast pkts rpf check failed, trapped at fwd stage macro or resolution macro for complex rpf";
            }
            case LA_EVENT_L3_IP_MULTICAST_RPF:
            {
                return " ip multicast pkts rpf check failed, trapped at fwd stage for non compatible mc pkts or in transmit for mc compatible pkts";
            }
            case LA_EVENT_L3_IP_MC_DROP:
            {
                return "";
            }
            case LA_EVENT_L3_IP_MC_PUNT_DC_PASS:
            {
                return "";
            }
            case LA_EVENT_L3_IP_MC_SNOOP_DC_PASS:
            {
                return "";
            }
            case LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL:
            {
                return "";
            }
            case LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL:
            {
                return "";
            }
            case LA_EVENT_L3_IP_MC_SNOOP_LOOKUP_MISS:
            {
                return "";
            }
            case LA_EVENT_L3_IP_MULTICAST_NOT_FOUND:
            {
                return " priority for mc_not found, should be stronger than rpf trap since rpf is always checked";
            }
            case LA_EVENT_L3_IP_MC_S_G_PUNT_MEMBER:
            {
                return " trap must be mapped to snoop action, to ensure forward the packet to mc group members";
            }
            case LA_EVENT_L3_IP_MC_G_PUNT_MEMBER:
            {
                return " trap must be mapped to snoop action, to ensure forward the packet to mc group members";
            }
            case LA_EVENT_L3_IP_MC_EGRESS_PUNT:
            {
                return " ip multicast pkt member is marked to punt the member";
            }
            case LA_EVENT_L3_ISIS_OVER_L3:
            {
                return " ISIS pkts over L3-AC interface, , trapped at the termination stage";
            }
            case LA_EVENT_L3_ISIS_DRAIN:
            {
                return " ISIS draining/filtering, , trapped at the termination stage";
            }
            case LA_EVENT_L3_NO_HBM_ACCESS_DIP:
            {
                return " ip pkts dip LPM lookup results with failed to access hbm (prefix is in hbm), trapped at fwd stage";
            }
            case LA_EVENT_L3_NO_HBM_ACCESS_SIP:
            {
                return " ip pkts sip LPM lookup results with failed to access hbm (prefix is in hbm), trapped at fwd stage";
            }
            case LA_EVENT_L3_LPM_ERROR:
            {
                return " ip unicast pkts u-rpf LPM destination type is for-us (LPTS)";
            }
            case LA_EVENT_L3_LPM_DROP:
            {
                return " ip unicast pkts LPM destination result with drop destination, trapped at fwd stage";
            }
            case LA_EVENT_L3_LOCAL_SUBNET:
            {
                return " ip unicast pkts LPM destination encoding is directly attached does not match fwd lookup result, trapped at fwd stage";
            }
            case LA_EVENT_L3_ICMP_REDIRECT:
            {
                return " should be mapped with snoop action to allows fwd of the pkt";
            }
            case LA_EVENT_L3_NO_LP_OVER_LAG_MAPPING:
            {
                return " LP queuing (resolve VOQ over LAG) lookup failed, trapped at fwd stage last macro after resolution";
            }
            case LA_EVENT_L3_INGRESS_MONITOR:
            {
                return " map trap to netflow snoop action";
            }
            case LA_EVENT_L3_EGRESS_MONITOR:
            {
                return "";
            }
            case LA_EVENT_L3_ACL_DROP:
            {
                return " l3 forwarding pkts sec or udf acls result with deny action, trapped at fwd stage or transmit stage";
            }
            case LA_EVENT_L3_ACL_FORCE_PUNT:
            {
                return " l3 forwarding pkts sec or udf acls result with punt to host action, trapped at fwd stage or transmit stage";
            }
            case LA_EVENT_L3_ACL_FORCE_PUNT1:
            {
                return " only for ingress, these duplicate acl_force_punt for driving different TC";
            }
            case LA_EVENT_L3_ACL_FORCE_PUNT2:
            {
                return "";
            }
            case LA_EVENT_L3_ACL_FORCE_PUNT3:
            {
                return "";
            }
            case LA_EVENT_L3_ACL_FORCE_PUNT4:
            {
                return "";
            }
            case LA_EVENT_L3_ACL_FORCE_PUNT5:
            {
                return "";
            }
            case LA_EVENT_L3_ACL_FORCE_PUNT6:
            {
                return "";
            }
            case LA_EVENT_L3_ACL_FORCE_PUNT7:
            {
                return "";
            }
            case LA_EVENT_L3_GLEAN_ADJ:
            {
                return " l3 fwd adj node (next hop) can't be resolved, trapped at ingress fwd stage resolution macro";
            }
            case LA_EVENT_L3_DROP_ADJ:
            {
                return " l3 fwd adj node (next hop) filter and deny action, trapped at ingress fwd stage resolution macro";
            }
            case LA_EVENT_L3_DROP_ADJ_NON_INJECT:
            {
                return " l3 fwd adj node (next hop) filter and deny action for non inject up pkts, trapped at ingress fwd stage resolution macro";
            }
            case LA_EVENT_L3_NULL_ADJ:
            {
                return " l3 fwd adj node (next hop) is null (not set by control), trapped at ingress fwd stage resolution macro";
            }
            case LA_EVENT_L3_USER_TRAP1:
            {
                return " user defined trap1. General purpose trap.";
            }
            case LA_EVENT_L3_USER_TRAP2:
            {
                return " user defined trap2. General purpose trap.";
            }
            case LA_EVENT_L3_LPM_DEFAULT_DROP:
            {
                return " ip pkts LPM result with default deny destination to drop, trapped at fwd stage";
            }
            case LA_EVENT_L3_LPM_INCOMPLETE0:
            {
                return " ip pkts LPM result with future traped indication results, trapped at fwd stage";
            }
            case LA_EVENT_L3_LPM_INCOMPLETE2:
            {
                return " ip pkts LPM result with future traped indication results, trapped at fwd stage";
            }
            case LA_EVENT_L3_BFD_MICRO_IP_DISABLED:
            {
                return " for ip uc BFD micro hop pkts, trap to control, trapped at termination stage or fwd stage";
            }
            case LA_EVENT_L3_NO_VNI_MAPPING:
            {
                return " trapped at transmit stage";
            }
            case LA_EVENT_L3_NO_HBM_ACCESS_OG_SIP:
            {
                return " IP SIP object group LPM lookup failed to access HBM (prefix is in HBM), trapped at fwd stage";
            }
            case LA_EVENT_L3_NO_HBM_ACCESS_OG_DIP:
            {
                return " IP DIP object group LPM lookup failed to access HBM (prefix is in HBM), trapped at fwd stage";
            }
            case LA_EVENT_L3_NO_L3_DLP_MAPPING:
            {
                return " All egress l3 encapsulation processing , failed to map l3-dlp in encapsulation database, trapped at transmit stage";
            }
            case LA_EVENT_L3_L3_DLP_DISABLED:
            {
                return " Egress processing, l3-dlp is disabled for 1+1 linear protection, trapped at transmit stage";
            }
            case LA_EVENT_L3_SPLIT_HORIZON:
            {
                return " l3 interface egress split horizon filter (based on slp and dlp profile matching), trapped at transmit stage";
            }
            case LA_EVENT_L3_MC_SAME_INTERFACE:
            {
                return " excluding collapsed mc bridge copies, trapped at transmit stage";
            }
            case LA_EVENT_L3_NO_VPN_LABEL_FOUND:
            {
                return " vpn label could not be resolved on egress encapsulation databases, trapped at transmit stage";
            }
            case LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE:
            {
                return " l3 packets update ttl, when incoming ttl is 1 (and transmitted pkt ttl is set to 0), trapped at transmit stage";
            }
            case LA_EVENT_L3_TX_MTU_FAILURE:
            {
                return " l2 transmit pkt (with expected encapsulation headers) exceeded port MTU, trapped at transmit stage";
            }
            case LA_EVENT_L3_TX_FRR_DROP:
            {
                return "";
            }
            case LA_EVENT_OAMP_ETH_UNKNOWN_PUNT_REASON:
            {
                return " NPU-host OAM processing, unknown punt reason for eth oam packet";
            }
            case LA_EVENT_OAMP_ETH_MEP_MAPPING_FAILED:
            {
                return " NPU-host OAM processing, no match in MEP mapping lookup";
            }
            case LA_EVENT_OAMP_ETH_MP_TYPE_MISMATCH:
            {
                return " NPU-host OAM processing, mep type on punt header does not match location in MEP DB";
            }
            case LA_EVENT_OAMP_ETH_MEG_LEVEL_MISMATCH:
            {
                return " NPU-host OAM processing, mismatch between meg level in packet to mep DB";
            }
            case LA_EVENT_OAMP_ETH_BAD_MD_NAME_FORMAT:
            {
                return " NPU-host OAM processing, md name format is not equal to '01' (Y.1371)";
            }
            case LA_EVENT_OAMP_ETH_UNICAST_DA_NO_MATCH:
            {
                return " NPU-host OAM processing, unicast DA in OAM packet does not match the mep mac address";
            }
            case LA_EVENT_OAMP_ETH_MULTICAST_DA_NO_MATCH:
            {
                return " NPU-host OAM processing, wrong multicast DA in OAM packet";
            }
            case LA_EVENT_OAMP_ETH_WRONG_MEG_ID_FORMAT:
            {
                return " NPU-host OAM processing, meg id format or length on packet does not match mep db entry";
            }
            case LA_EVENT_OAMP_ETH_MEG_ID_NO_MATCH:
            {
                return " NPU-host OAM processing, meg id value does not match mep db entry";
            }
            case LA_EVENT_OAMP_ETH_CCM_PERIOD_NO_MATCH:
            {
                return " NPU-host OAM processing, ccm period does not match mep db entry";
            }
            case LA_EVENT_OAMP_ETH_CCM_TLV_NO_MATCH:
            {
                return " NPU-host OAM processing, tlv offset on packet != 70";
            }
            case LA_EVENT_OAMP_ETH_LMM_TLV_NO_MATCH:
            {
                return " NPU-host OAM processing, tlv offset on packet != 12";
            }
            case LA_EVENT_OAMP_ETH_NOT_SUPPORTED_OAM_OPCODE:
            {
                return " NPU-host OAM processing, oam opcode not supported by OAMP";
            }
            case LA_EVENT_OAMP_BFD_TRANSPORT_NOT_SUPPORTED:
            {
                return " NPU-host BFD processing, BFD session with incorrect transport";
            }
            case LA_EVENT_OAMP_BFD_SESSION_LOOKUP_FAILED:
            {
                return " NPU-host BFD processing, BFD failing session lookup";
            }
            case LA_EVENT_OAMP_BFD_INCORRECT_TTL:
            {
                return " NPU-host BFD processing, BFD failing ttl check";
            }
            case LA_EVENT_OAMP_BFD_INVALID_PROTOCOL:
            {
                return " NPU-host BFD processing, BFD failing protocol check";
            }
            case LA_EVENT_OAMP_BFD_INVALID_UDP_PORT:
            {
                return " NPU-host BFD processing, BFD failing UDP port check";
            }
            case LA_EVENT_OAMP_BFD_INCORRECT_VERSION:
            {
                return " NPU-host BFD processing, BFD incorrect version";
            }
            case LA_EVENT_OAMP_BFD_INCORRECT_ADDRESS:
            {
                return " NPU-host BFD processing, BFD incorrect address";
            }
            case LA_EVENT_OAMP_BFD_MISMATCH_DISCR:
            {
                return " NPU-host BFD processing, BFD mismatch in discriminator";
            }
            case LA_EVENT_OAMP_BFD_STATE_FLAG_CHANGE:
            {
                return " NPU-host BFD processing, BFD state/flag change";
            }
            case LA_EVENT_OAMP_BFD_SESSION_RECEIVED:
            {
                return " NPU-host BFD processing, BFD session received";
            }
            case LA_EVENT_OAMP_PFC_LOOKUP_FAILED:
            {
                return " NPU-host PFC implementation processing, PFC ssp lookup failed";
            }
            case LA_EVENT_OAMP_PFC_DROP_INVALID_RX:
            {
                return " NPU-host PFC implementation processing, PFC invalid rx packet";
            }
            case LA_EVENT_APP_SGACL_DROP:
            {
                return "";
            }
            case LA_EVENT_APP_SGACL_LOG:
            {
                return "";
            }
            case LA_EVENT_APP_IP_INACTIVITY:
            {
                return "";
            }
            case LA_EVENT_SVL_CONTROL_PROTOCOL:
            {
                return " Protocol Packets received on the SVL links for control processing";
            }
            case LA_EVENT_SVL_CONTROL_IPC:
            {
                return " IPC Packets received on the SVL links with Inject Down header";
            }
            case LA_EVENT_SVL_SVL_MC_PRUNE:
            {
                return " SVL Pruning trap for MC packets";
            }
            case LA_EVENT_L2_LPTS_TRAP0:
            {
                return "";
            }
            case LA_EVENT_L2_LPTS_TRAP1:
            {
                return "";
            }
            case LA_EVENT_L2_LPTS_TRAP2:
            {
                return "";
            }
            case LA_EVENT_L2_LPTS_TRAP3:
            {
                return "";
            }
            case LA_EVENT_L2_LPTS_TRAP4:
            {
                return "";
            }
            case LA_EVENT_L2_LPTS_TRAP5:
            {
                return "";
            }
            case LA_EVENT_L2_LPTS_TRAP6:
            {
                return "";
            }
            case LA_EVENT_L2_LPTS_TRAP7:
            {
                return "";
            }
            case LA_EVENT_L2_LPTS_TRAP8:
            {
                return "";
            }
            case LA_EVENT_L2_LPTS_TRAP9:
            {
                return "";
            }
            case LA_EVENT_L2_LPTS_TRAP10:
            {
                return "";
            }
            case LA_EVENT_L2_LPTS_TRAP11:
            {
                return "";
            }
            case LA_EVENT_INTERNAL_L3_LPM_LPTS:
            {
                return " served as internal datapath signal only, to start LPTS processing";
            }
            case LA_EVENT_INTERNAL_IPV4_NON_ROUTABLE_MC_ROUTING:
            {
                return "";
            }
            case LA_EVENT_INTERNAL_IPV4_NON_ROUTABLE_MC_BRIDGING:
            {
                return "";
            }
            case LA_EVENT_INTERNAL_IPV6_NON_ROUTABLE_MC_ROUTING:
            {
                return "";
            }
            case LA_EVENT_INTERNAL_IPV6_NON_ROUTABLE_MC_BRIDGING:
            {
                return "";
            }
            
            default:
            {
                break;
            }
        }
        
        return std::string("UNKNOWN la_event_e: ") + std::to_string(event);
    }
    
    
    const char* la_event_condition_names[] = {
        "LA_EVENT_CONDITION_NON_INJECT_UP",
        "LA_EVENT_CONDITION_SKIP_P2P"
    };
    
    
    /// @}
