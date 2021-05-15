# SR Demand Matrix


The data-plane applciation accounts for every packet and bytes going to a SID on every hop. This counter is called the base counter. That counter is derived from the `<prefix,NH>` or the `<prefix>` egress database. In addition to that counter there's a need for an additional counter, named the TM counter, accounting for traffic entering the domain through the TM border as described in the below figure.
![SR-Demand Matrix Example](sr-demand-matrix.png)
The TM counter is increment if the packet originated from outside the TM border (Interfaces marked in red). Those interfaces are configured explicitly through the Cisco CLI.

## Definitions
* Base Counter - A Packet and Byte counter that counts traffic to a specific SID
* TM Counter - A Packet and Byte counter that counts traffic to a specific SID where the incoming interface is market for TM acounting.

## References
Reference to Requirements and Architecture doc.

## Detailed Design
### Macro Flow
The following diagram depicts the Rx macro flow.
![SR-DM-RX](sr-demand-matrix-rx-flow.png)
The external interface marking part of the source logical port attributes and is saved to the pd.
In the resolution macro it is saved to the npu header.

On the egress side, the TM counter is incremented in case a TM counter exists and is enabled, `tm_accounting` on npu header is set, not LDPoTE encapsulation type.


### API
* minimal_l3_lp_attributes_t

| Field Name  | # bits  | Default Value |    Description |
| ----------- | ------- | ------------- | -------------- |
| p_counter | 20 | 0 | source logical port counter |
| per_protocol_count | 1 | 0 | If set, then counter offset will be calculated based on the l3 protocol | 
| lp_set | 1 | 0 | if not set then the logical port attributes are inherited wfrom the underlying interface |
| **tm_accounting** | 1 | 0 | If set then this interface is an "external" interface and TM counter is to be incremented on SR forwarded packet|
| ftr_vector | 2 | 0 | Feature vector |
| l3_relay_id | 11 | 0 | VRF id |
| global_slp_id | 16 | 0 | Source LP GID |

* lsp_encap_mapping_data_payload_t

| Field Name  | # bits  | Default Value |    Description |
| ----------- | ------- | ------------- | -------------- |
| label_0     | 20      | 0 | First label to impose |
| **label_1_or_tm_counter** | 20 | 0 | Second label to impose or TM counter in case tm_accounting is marked in lsp_attributes. This is only valid in case is_3_labels is not set. | 
| label_2_or_attributes | 20 | 0 | Third label in cse is_3_labels is set, or path attributes in case it is not set |
| is_3_labels          | 1  | 0 | if set, then label_2_or_attributes contains the third label. Otherwise it contains contents of header lsp_attributes_t |
| base_counter         | 19 | 0 | LSP path base counter |

* lsp_attributes_t

| Field Name  | # bits  | Default Value |    Description |
| ----------- | ------- | ------------- | -------------- |
| lsp_idx     | 13      | 0  | LSP path index used as key in subsequent macro to retrieve additional labels |
| **tm_accounting** | 1  | 1 | Flag indicating the presence of TM counter instead of label 1|
| srte_accounting | 1 | 1 | Flag indicating that counter demuxing is applied on base counter |
| add_ipv6_explicit_null | 1 | 0 | Flag indicating whther to impose an additional IPv6 explicit null label in case packet is IPv6. |
| num_labels  | 4       | 0 | Total Number of labels to impose |

* NPU Header - nw_npu_app_header_t

| Field Name  | # bits  | Default Value |    Description |
| ----------- | ------- | ------------- | -------------- |
| ingress_ptp_info | 4 | 0 | PTP attributes |
| **tm_accounting** | 1  | 0 | Flag indicating the source logical port is set configured as "external" and should be accountin TM counter on SR traffic |
| force_pipe_ttl | 1 | 0 | Do not increment ttl on egress
| is_inject_up | 1 | 0 |Packet was injected and processed by Rx |
| ip_first_fragment | 1 | 0 | Indicator that the IP packet is the first fragment |
| ttl | 8 | 0 | incoming packet TTL |
| collapsed_mc_info | 2 | 0 | MC over SVI |
| npu_app_combined_fields | 38 | 0 | Additional Attributes |

### Counters
TM counter will be allocated from Group D at the egress. it is stamped in the network_tx_mpls_l3_macro in case the `tm_accounting` flag is set in the lsp payload and the `tm_accounting` flag is set in the NPU header. TM counter will not be stamped in case of LDPoTE encapsulation.

### Error Handling
No specific error handling. Interupt will be raised in case of counter bank collision.

## Test Plan
### Good Path
* Configure SR paths with TM counter with `n` labels n=0..8. Configure an interface with `tm_accounting` enabled and on with `tm_accounting` disabled. send packet on both interfaces. Counter on packet from `tm_accounting` should increment while on the other interface it should not.
### Bad Path
* Not aplicable
### Limits Tests
* Configure SR paths with TM counter with `n` labels on all slices until resources run out. Should be able to reach 4K. Send traffic from interfaces marked as `tm_accounting`, while removing and adding paths. Check counters increment when tm_accoiunting is set on ingress interface, and do not increment when on interface wehrer the tm acounting is unset.
### Performance Tests
* Same as above sending line rate traffic.

## Scale
The number of TM Counters supported is the derived from the number of SID lists supported and the number of counter banks that can be allocated to a Group D at teh egress. As such, the number of supported counters is 4K.
## Performance
Line rate

## Limitations
TM Counter is not supported in LDPoTE flow. (SR over tunnel)

