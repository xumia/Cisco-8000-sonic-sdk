This document describe each JSON MIX file in this directory test/board/mixes/blacktip

The board tests run on blacktip Board, and connected to Spirent

Connectivity Topology:
Spirent connected to 2,1,0 400G
Slice 0 connected to Slice 5 through Palladin cable
Slice 3 connected to Slice 4 through Palladin cable

The exact connectivity between Slices is being documented in excel file ifg_connectivity_v1
To see for example the connectivity between Slices 0 and 5:
 - goto Paladin_Connectivity
 - set Connector 1 to J5
 - set Connector 2 to J0
 = the excel will show connection between each two SerDes's between the Slices

All JSON MIX files must be according above table

blacktip_default_mix.json
    This mix uses above topology to test Direct<->Direct ports on all supported technologies: 1X10,1X25,1X50,2X20,2X25,2X50,4X10,4X25,8X50

blacktip_anlt_mix.json
    This mix uses above topology to test all Supported Auto-Negotiation technologies based on IEEE Spec 802.3 Clause 73: 1X25,1X50,2X50,4X10,4X25,8X50

reconfig_mix.json
    This mix uses above topology to test reconfiguring Port configurations through reconfigure() API
