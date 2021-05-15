This document describe each JSON MIX file in this directory test/board/mixes/

The board tests run on Sherman Board P7, and connected to Spirent

Connectivity Topology:
________________________________________________________
    Port    |   Port    |   Topology        | Cable     |
---------------------------------------------------------
0  [0,0,8]  | 1  [0,0,0]| RT<->RT           |  100G     |
---------------------------------------------------------
2  [0,1,0]  | 3  [0,1,8]| RT<->RT           |  400G     |
---------------------------------------------------------
6  [5,1,0]  | 8  [4,1,8]| RT<->Direct       |  400G     |
---------------------------------------------------------
10 [4,0,8]  | 11 [4,0,0]| Direct<->Direct   |  400G     |
---------------------------------------------------------
12 [3,1,8]  | 13 [3,1,0]| Direct<->Direct   |  400G     |
---------------------------------------------------------
14 [3,0,8]  | 15 [3,0,0]| Direct<->Direct   |  100G     |
---------------------------------------------------------
16 [2,1,8]  | 17 [2,1,0]| Direct<->Direct   |  100G     |
---------------------------------------------------------
18 [2,0,8]  | 19 [2,0,0]| Direct<->Direct   |  100G     |
---------------------------------------------------------
20 [1,1,8]  | 21 [1,1,0]| Direct<->Direct   |  100G     |
---------------------------------------------------------
22 [1,0,8]  | Sp [2,1]  | Direct<->GEN      |  100G     |
---------------------------------------------------------
23 [1,0,0]  | Sp [1,1]  | Direct<->GEN      |  400G     |
---------------------------------------------------------

All JSON MIX files must be according above table

sherman_default_mix.json
    This mix uses above topology to test Direct<->Direct ports on all supported technologies: 1X10,1X25,1X50,2X20,2X25,2X50,4X10,4X25,8X50

sherman_anlt_mix.json
    This mix uses above topology to test all Supported Auto-Negotiation technologies based on IEEE Spec 802.3 Clause 73: 1X25,1X50,2X50,4X10,4X25,8X50

reconfig_mix.json
    This mix uses above topology to test reconfiguring Port configurations through reconfigure() API
