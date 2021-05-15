* This is the introduction and example of how to run the Serdes XBAR testing scripts.
* 
* module name: gb_anlt_base.py
* description:  
*               This file has functions do the configuration of the XBAR with:
*               serdes_rx_lane_swap_config/serdes_tx_lane_swap_config - in function set_txrx_swap_churchill() or set_txrx_swap()
*               serdes_an_master_config/serdes_an_bitmap_config - in function config_an_serdes(SERDES_NUM)
*
*               And the init_device() initialize GB with different mac_port type.
*               It has one parameter: --mac_port to specify the mac_port type, and goes through below 3 tests with all the ports. 
*
*
* module name: gb_xbar_broadcast_msg_test.py
* description:  
*               Test name: anlt_lt_broadcast_msg_test
*               It tests broadcast message from ANLT group Leader Rx to all the follower Serdes.
*
*
* module name: gb_xbar_status_test.py
* description:  
*               Test name: test_done_status
*               It tests the Done status of each ANLT group. All group followers file done status till all follower Serdes says done.
*
*               Test name: test_error_status
*               It tests the Error status of each ANLT group. All group followers file an error once there's error on any follower Serdes.
*
*
* module name: gb_xbar_txrx_msg_test.py
* description:  
*               Test name: txrx_anlt_lt_msg_test
*               It tests Tx<->Rx point to point message on all the Serdes. For each Serdes, Tx sends
*
* NOTE : for more detailed information of these tests, please check "gb_anlt_configuration.pptx"
*        

Execute path: driver/gibraltar
Testing mode: 8x50G PAM4
Testing command: 
       python3 test/board/anlt_xbar/gb_anlt_base.py --mac_port=[8|4|2|1]
       mac_port = 8 -- 8 Serdes mac port
                  4 -- 4 Serdes mac port
                  2 -- 2 Serdes mac port
                  1 -- 1 Serdes mac port

