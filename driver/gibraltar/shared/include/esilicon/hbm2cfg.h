//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
//                        ESILICON CORPORATION CONFIDENTIAL                           //
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
//      COPYRIGHT (C) 2000-2019 ESILICON CORPORATION. ALL RIGHTS RESERVED.            //
//      NO PART OF THIS DOCUMENT MAY BE PHOTOCOPIED, REPRODUCED OR TRANSLATED         //
//      TO ANOTHER PROGRAM LANGUAGE WITHOUT THE PRIOR WRITTEN CONSENT OF ESILICON     //
//      CORPORATION. THIS DATA CAN ONLY BE USED AS AUTHORIZED BY A LICENSE            //
//      FROM ESILICON CORPORATION. IN ADDITION, THIS DATA IS PROTECTED BY             //
//      COPYRIGHT LAW AND INTERNATIONAL TREATIES.                                     //
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
//                                                                                    //
// Revision           : 1.2                                                           //
// Generation date    : May 17 2019                                                   //
//                                                                                    //
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
//                                                                                    //
// View type          : C Code                                                        //
// Instance name      : ts_7ff_hbm2llhbmphy                                           //
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
//                                                                                    //
// Verified with:                                                                     //
//    a. Synopsys | VCS | N-2017.12-SP1                                               //
//                                                                                    //
// Assumptions:                                                                       //
//    a. Compiler: gcc - GNU project C and C++ compiler                               //
//                                                                                    //
// Limitations:                                                                       //
//    a. Do not support timing backannotation                                         //
//                                                                                    //
// Known bugs         : None.                                                         //
//                                                                                    //
// Known work arounds : N/A                                                           //
//                                                                                    //
// Comments           : None.                                                         //
//                                                                                    //
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
// REVISION HISTORY                                                                   //
// Revision      Date           Author        Description                             //
// -----------------------------------------------------------------------------------//
//  1.2       May 17 2019       tqcuong       Add the parameter:                      //
//                                             user_cfg_phy_ext_resistor_enab         //
//  1.1       Mar 08 2019       knerurkar     Update for the parameterized code       //
// -----------------------------------------------------------------------------------//

//Note:
//-----
// These configuration is for simulation purpose.
// For the real silicon, user should change the configuration as below:
//   
//   user_cfg_phy_train_ck_min_range    0xA
//   user_cfg_phy_train_ck_dly_start    0x000
//   user_cfg_phy_train_ck_dly_end      0x1FF
//   user_cfg_phy_train_ck_corr         0x0
//   
//   user_cfg_phy_train_rdqs_min_range  0xA
//   user_cfg_phy_train_rdqs_dly_start  0x000
//   user_cfg_phy_train_rdqs_dly_end    0x1FF
//   user_cfg_phy_train_rdqs_corr       0
//   
//   user_cfg_phy_train_wdqs_min_range  0xA
//   user_cfg_phy_train_wdqs_dly_start  0x000
//   user_cfg_phy_train_wdqs_dly_end    0x1FF
//   user_cfg_phy_train_wdqs_corr       0
//   
//   user_cfg_phy_train_rdsel_min_range 0x2
//   user_cfg_phy_train_rdsel_start     0x0
//   user_cfg_phy_train_rdsel_end       0x3F
//   user_cfg_phy_train_rdsel_corr      set to the parity latency value
   
//   user_cfg_phy_train_runtime         0x1FF
//   user_cfg_phy_train_cmd2cmd         0x0
//   user_cfg_phy_train_start_delay     0x0
//   user_cfg_phy_train_repair_en       0x1

#define user_cfg_dram_mr0 0x73
#define user_cfg_dram_mr1 0x90
#define user_cfg_dram_mr2 0xC7   
#define user_cfg_dram_mr3 0x9D
#define user_cfg_dram_mr4 0x0B //- parity = 2, disable dm, enable  ecc
#define user_cfg_dram_mr5 0x00  
#define user_cfg_dram_mr6 0x00  
#define user_cfg_dram_mr7 0x00  


#define user_cfg_phy_channel_enab 0xFF //8bits -Enable the channel for operation,eg: 0xFF means enable for all 8 channels, 0x5 enables for channel 2 & channel 0
#define user_cfg_phy_dr_strength  0x0

#define user_cfg_phy_get_trim_res_from_reg_enab  0x1
#define user_cfg_phy_trim_res                    0xF  //4bits - this field is value when user_cfg_phy_get_trim_res_from_reg_enab = 1
#define user_cfg_phy_override_cal_driv_enab      0x0
#define user_cfg_phy_override_cal_driv_n         0x00 //6bits - this field is valid when user_cfg_phy_override_cal_driv_enab = 1
#define user_cfg_phy_override_cal_driv_p         0x00 //6bits - this field is valid when user_cfg_phy_override_cal_driv_enab = 1
#define user_cfg_phy_ext_resistor_enab           0x0  //1bit

#define user_cfg_phy_pll                   0x60000be  //With PLL_REF=25Mhz, this cfg value will create the PLL_OUT = 2.4Ghz

#define user_cfg_phy_ck_ext_adj            0x3c
#define user_cfg_phy_ck_match_dly          0x4

#define user_cfg_phy_wdqs_ext_adj          0x3c
#define user_cfg_phy_wdqs_match_dly        0x4

#define user_cfg_phy_rdqs_ext_adj          0x3c
#define user_cfg_phy_rdqs_match_dly        0x4

#define user_cfg_phy_train_ck_min_range    0x3
#define user_cfg_phy_train_ck_dly_start    0x1E
#define user_cfg_phy_train_ck_dly_end      0x23
#define user_cfg_phy_train_ck_corr         0x0

#define user_cfg_phy_train_rdqs_min_range  0x3
#define user_cfg_phy_train_rdqs_dly_start  0x1E
#define user_cfg_phy_train_rdqs_dly_end    0x23
#define user_cfg_phy_train_rdqs_corr       0

#define user_cfg_phy_train_wdqs_min_range  0x3
#define user_cfg_phy_train_wdqs_dly_start  0x1E
#define user_cfg_phy_train_wdqs_dly_end    0x23
#define user_cfg_phy_train_wdqs_corr       0

#define user_cfg_phy_train_rdsel_min_range 0x2
#define user_cfg_phy_train_rdsel_start     (((user_cfg_dram_mr2 >> 3)+2)+4)//Read latency + 4
#define user_cfg_phy_train_rdsel_end       (((user_cfg_dram_mr2 >> 3)+2)+7)//Read latency + 7 
#define user_cfg_phy_train_rdsel_corr      (user_cfg_dram_mr4 >> 2)

#define user_cfg_phy_train_runtime         0x32
#define user_cfg_phy_train_cmd2cmd         0x0
#define user_cfg_phy_train_start_delay     0x0
#define user_cfg_phy_train_repair_en       0x1
