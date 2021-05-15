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
//  1.2       May 17 2019       knerurkar     No change                               //
//  1.1       Mar 08 2019       knerurkar     No change                               //
//  1.0       Feb 19 2019       knerurkar     First official release                  //
// -----------------------------------------------------------------------------------//  

typedef unsigned char u1_t;
typedef unsigned char u2_t;
typedef unsigned char u3_t;
typedef unsigned char u4_t;
typedef unsigned char u5_t;
typedef unsigned char u6_t;
typedef unsigned char u8_t;
typedef unsigned short u9_t;
typedef unsigned short u10_t;
typedef unsigned short u12_t;
typedef unsigned short u14_t;
typedef unsigned short u15_t;
typedef unsigned short u16_t;
typedef unsigned int u20_t;
typedef unsigned int u32_t;


typedef enum apbops{
    APBPHASE
   ,APBREAD
   ,APBWRITE
   
}apbOp_t;

#define PHASE0   0
#define PHASE1   1
#define PHASE2   2
#define PHASE3   3
#define PHASE4   4

#define NONE_DONE 0
#define CK_DONE 1
#define MR_DONE 2
#define WDQS_DONE 3
#define RDQS_DONE 4
#define RDSEL_DONE 5
