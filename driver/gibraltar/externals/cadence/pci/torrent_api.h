#pragma once

// Reset PHY
int Reset_PHY(apb_handler *apbh);

// Get PMA common status signals
void Get_CMN_Status(apb_handler *apbh, int &out_CMN_Rdy, int &out_Mac_Sus_ACK,
                    int &out_Refclk_active);
// Determine isolation mode
int Isolation_Mode(apb_handler *apbh);

// Get PLL0 status signals
void Get_PLL0_Status(apb_handler *apbh, int &out_PLL_CLK_en_ACK,
                     int &out_PLL_Rdy, int &out_PLL_Lock, int &out_PLL_disable);
// Get PLL1 status signals
void Get_PLL1_Status(apb_handler *apbh, int &out_PLL_CLK_en_ACK,
                     int &out_PLL_Rdy, int &out_PLL_Lock, int &out_PLL_disable);
// Reset link
int Reset_Link(apb_handler *apbh, int lane);
// Set specified powerstate
int Set_Powerstate(apb_handler *apbh, int lane, int pwrstate, int L1_substate);
// Get current powerstate
void Get_Powerstate(apb_handler *apbh, int lane, int &out_pwrstate);
// Set specified standard
int Set_Standard(apb_handler *apbh, int lane, int standard);
// Set specified loopback
int Set_Loopback(apb_handler *apbh, int lane, int loop_mode);
// Set specified cursor values
int Set_Cursors(apb_handler *apbh, int lane, int cursor);
// Set specified preset values
int Set_Preset(apb_handler *apbh, int lane, int preset);
// Get current cursor values
void Get_Cursors(apb_handler *apbh, int lane, int &out_val);
// Get current FS and LF values
void Get_FS_LF(apb_handler *apbh, int lane, int &out_FS, int &out_LF);
// Set specified Vmargin value
int Set_Vmargin(apb_handler *apbh, int lane, int Vmargin);
// Set TX idle high or low
int Set_TX_Idle(apb_handler *apbh, int lane, int idle);
// Run receiver detect test
void Receiver_Detect(apb_handler *apbh, int lane, int &out_rx_det);
// Set TX invert high or low
int Set_TX_Invert(apb_handler *apbh, int lane, int invert);
// Set TX low power swing high or low
int Set_TX_LowSwing(apb_handler *apbh, int lane, int lps);
// Set specified TX BIST mode
int Set_TX_BIST(apb_handler *apbh, int lane, int BIST_Mode, int error);
// Set RX invert high or low
int Set_RX_Invert(apb_handler *apbh, int lane, int invert);
// Get current RX sigdetect value
void Get_RX_Sigdetect(apb_handler *apbh, int lane, int &out_sigdet);
// Get current RX LFPS detect value
void Get_RX_LFPS_Detect(apb_handler *apbh, int lane, int &out_LFPS_Detect);
// Set specified RX BIST mode
int Set_RX_BIST(apb_handler *apbh, int lane, int BIST_Mode);
// Get current RX BIST status
void Get_RX_BIST_Status(apb_handler *apbh, int lane, int &out_sync,
                        int &out_error);
// Run RX EQ eval
void RX_EQ_Eval(apb_handler *apbh, int lane, int &out_EQE_eval);
// Get current RX REE status signals
void Get_RX_REE_Status(apb_handler *apbh, int lane, int &out_offset,
                       int &out_atten, int &out_VGA, int &out_peak_amp,
                       int &out_tap1, int &out_tap2, int &out_tap3);
// Run eye surf
void Eye_Surf(apb_handler *apbh, char *eye_file_path, int lane,
              int delay_time = 0x0000000F, int test_time = 0x000000FF);
