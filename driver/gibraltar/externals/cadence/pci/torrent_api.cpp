#include "apb_handler.h"
#include "api_enums.h"
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>

// Function to reset PHY
int Reset_PHY(apb_handler *apbh) {

  int readOut = 0; // Variable to read out current value of register
  int PHY_rst;     // Variable to write reset signal

  apbh->read(0xC008, readOut); // Read current value of signal
  PHY_rst =
      readOut & 0xFFFE; // Set variable to current value of signal with LSB low
  apbh->write(0xC008, PHY_rst); // Write PHY reset (LSB of this register) low
  PHY_rst = PHY_rst | 0x0001;   // Set LSB high
  apbh->write(0xC008, PHY_rst); // Write PHY reset high again

  return 0; // Indicate function has finished
}

// Function to get PMA common status signals
void Get_CMN_Status(apb_handler *apbh, int &out_CMN_Rdy, int &out_Mac_Sus_ACK,
                    int &out_Refclk_active) {

  int readOut = 0; // Variable to hold read value

  apbh->read(0xE000, readOut);    // Read status register
  out_CMN_Rdy = readOut & 0x0001; // Mask off CMN_Ready signal from reg read
  out_Mac_Sus_ACK = (readOut & 0x0020) >>
                    5; // Mask off Macro Suspend ACK signal and shift to LSB
  out_Refclk_active =
      (readOut & 0x0010) >> 4; // Mask off Refclk active signal and shift to LSB

  return;
}

// Function to read if device is in PHY or PMA isolation mode
int Isolation_Mode(apb_handler *apbh) {

  int isoOut = 0; // Variable to hold read value

  apbh->read(0xE00F, isoOut); // Read isolation register
  isoOut = (isoOut & 0x1000) >>
           12; // Mask off isolation mode select bit and shift to LSB

  return isoOut; // Return PMA (1) or PHY (0) isolation mode
}

// Function to get PMA PLL0 status signals
void Get_PLL0_Status(apb_handler *apbh, int &out_PLL_CLK_en_ACK,
                     int &out_PLL_Rdy, int &out_PLL_Lock,
                     int &out_PLL_disable) {

  int readOut = 0; // Variable to hold read value

  apbh->read(0xE001, readOut); // Read PLL control register

  out_PLL_CLK_en_ACK =
      (readOut & 0x0010) >> 4; // Mask off clock enable ACK bit and shift to LSB
  out_PLL_Rdy = (readOut & 0x0001); // Mask off PLL ready bit
  out_PLL_Lock =
      (readOut & 0x0040) >> 6; // Mask off PLL lock bit and shift to LSB
  out_PLL_disable =
      (readOut & 0x0004) >> 2; // Mask off PLL diable bit and shift to LSB

  return;
}

// Function to get PMA PLL1 status signals
void Get_PLL1_Status(apb_handler *apbh, int &out_PLL_CLK_en_ACK,
                     int &out_PLL_Rdy, int &out_PLL_Lock,
                     int &out_PLL_disable) {

  int readOut = 0; // Variable to hold read value

  apbh->read(0xE001, readOut); // Read PLL control register

  out_PLL_CLK_en_ACK =
      (readOut & 0x0020) >> 5; // Mask off clock enable ACK bit and shift to LSB
  out_PLL_Rdy = (readOut & 0x0002) >> 1; // Mask off PLL ready bit
  out_PLL_Lock =
      (readOut & 0x0080) >> 7; // Mask off PLL lock bit and shift to LSB
  out_PLL_disable =
      (readOut & 0x0008) >> 3; // Mask off PLL diable bit and shift to LSB

  return;
}

// Function to reset link
int Reset_Link(apb_handler *apbh, int lane) {

  int readOut = 0; // Variable to read current state of register
  int addr;        // Variable to hold register address
  int link_rst;    // Variable to write reset signal

  addr = 0xD00B; // Set base address and modify with lane input
  addr = addr | (lane << 8);

  apbh->read(addr, readOut);    // Read current state of register
  link_rst = readOut & 0xFFFE;  // Set link reset low
  apbh->write(addr, link_rst);  // Write to register
  link_rst = link_rst | 0x0001; // Set link reset high
  apbh->write(addr, link_rst);  // Write to register

  return 0;
}

// Function to change powerstate
// Must be in PHY isolation mode for this function
int Set_Powerstate(apb_handler *apbh, int lane, int pwrstate, int L1_substate) {

  int readOut = 0; // Variable to read current state of register
  int write;       // Variable to write to registers
  int addr;        // Variable to hold register address

  addr = 0xD00B; // Set base address and modify with lane input
  addr = addr | (lane << 8);

  apbh->read(addr, readOut);   // Read current state of register
  write = readOut & 0xEFFF;    // Set ent_l1_x bit low
  apbh->write(addr, write);    // Write ent_l1_x to register
  while (readOut & 0x0002) {   // Wait for phy_status to go low
    apbh->read(addr, readOut); // Refresh read on each loop
  }

  write =
      (write & 0xFF8F) | (pwrstate << 4); // Set desired powerstate from input
  apbh->write(addr, write);     // Write desired powerstate to register
  while (!(readOut & 0x0002)) { // Wait for phy_status to go high
    apbh->read(addr, readOut);  // Refresh read on each loop
  }

  write = write | 0x0400;   // Set tx_cmn_mode_en high
  apbh->write(addr, write); // Write tx_cmn_mode_en to register

  if (pwrstate >> 2) {        // If L1.1 or L1.2 is desired
    write = write | 0x1000;   // Set ent_l1_x high
    apbh->write(addr, write); // Write to register

    if (!L1_substate) {         // If L1.2 is desired
      write = write & 0xFBFF;   // Set tx_cmn_mode_en low
      apbh->write(addr, write); // Write to register
    }
  }

  return 0;
}

// Function to read current powerstate
void Get_Powerstate(apb_handler *apbh, int lane, int &out_pwrstate) {

  int readOut = 0; // Variable to hold reg read
  int addr;        // Variable to hold register address
  int pstate;      // Variable to hold one-hot powerstate encoding

  addr = 0xF00B; // Set base address and modify with lane input
  addr = addr | (lane << 8);

  apbh->read(addr, readOut); // Read powerstate register
  pstate =
      (readOut & 0x3F00) >> 8; // Mask off current powerstate bits and shift

  switch (pstate) { // Translate one hot encoding request input to power state
                    // output (PMA spec table 13)
  case 0:
    out_pwrstate = 0xFF; // Initial power up state
    break;
  case 1:
    out_pwrstate = 0x00;
    break;
  case 2:
    out_pwrstate = 0x01;
    break;
  case 4:
    out_pwrstate = 0x02;
    break;
  case 8:
    out_pwrstate = 0x03;
    break;
  }

  return;
}

// Function to set standard
int Set_Standard(apb_handler *apbh, int lane, int standard) {

  int pwrstate = 0; // Variable to hold previous powerstate
  int readOut = 0;  // Variable to hold reg reads
  int addr_rst;     // Variable to hold address of xcvr reset register
  int addr_stn;     // Variable to hold address of PMA standards register
  int addr_phy;     // Variable to hold address of PHY isolation register
  int xcvr_reset;   // Variable to write xcvr reset
  int width = 0x5;  // Variable to hold data width value, default is 20 bits
  int set_stn;      // Variable to write standard to register

  switch (lane) { // Translate lane input to register addresses
  case 0:
    addr_rst = 0xF003;
    addr_stn = 0xF00A;
    addr_phy = 0xD00B;
    break;
  case 1:
    addr_rst = 0xF103;
    addr_stn = 0xF10A;
    addr_phy = 0xD10B;
    break;
  case 2:
    addr_rst = 0xF203;
    addr_stn = 0xF20A;
    addr_phy = 0xD20B;
    break;
  case 3:
    addr_rst = 0xF303;
    addr_stn = 0xF30A;
    addr_phy = 0xD30B;
    break;
  case 4:
    addr_rst = 0xF403;
    addr_stn = 0xF40A;
    addr_phy = 0xD40B;
    break;
  case 5:
    addr_rst = 0xF503;
    addr_stn = 0xF50A;
    addr_phy = 0xD50B;
    break;
  case 6:
    addr_rst = 0xF603;
    addr_stn = 0xF60A;
    addr_phy = 0xD60B;
    break;
  case 7:
    addr_rst = 0xF703;
    addr_stn = 0xF70A;
    addr_phy = 0xD70B;
    break;
  default:
    return -1;
  }

  Get_Powerstate(apbh, lane, pwrstate); // Get current powerstate
  Set_Powerstate(apbh, lane, 0x02, 0);   // Transition to powerstate A2

  apbh->read(addr_rst, readOut);     // Read current value of reset register
  xcvr_reset = readOut | 0x0100;     // Set xcvr_reset high
  apbh->write(addr_rst, xcvr_reset); // Write xcvr_reset to register

  if (standard == 0x2) { // If Gen3 standard, set data width to 16 bits
    width = 0x1;
  }
  apbh->read(addr_stn, readOut); // Read current value of standards register
  set_stn = (readOut & 0xFFC8) | width |
            (standard
             << 4); // Modify value with correct data width and input standard
  apbh->write(addr_stn, set_stn); // Write standard and data width to register

  apbh->read(addr_phy,
             readOut); // Read current value of PHY iso standards register
  set_stn =
      (readOut & 0xFCFF) | (standard << 8); // Modify value with input standard
  apbh->write(addr_phy, set_stn);           // Write standard to register

  xcvr_reset = xcvr_reset & 0xFEFF;  // Set xcvr reset low
  apbh->write(addr_rst, xcvr_reset); // Write xcvr reset
  Set_Powerstate(apbh, lane, pwrstate,
                 0); // Set powerstate back to previous state

  return 0;
}

// Function to enable various loopback functions
// Programmer's guide section 3.8
int Set_Loopback(apb_handler *apbh, int lane, int loop_mode) {

  int addr; // Variable to hold register address

  addr = 0xF001; // Set base address and modify with lane input
  addr = addr | (lane << 8);

  apbh->write(addr, loop_mode); // Write loopback settings

  return 0;
}

// Function to set cursor values
int Set_Cursors(apb_handler *apbh, int lane, int cursor) {

  int iso;       // Variable to indicate PMA or PHY isolation mode
  int addrh = 0; // Variable to hold high isolation register address
  int addrl = 0; // Variable to hold low isolation register address
  int crsr_l;    // Variable to hold low 6 bits of cursor input
  int crsr_m;    // Variable to hold mid 6 bits of cursor input
  int crsr_h;    // Variable to hold high 6 bits of cursor input
  int write_var; // Variable to write to registers

  iso = Isolation_Mode(apbh); // Determine PMA or PHY isolation mode

  if (iso) {
    switch (lane) { // Translate lane input to register addresses
    case 0:
      addrl = 0xF006;
      addrh = 0xF007;
      break;
    case 1:
      addrl = 0xF106;
      addrh = 0xF107;
      break;
    case 2:
      addrl = 0xF206;
      addrh = 0xF207;
      break;
    case 3:
      addrl = 0xF306;
      addrh = 0xF307;
      break;
    case 4:
      addrl = 0xF406;
      addrh = 0xF407;
      break;
    case 5:
      addrl = 0xF506;
      addrh = 0xF507;
      break;
    case 6:
      addrl = 0xF606;
      addrh = 0xF607;
      break;
    case 7:
      addrl = 0xF706;
      addrh = 0xF707;
      break;
    }
  } else {
    switch (lane) { // Translate lane input to register addresses
    case 0:
      addrl = 0xD003;
      addrh = 0xD004;
      break;
    case 1:
      addrl = 0xD103;
      addrh = 0xD104;
      break;
    case 2:
      addrl = 0xD203;
      addrh = 0xD204;
      break;
    case 3:
      addrl = 0xD303;
      addrh = 0xD304;
      break;
    case 4:
      addrl = 0xD403;
      addrh = 0xD404;
      break;
    case 5:
      addrl = 0xD503;
      addrh = 0xD504;
      break;
    case 6:
      addrl = 0xD603;
      addrh = 0xD604;
      break;
    case 7:
      addrl = 0xD703;
      addrh = 0xD704;
      break;
    }
  }

  crsr_l = cursor & 0x0003F; // Zero out first 12 bits of cursor input and place
                             // in low cursor variable
  crsr_m = (cursor & 0x00FC0) >> 6;  // Zero out first and last 6 bits of cursor
                                     // input and place in mid cursor variable
  crsr_h = (cursor & 0x3F000) >> 12; // Zero out last 12 bits of cursor input
                                     // and place in high cursor variable

  write_var =
      0x0000 | crsr_l |
      (crsr_m << 8); // Encode low and mid cursor values into write variable
  apbh->write(addrl, write_var); // Write to register

  write_var = 0x0000 | crsr_h;   // Encode high cursor value into write variable
  apbh->write(addrh, write_var); // Write to register

  return 0;
}

// Function to set PCIe preset values
int Set_Preset(apb_handler *apbh, int lane, int preset) {

  int addr_pl;     // Variable to hold address of preset coefficients low iso
                   // register
  int addr_ph;     // Variable to hold address of preset coefficients high iso
                   // register
  int addr_dl;     // Variable to hold address of deemphasis low iso register
  int addr_dh;     // Variable to hold address of deemphasis high iso register
  int iso;         // Variable to determine isolation mode
  int readOut = 0; // Variable to hold reg read
  int writevar;    // Variable to write to registers

  iso = Isolation_Mode(apbh); // Determine PMA or PHY isolation mode

  if (iso) { // Set register address based on isolation mode
    addr_pl = 0xF004;
  } else {
    addr_pl = 0xD001;
  }

  addr_pl = addr_pl | (lane << 8); // Alter register address based on lane input
  addr_ph =
      addr_pl + 1; // Set address of other three registers as offset of addr_pl
  addr_dl = addr_ph + 1;
  addr_dh = addr_dl + 1;

  apbh->read(addr_ph, readOut); // Read current value of register
  writevar =
      (readOut & 0xF0FF) |
      (preset << 8); // Zero out preset index bits and insert preset input
  apbh->write(addr_ph, writevar); // Write preset index to register
  writevar = writevar | 0x1000;   // Set tx_get_local_preset_coef bit high
  apbh->write(addr_ph, writevar); // Write bit to register
  apbh->read(addr_ph, readOut);   // Read register
  while (!(readOut & 0x8000)) {   // Wait for 15th bit to go high
    apbh->read(addr_ph, readOut); // Refresh readOut on each loop
  }

  apbh->write(addr_dh,
              readOut); // Write bits [5:0] to deemphasis isolation register
  apbh->read(addr_pl, readOut); // Read low preset register
  apbh->write(addr_dl,
              readOut); // Write low preset values to low deemphasis register

  return 0;
}

// Function to read tx emphasis values
// PMA spec 3.2.19
void Get_Cursors(apb_handler *apbh, int lane, int &out_val) {

  int dataOut = 0; // Variable to hold data from reg read
  int addr_pre;    // Variable to hold address for pre-cursor reg read
  int addr_main;   // Variable to hold address for main-cursor reg read
  int addr_post;   // Variable to hold address for post-cursor reg read
  int prec;        // Variable to combine pre-cursor value into out_val
  int mainc;       // Variable to combine main-cursor value into out_val
  int postc;       // Variable to combine post-cursor value into out_val

  switch (lane) { // Translate lane input to register addresses
  case 0:
    addr_pre = 0x4044;
    addr_main = 0x4045;
    addr_post = 0x4046;
    break;
  case 1:
    addr_pre = 0x4244;
    addr_main = 0x4245;
    addr_post = 0x4246;
    break;
  case 2:
    addr_pre = 0x4444;
    addr_main = 0x4445;
    addr_post = 0x4446;
    break;
  case 3:
    addr_pre = 0x4644;
    addr_main = 0x4645;
    addr_post = 0x4646;
    break;
  case 4:
    addr_pre = 0x4844;
    addr_main = 0x4845;
    addr_post = 0x4846;
    break;
  case 5:
    addr_pre = 0x4A44;
    addr_main = 0x4A45;
    addr_post = 0x4A46;
    break;
  case 6:
    addr_pre = 0x4C44;
    addr_main = 0x4C45;
    addr_post = 0x4C46;
    break;
  case 7:
    addr_pre = 0x4E44;
    addr_main = 0x4E45;
    addr_post = 0x4E46;
    break;
  default:
      return;
  }

  apbh->read(addr_pre, dataOut); // Read TX pre-cursor value
  dataOut = dataOut & 0x003F;    // Mask off last 6 bits
  prec = dataOut << 12;          // Shift precursor value and store in prec

  apbh->read(addr_main, dataOut); // Read TX main-cursor value
  dataOut = dataOut & 0x003F;     // Mask off last 6 bits
  mainc = dataOut << 6;           // Shift main cursor value and store in mainc

  apbh->read(addr_post, dataOut); // Read TX post-cursor value
  dataOut = dataOut & 0x003F;     // Mask off last 6 bits
  postc = dataOut;                // Store postc value

  out_val = prec | mainc | postc; // Combine three values into one 18 bit word

  return;
}

// Function to readback FS and LF values
void Get_FS_LF(apb_handler *apbh, int lane, int &out_FS, int &out_LF) {

  int readOut = 0; // Variable to hold reg read
  int addr;        // Variable to hold register address

  addr = 0xD005; // Set base address and modify with lane input
  addr = addr | (lane << 8);

  apbh->read(addr, readOut);        // Read FS/LF register
  out_LF = readOut & 0x003F;        // Mask off LF bits
  out_FS = (readOut & 0x3F00) >> 8; // Mask off FS bits and shift to LSB

  return;
}

// Function to set Vmargin value
int Set_Vmargin(apb_handler *apbh, int lane, int Vmargin) {

  int addr;        // Variable to hold register address
  int readOut = 0; // Variable to hold reg read
  int Vwrite;      // Variable to write Vmargin current value

  addr = 0xF009; // Set base addresses and modify with lane input
  addr = addr | (lane << 8);

  apbh->read(addr, readOut); // Read current value of register
  Vwrite = (readOut & 0xFFF8) |
           Vmargin; // Zero out Vmargin bits and set to specified Vmargin input
  apbh->write(addr, Vwrite); // Write Vmargin to register

  return 0;
}

// Function to set TX electrical idle high or low
int Set_TX_Idle(apb_handler *apbh, int lane, int idle) {

  int addr_phy;    // Variable to hold address of PHY register
  int addr_pma;    // Variable to hold address of PMA register
  int phyw;        // Variable to write to PHY reg
  int pmaw;        // Variable to write to PMA reg
  int readOut = 0; // Variable to hold reg read

  switch (lane) { // Translate lane input to register addresses
  case 0:
    addr_phy = 0xD000;
    addr_pma = 0xF003;
    break;
  case 1:
    addr_phy = 0xD100;
    addr_pma = 0xF103;
    break;
  case 2:
    addr_phy = 0xD200;
    addr_pma = 0xF203;
    break;
  case 3:
    addr_phy = 0xD300;
    addr_pma = 0xF303;
    break;
  case 4:
    addr_phy = 0xD400;
    addr_pma = 0xF403;
    break;
  case 5:
    addr_phy = 0xD500;
    addr_pma = 0xF503;
    break;
  case 6:
    addr_phy = 0xD600;
    addr_pma = 0xF603;
    break;
  case 7:
    addr_phy = 0xD700;
    addr_pma = 0xF703;
    break;
  default:
    return -1;
  }

  if (idle) {
    apbh->read(addr_phy, readOut); // Read current value of PHY register
    phyw = readOut | 0x0008;       // Set TX idle bit high
    apbh->write(addr_phy, phyw);   // Write TX idle bit to register

    apbh->read(addr_pma, readOut); // Read current value of PMA register
    pmaw = readOut | 0x1000;       // Set TX idle bit high
    apbh->write(addr_pma, pmaw);   // Write TX idle bit to register
  } else {
    apbh->read(addr_phy, readOut); // Read current value of PHY register
    phyw = readOut & 0xFFF7;       // Set TX idle bit low
    apbh->write(addr_phy, phyw);   // Write TX idle bit to register

    apbh->read(addr_pma, readOut); // Read current value of PMA register
    pmaw = readOut & 0xEFFF;       // Set TX idle bit low
    apbh->write(addr_pma, pmaw);   // Write TX idle bit to register
  }

  return 0;
}

// Function to run receiver detect
void Receiver_Detect(apb_handler *apbh, int lane, int &out_rx_det) {

  int iso;         // Variable to determine whether in PMA or PHY iso mode
  int addr;        // Variable to hold main register address
  int addr_stat;   // Variable to hold status register address for PHY iso
  int addr_idle;   // Variable to check idle status for PHY iso
  int readOut = 0; // Variable to hold reg read
  int idle;        // Variable to hold previous tx idle state
  int rcvdet;      // Variable to write to registers

  iso = Isolation_Mode(apbh); // Determine current isolation mode

  if (!iso) {      // PHY isolation mode
    addr = 0xD00B; // Set base addresses and modify with lane input
    addr = addr | (lane << 8);
    addr_stat = 0xD008;
    addr_stat = addr_stat | (lane << 8);
    addr_idle = 0xD000;
    addr_idle = addr_idle | (lane << 8);

    apbh->read(addr_idle, readOut); // Read current value of idle register
    idle = (readOut & 0x0010);      // Save idle bit to variable
    Set_TX_Idle(apbh, lane, 0x1);   // Set TX to idle

    apbh->read(addr_stat,
               readOut); // Read both registers to clear previous bits
    apbh->read(addr, readOut);

    apbh->read(addr, readOut);    // Read current value of register
    rcvdet = readOut | 0x0400;    // Set cmn mode enable high
    apbh->write(addr, rcvdet);    // Write to register
    rcvdet = rcvdet | 0x0004;     // Set rcv detect enable high
    apbh->write(addr, rcvdet);    // Write to register
    while (!(readOut & 0x0002)) { // Wait for PHY status to go high
      apbh->read(addr, readOut);  // Refresh readOut on each loop
    }
    apbh->read(addr_stat, readOut); // Read rx status register
    if ((readOut & 0x0007) ==
        0x0003) { // If rx status is 3, set rx_det output high
      out_rx_det = 0x1;
    } else { // If rx status is not 3, set rx_det out low
      out_rx_det = 0x0;
    }
    rcvdet = rcvdet & 0xFBFB;  // Set cmn mode enable and rcv detect enable low
    apbh->write(addr, rcvdet); // Write to register
    if (!idle) { // If TX idle was previously disabled, set low again
      Set_TX_Idle(apbh, lane, 0x0);
    }
  } else {
    addr = 0xF003;             // Set base address
    addr = addr | (lane << 8); // Modify address based on lane input

    apbh->read(addr, readOut); // Read current value of register
    idle = readOut & 0x1000;   // Save tx idle value
    rcvdet = readOut | 0x1000; // Set idle high
    apbh->write(addr, rcvdet); // Write idle to register

    rcvdet = rcvdet | 0x0200;     // Set receiver detect enable high
    apbh->write(addr, rcvdet);    // Write to register
    while (!(readOut & 0x0400)) { // Wait for rcv detect done to go high
      apbh->read(addr, readOut);  // Refresh readOut on each loop
    }
    out_rx_det =
        (readOut & 0x0800) >> 11; // Mask off value of tx_rcv_detected and shift
    if (!idle) { // If idle was low before, set it low again at end of function
      rcvdet = readOut & 0xEFFF;
      apbh->write(addr, rcvdet);
    }
  }

  return;
}

// Function to set TX differential invert high or low
int Set_TX_Invert(apb_handler *apbh, int lane, int invert) {

  int addr;        // Variable to hold register address
  int readOut = 0; // Variable to hold reg read
  int inv;         // Variable to write invert

  addr = 0xF000; // Set base address and modify with lane input
  addr = addr | (lane << 8);

  apbh->read(addr, readOut); // Read current value of register
  if (invert) {
    inv = readOut | 0x0080; // Set invert bit high
  } else {
    inv = readOut & 0xFF7F; // Set invert bit low
  }
  apbh->write(addr, inv); // Write invert bit

  return 0;
}

// Function to set TX low power swing high or low
int Set_TX_LowSwing(apb_handler *apbh, int lane, int lps) {

  int addr;        // Variable to hold register address
  int readOut = 0; // Variable to hold reg read
  int swing;       // Variable to write low swing

  addr = 0xF009; // Set base address and modify with lane input
  addr = addr | (lane << 8);

  apbh->read(addr, readOut); // Read current value of register
  if (lps) {
    swing = readOut | 0x0080; // Set TX low swing bit high
  } else {
    swing = readOut & 0xFF7F; // Set TX low swing bit low
  }
  apbh->write(addr, swing); // Write TX low swing bit to register

  return 0;
}

// Function to disable TX BIST or setup to generate specified pattern
int Set_TX_BIST(apb_handler *apbh, int lane, int BIST_Mode, int error) {

  int addr;        // Variable to hold register address
  int readOut = 0; // Variable to hold reg read
  int regWrite;    // Variable to write to register

  addr = 0x4140; // Set base address and modify with lane input
  addr = addr | (lane << 9);

  apbh->read(addr, readOut); // Read current value of register

  if (BIST_Mode) { // If BIST is going to be enabled, set and write enable bit
    regWrite = readOut | 0x0001;
    apbh->write(addr, regWrite);
  }

  switch (BIST_Mode) { // Parse BIST_Mode input
  case 0:
    regWrite = readOut & 0xFFFE; // If BIST_Mode = 0, disable TX BIST
    break;
  case 1:
    regWrite = (readOut & 0xF0FF) | 0x0800;
    break;
  case 2:
    regWrite = (readOut & 0xF0FF) |
               0x0900; // If BIST_Mode = 1-4, zero out BIST mode field, set
    break;
  case 3:
    regWrite = (readOut & 0xF0FF) |
               0x0A00; // enable bit high, and set BIST mode field to
    break;
  case 4:
    regWrite = (readOut & 0xF0FF) | 0x0B00; // corresponding pattern
    break;
  }

  if (error) {
    regWrite =
        regWrite | 0x0010; // If error input is high, set force error bit high
  } else {
    regWrite =
        regWrite & 0xFFEF; // If error input is low, set force error bit low
  }

  apbh->write(addr, regWrite); // Write final bit string to register

  return 0;
}

// Function to set RX differential invert
int Set_RX_Invert(apb_handler *apbh, int lane, int invert) {

  int addr_pma;    // Variable to hold pma register address
  int addr_phy;    // Variable to hold phy register address
  int readOut = 0; // Variable to hold reg read
  int inv;         // Variable to write invert

  switch (lane) { // Translate lane input to register addresses
  case 0:
    addr_pma = 0xF000;
    addr_phy = 0xD008;
    break;
  case 1:
    addr_pma = 0xF100;
    addr_phy = 0xD108;
    break;
  case 2:
    addr_pma = 0xF200;
    addr_phy = 0xD208;
    break;
  case 3:
    addr_pma = 0xF300;
    addr_phy = 0xD308;
    break;
  case 4:
    addr_pma = 0xF400;
    addr_phy = 0xD408;
    break;
  case 5:
    addr_pma = 0xF500;
    addr_phy = 0xD508;
    break;
  case 6:
    addr_pma = 0xF600;
    addr_phy = 0xD608;
    break;
  case 7:
    addr_pma = 0xF700;
    addr_phy = 0xD708;
    break;
  default:
    return -1;
  }

  if (invert) {
    apbh->read(addr_pma, readOut); // Read current value of register
    inv = readOut | 0x0001;        // Set invert bit high
    apbh->write(addr_pma, inv);    // Write invert bit

    apbh->read(addr_phy, readOut); // Read current value of register
    inv = readOut | 0x0080;        // Set invert bit high
    apbh->write(addr_phy, inv);    // Write invert bit
  } else {
    apbh->read(addr_pma, readOut); // Read current value of register
    inv = readOut & 0xFFFE;        // Set invert bit low
    apbh->write(addr_pma, inv);    // Write invert bit

    apbh->read(addr_phy, readOut); // Read current value of register
    inv = readOut & 0xFF7F;        // Set invert bit low
    apbh->write(addr_phy, inv);     // Write invert bit
  }

  return 0;
}

// Function to get current value of sigdetect
void Get_RX_Sigdetect(apb_handler *apbh, int lane, int &out_sigdet) {

  int addr;        // Variable to hold register address
  int readOut = 0; // Variable to hold reg read

  addr = 0xF003; // Set base address and modify with lane input
  addr = addr | (lane << 8);

  apbh->read(addr, readOut); // Read xcvr control register
  out_sigdet = (readOut & 0x0008) >>
               3; // Zero out all bits except sigdetect and shift to LSB

  return;
}

// Function to get current value of LFPS detect
void Get_RX_LFPS_Detect(apb_handler *apbh, int lane, int &out_LFPS_Detect) {

  int addr;        // Variable to hold register address
  int readOut = 0; // Variable to hold reg read

  addr = 0xF003; // Set base address and modify with lane input
  addr = addr | (lane << 8);

  apbh->read(addr, readOut); // Read xcvr control register
  out_LFPS_Detect = (readOut & 0x0010) >>
                    4; // Zero out all bits except LFPS detect and shift to LSB

  return;
}

// Function to disable RX BIST or setup to generate specified pattern
int Set_RX_BIST(apb_handler *apbh, int lane, int BIST_Mode) {

  int addr;        // Variable to hold register address
  int readOut = 0; // Variable to hold reg read
  int regWrite;    // Variable to write to register

  addr = 0x80B0; // Set base address and modify with lane input
  addr = addr | (lane << 9);

  apbh->read(addr, readOut); // Read current value of register

  if (BIST_Mode) { // If BIST is going to be enabled, set and write enable bit
    regWrite = readOut | 0x0001;
    apbh->write(addr, regWrite);
  }

  switch (BIST_Mode) { // Parse BIST_Mode input
  case 0:
    regWrite = readOut & 0xFFFE; // If BIST_Mode = 0, disable RX BIST
    break;
  case 1:
    regWrite = (readOut & 0xF0FF) | 0x0800;
    break;
  case 2:
    regWrite = (readOut & 0xF0FF) |
               0x0900; // If BIST_Mode = 1-4, zero out BIST mode field, set
    break;
  case 3:
    regWrite = (readOut & 0xF0FF) |
               0x0A00; // enable bit high, and set BIST mode field to
    break;
  case 4:
    regWrite = (readOut & 0xF0FF) | 0x0B00; // corresponding pattern
    break;
  }

  apbh->write(addr, regWrite); // Write final bit string to register

  return 0;
}

// Function to get current RX BIST status
void Get_RX_BIST_Status(apb_handler *apbh, int lane, int &out_sync,
                        int &out_error) {

  int addr_sync;   // Variable to hold address of PMA xcvr control register
  int addr_err;    // Variable to hold address of error count register
  int readOut = 0; // Variable to read out full PMA xcvr control register

  addr_sync = 0xF000; // Set base address and modify with lane input
  addr_sync = addr_sync | (lane << 8);

  addr_err = 0x80B3; // Set base address and modify with lane input
  addr_err = addr_err | (lane << 9);

  apbh->read(addr_sync, readOut); // Read PMA xcvr control register
  out_sync =
      (readOut & 0x0002) >> 1; // Zero out all but sync bit and shift to LSB
  apbh->read(addr_err, out_error); // Read error count

  return;
}

// Function to run RX EQ Eval
void RX_EQ_Eval(apb_handler *apbh, int lane, int &out_EQE_eval) {

  int addr;        // Variable to hold register address
  int readOut = 0; // Variable to hold reg read
  int EQEwrite;    // Variable to write to register
  int iso;

  iso = Isolation_Mode(apbh);

  if (iso) {
    addr = 0xF00D;             // Set register address
    addr = addr | (lane << 8); // Modify address with lane number

    apbh->read(addr, readOut); // Read current value of register
    if (readOut & 0x0002) {    // If status bit is high, quit function
      return;
    }
    EQEwrite = readOut | 0x0001;  // Set start bit high
    apbh->write(addr, EQEwrite);  // Write start bit high
    while (!(readOut & 0x0002)) { // Wait for status bit to go high
      apbh->read(addr, readOut); // Refresh readOut on each loop
    }
    out_EQE_eval =
        (readOut & 0x03F0) >> 4; // Mask off dir_change bits, shift, and output
    EQEwrite = readOut & 0xFFFE; // Set start bit low again
    apbh->write(addr, EQEwrite); // Write start bit low
  } else {
    addr = 0xD009;             // Set register address
    addr = addr | (lane << 8); // Modify address with lane number

    apbh->read(addr, readOut); // Read current value of register
    if (readOut & 0x0040) {     // If status bit is high, quit function
      return;
    }
    EQEwrite = readOut | 0x0100;  // Set start bit high
    apbh->write(addr, EQEwrite);  // Write start bit
    while (!(readOut & 0x0040)) { // Wait for status bit to go high
      apbh->read(addr, readOut); // Refresh readOut on each loop
    }
    out_EQE_eval = readOut & 0x003F; // Mask off dir_change bits and output
    EQEwrite = readOut & 0xFEFF;     // Set start bit low
    apbh->write(addr, EQEwrite);     // Write start bit
  }

  return;
}

// Function to get current RX REE values
void Get_RX_REE_Status(apb_handler *apbh, int lane, int &out_offset,
                       int &out_atten, int &out_VGA, int &out_peak_amp,
                       int &out_tap1, int &out_tap2, int &out_tap3) {

  int addr_off;    // Variable to hold offset register address
  int addr_att;    // Variable to hold attenuation register address
  int addr_vga;    // Variable to hold VGA register address
  int addr_pka;    // Variable to hold peaking amp register address
  int addr_tp1;    // Variable to hold tap1 register address
  int addr_tp2;    // Variable to hold tap2 register address
  int addr_tp3;    // Variable to hold tap3 register address
  int readOut = 0; // Variable to read from registers

  switch (lane) { // Translate lane input to register addresses
  case 0:
    addr_off = 0x8166;
    addr_att = 0x814C;
    addr_vga = 0x8162;
    addr_pka = 0x8137;
    addr_tp1 = 0x8152;
    addr_tp2 = 0x8156;
    addr_tp3 = 0x815A;
    break;
  case 1:
    addr_off = 0x8366;
    addr_att = 0x834C;
    addr_vga = 0x8362;
    addr_pka = 0x8337;
    addr_tp1 = 0x8352;
    addr_tp2 = 0x8356;
    addr_tp3 = 0x835A;
    break;
  case 2:
    addr_off = 0x85166;
    addr_att = 0x854C;
    addr_vga = 0x8562;
    addr_pka = 0x8537;
    addr_tp1 = 0x8552;
    addr_tp2 = 0x8556;
    addr_tp3 = 0x855A;
    break;
  case 3:
    addr_off = 0x8766;
    addr_att = 0x874C;
    addr_vga = 0x8762;
    addr_pka = 0x8737;
    addr_tp1 = 0x8752;
    addr_tp2 = 0x8756;
    addr_tp3 = 0x875A;
    break;
  case 4:
    addr_off = 0x8966;
    addr_att = 0x894C;
    addr_vga = 0x8962;
    addr_pka = 0x8937;
    addr_tp1 = 0x8952;
    addr_tp2 = 0x8956;
    addr_tp3 = 0x895A;
    break;
  case 5:
    addr_off = 0x8A166;
    addr_att = 0x8A4C;
    addr_vga = 0x8A62;
    addr_pka = 0x8A37;
    addr_tp1 = 0x8A52;
    addr_tp2 = 0x8A56;
    addr_tp3 = 0x8A5A;
    break;
  case 6:
    addr_off = 0x8C66;
    addr_att = 0x8C4C;
    addr_vga = 0x8C62;
    addr_pka = 0x8C37;
    addr_tp1 = 0x8C52;
    addr_tp2 = 0x8C56;
    addr_tp3 = 0x8C5A;
    break;
  case 7:
    addr_off = 0x8F66;
    addr_att = 0x8F4C;
    addr_vga = 0x8F62;
    addr_pka = 0x8F37;
    addr_tp1 = 0x8F52;
    addr_tp2 = 0x8F56;
    addr_tp3 = 0x8F5A;
    break;
  default:
    return;
  }

  apbh->read(addr_off, readOut); // Read offset register
  out_offset =
      readOut & 0x003F; // Mask off last 6 bits and set to output variable
  apbh->read(addr_att, readOut); // Read attenuation register
  out_atten =
      readOut & 0x001F; // Mask off last 5 bits and set to output variable
  apbh->read(addr_vga, readOut); // Read VGA register
  out_VGA = readOut & 0x003F; // Mask off last 6 bits and set to output variable
  apbh->read(addr_pka, readOut); // Read peak amp register
  out_peak_amp =
      readOut & 0x003F; // Mask off last 6 bits and set to output variable
  apbh->read(addr_tp1, readOut); // Read tap 1 register
  out_tap1 =
      readOut & 0x003F; // Mask off last 6 bits and set to output variable
  apbh->read(addr_tp2, readOut); // Read tap 2 register
  out_tap2 =
      readOut & 0x003F; // Mask off last 6 bits and set to output variable
  apbh->read(addr_tp3, readOut); // Read tap 3 register
  out_tap3 =
      readOut & 0x003F; // Mask off last 6 bits and set to output variable

  return;
}

// Function to run eye surf test
// See Programmer's Guide Section 3.7 for more information on eye surf procedure
// See PMA Spec Section 3.2.33 for more information on eye surf registers
// delay_time and test_time written to two registers each, Low is least
// significant 16 bits and High is most significant 16 bits of full value
void Eye_Surf(apb_handler *apbh, char *eye_file_path, int lane,
              int delay_time = 0x0000000F, int test_time = 0x000000FF) {
  // Initialize internal variables
  int delayTimeLow = delay_time & 0x0000FFFF;
  int delayTimeHigh = delay_time >> 16;
  int testTimeLow = test_time & 0x0000FFFF;
  int testTimeHigh = test_time >> 16;
  int dataOut = 0;           // Variable to read out eye surf data from register reads
  // ADDR_A0 and ADDR_A1 are here for documentation.  They should be programmed before running eye surf via I2C.
  /* int addr_A0;            // Variable to hold address of A0 power state register
  int addr_A1;               // Variable to hold address of A1 power state register */
  int addr_gcsm1;            // Variable to hold address of RX_REE_GCSM1_CTRL register
  int addr_gcsm2;            // Variable to hold address of RX_REE_GCSM2_CTRL register
  int addr_pergcsm;          // Variable to hold address of RX_REE_PERGCSM_CTRL register
  int addr_dellow;           // Variable to hold address of low delay time register
  int addr_delhigh;          // Variable to hold address of high delay time register
  int addr_testlow;          // Variable to hold address of low test time register
  int addr_testhigh;         // Variable to hold address of high test time register
  int addr_ns;               // Variable to hold address of north-south coordinate register
  int addr_ew;               // Variable to hold address of east-west coordinate register
  int addr_eyesurf;          // Variable to hold address of eye surf control register
  int addr_errcnt;           // Variable to hold address of bit error count register
  int dataWrite;             // Variable to write values to registers
  std::fstream file;         // Declare fstream object
  int ns;                    // Variable to hold north-south coordinates
  int ew;                    // Variable to hold east-west coordinates
  int ns_write;		         // Variable to hold negative north-south coordinates
  int ew_write;		         // Variable to hold negative east-west coordinates
  int timeout_max = 10;      // 10 us
  int timeout = timeout_max; //timeout for eye surf done bit

  switch (lane) { // Translate lane input to register addresses
  case 0:
    /* addr_A0 = 0x8000;
    addr_A1 = 0x8001; */
    addr_gcsm1 = 0x8108;
    addr_gcsm2 = 0x8110;
    addr_pergcsm = 0x8118;
    addr_dellow = 0x80A4;
    addr_delhigh = 0x80A5;
    addr_testlow = 0x80A6;
    addr_testhigh = 0x80A7;
    addr_ns = 0x80A8;
    addr_ew = 0x80A9;
    addr_eyesurf = 0x80A0;
    addr_errcnt = 0x80AA;
    break;
  case 1:
    /* addr_A0 = 0x8200;
    addr_A1 = 0x8201; */
    addr_gcsm1 = 0x8308;
    addr_gcsm2 = 0x8310;
    addr_pergcsm = 0x8318;
    addr_dellow = 0x82A4;
    addr_delhigh = 0x82A5;
    addr_testlow = 0x82A6;
    addr_testhigh = 0x82A7;
    addr_ns = 0x82A8;
    addr_ew = 0x82A9;
    addr_eyesurf = 0x82A0;
    addr_errcnt = 0x82AA;
    break;
  case 2:
    /* addr_A0 = 0x8400;
    addr_A1 = 0x8401; */
    addr_gcsm1 = 0x5108;
    addr_gcsm2 = 0x8510;
    addr_pergcsm = 0x8518;
    addr_dellow = 0x84A4;
    addr_delhigh = 0x84A5;
    addr_testlow = 0x84A6;
    addr_testhigh = 0x84A7;
    addr_ns = 0x84A8;
    addr_ew = 0x84A9;
    addr_eyesurf = 0x84A0;
    addr_errcnt = 0x84AA;
    break;
  case 3:
    /* addr_A0 = 0x8600;
    addr_A1 = 0x8601; */
    addr_gcsm1 = 0x8708;
    addr_gcsm2 = 0x8710;
    addr_pergcsm = 0x8718;
    addr_dellow = 0x86A4;
    addr_delhigh = 0x86A5;
    addr_testlow = 0x86A6;
    addr_testhigh = 0x86A7;
    addr_ns = 0x86A8;
    addr_ew = 0x86A9;
    addr_eyesurf = 0x86A0;
    addr_errcnt = 0x86AA;
    break;
  case 4:
    /* addr_A0 = 0x8800;
    addr_A1 = 0x8801; */
    addr_gcsm1 = 0x8908;
    addr_gcsm2 = 0x8910;
    addr_pergcsm = 0x8918;
    addr_dellow = 0x88A4;
    addr_delhigh = 0x88A5;
    addr_testlow = 0x88A6;
    addr_testhigh = 0x88A7;
    addr_ns = 0x88A8;
    addr_ew = 0x88A9;
    addr_eyesurf = 0x88A0;
    addr_errcnt = 0x88AA;
    break;
  case 5:
    /* addr_A0 = 0x8A00;
    addr_A1 = 0x8A01; */
    addr_gcsm1 = 0x8B08;
    addr_gcsm2 = 0x8B10;
    addr_pergcsm = 0x8B18;
    addr_dellow = 0x8AA4;
    addr_delhigh = 0x8AA5;
    addr_testlow = 0x8AA6;
    addr_testhigh = 0x8AA7;
    addr_ns = 0x8AA8;
    addr_ew = 0x8AA9;
    addr_eyesurf = 0x8AA0;
    addr_errcnt = 0x8AAA;
    break;
  case 6:
    /* addr_A0 = 0x8C00;
    addr_A1 = 0x8C01; */
    addr_gcsm1 = 0x8D08;
    addr_gcsm2 = 0x8D10;
    addr_pergcsm = 0x8D18;
    addr_dellow = 0x8CA4;
    addr_delhigh = 0x8CA5;
    addr_testlow = 0x8CA6;
    addr_testhigh = 0x8CA7;
    addr_ns = 0x8CA8;
    addr_ew = 0x8CA9;
    addr_eyesurf = 0x8CA0;
    addr_errcnt = 0x8CAA;
    break;
  case 7:
    /* addr_A0 = 0x8E00;
    addr_A1 = 0x8E01; */
    addr_gcsm1 = 0x8F08;
    addr_gcsm2 = 0x8F10;
    addr_pergcsm = 0x8F18;
    addr_dellow = 0x8EA4;
    addr_delhigh = 0x8EA5;
    addr_testlow = 0x8EA6;
    addr_testhigh = 0x8EA7;
    addr_ns = 0x8EA8;
    addr_ew = 0x8EA9;
    addr_eyesurf = 0x8EA0;
    addr_errcnt = 0x8EAA;
    break;
  default: // lane 0 
    /* addr_A0 = 0x8000;
    addr_A1 = 0x8001; */
    addr_gcsm1 = 0x8108;
    addr_gcsm2 = 0x8110;
    addr_pergcsm = 0x8118;
    addr_dellow = 0x80A4;
    addr_delhigh = 0x80A5;
    addr_testlow = 0x80A6;
    addr_testhigh = 0x80A7;
    addr_ns = 0x80A8;
    addr_ew = 0x80A9;
    addr_eyesurf = 0x80A0;
    addr_errcnt = 0x80AA;
    break;
  }

  file.open(eye_file_path,
            std::ios::out | std::ios::app); // Open output file for writing

  // These four writes should be run at start of day, after PHY CDB has been
  // released from reset and
  // before PHY has been released from reset using PIPE reset
  // These should be done from side-band path via I2C.
/*   apbh->read(addr_A0, dataOut); // Read current value of register
  dataWrite = dataOut | 0x0002;  // Set enable bit high
  apbh->write(addr_A0,
              dataWrite); // Enable analog receiver E path in A0 power state
  apbh->read(addr_A1, dataOut); // Read current value of register
  dataWrite = dataOut | 0x0002;  // Set enable bit high
  apbh->write(addr_A1,
              dataWrite); // Enable analog receiver E path in A1 power state
  apbh->read(0x0049, dataOut); // Read current value of register
  dataWrite = dataOut | 0x8000; // Set input override enable bit high
  apbh->write(
      0x0049,
      dataWrite); // Write power island controller input override enable bit
  dataWrite =
      dataWrite | 0x0200; // Set power recovery request override bit high
  apbh->write(0x0049, dataWrite); // Write power recovery request override bit */

  apbh->read(addr_gcsm1, dataOut);      // Read current value of register
  dataWrite = dataOut & 0xFFFE;         // Set enable bit low
  apbh->write(addr_gcsm1, dataWrite);   // Write RX_REE_GCSM1_CTRL enable bit
  apbh->read(addr_gcsm2, dataOut);      // Read current value of register
  dataWrite = dataOut & 0xFFFE;         // Set enable bit low
  apbh->write(addr_gcsm2, dataWrite);   // Write RX_REE_GCSM2_CTRL enable bit
  apbh->read(addr_pergcsm, dataOut);    // Read current value of register
  dataWrite = dataOut & 0xFFFE;         // Set enable bit low
  apbh->write(addr_pergcsm, dataWrite); // Write RX_REE_PERGCSM_CTRL enable bit
  
  //Sleep 10ms after disabling rx equalizer
  usleep(10000);

  apbh->write(addr_dellow,
              delayTimeLow); // Set delay time, split between two registers
  apbh->write(addr_delhigh, delayTimeHigh); // default = 0x0000000F

  apbh->write(addr_testlow,
              testTimeLow); // Set test time, split between two registers
  apbh->write(addr_testhigh, testTimeHigh); // default = 0x000000FF

  // For loops used to cycle through north-south and east-west coordinates
  for (ns = 31; ns > 0; ns--) {   // This loop writes top half of plot
    ns_write = ns | 0x0100;                     // Set sign bit (bit 8 == 1 -> NORTH)
    apbh->write(addr_ns, ns_write);     // Write north-south coordinate
    for (ew = 31; ew > 0; ew--) { // This loop writes top left quarter of plot
      apbh->write(addr_ew, ew);   // Write east-west coordinate
      apbh->write(addr_eyesurf, 0x8000); // Write Ready bit
        apbh->read(addr_eyesurf, dataOut);      // Read value of done bit
      while((dataOut != 0xc000) && (timeout != 0)){ //If done bit set, or 1ms timeout
          apbh->read(addr_eyesurf, dataOut); //Read eye surf to see if done
          usleep(1);
          timeout--;
      }
      if(timeout == 0){
         printf("Timeout in Eye Surf during top left quadrant, dataOut = %x\n", dataOut);   
         return;
      }
      timeout = timeout_max;
      apbh->read(addr_errcnt, dataOut);  // Read error count at this point
      file << std::to_string(dataOut);   // Write error count to file
      file << ",";							// Add delimiter between error counts
      apbh->write(addr_eyesurf, 0x0000); // Reset Ready bit for next loop
    }
    for (ew = 0; ew < 32; ew++) { // This loop writes top right quarter of plot
            ew_write = ew | 0x0100;                 // Set sign bit
      apbh->write(addr_ew, ew_write);   // Write east-west coordinate
      apbh->write(addr_eyesurf, 0x8000); // Write Ready bit
			apbh->read(addr_eyesurf, dataOut);      // Read value of done bit
      while((dataOut != 0xc000) && (timeout != 0)){ //If done bit set, or 1ms timeout
          apbh->read(addr_eyesurf, dataOut); //Read eye surf to see if done
          usleep(1);
          timeout--;
      }
      if(timeout == 0){
         printf("Timeout in Eye Surf during top right quadrant, dataOut = %x\n", dataOut); 
         return;
      }
      timeout = timeout_max;
      apbh->read(addr_errcnt, dataOut);  // Read error count at this point
      file << std::to_string(dataOut);   // Write error count to file
      file << ",";							// Add delimiter between error counts
      apbh->write(addr_eyesurf, 0x0000); // Reset Ready bit for next loop
    }
    file << "\n";
  }
  for (ns = 0; ns < 32; ns++) { // This loop writes bottom half of plot
    apbh->write(addr_ns, ns);   // Write north-south coordinate
    for (ew = 31; ew > 0; ew--) {                // This loop writes bottom left quarter of plot
      //printf("write bottom left..\n");
      apbh->write(addr_ew, ew); // Write east-west coordinate
      apbh->write(addr_eyesurf, 0x8000); // Write Ready bit
      apbh->read(addr_eyesurf, dataOut);      // Read value of done bit
      while((dataOut != 0xc000) && (timeout != 0)){ //If done bit set, or 1ms timeout
          apbh->read(addr_eyesurf, dataOut); //Read eye surf to see if done
          usleep(1);
          timeout--;
      }
      if(timeout == 0){
         printf("Timeout in Eye Surf during bottom left quadrant, dataOut = %x\n", dataOut); 
         return;
      }
      timeout = timeout_max;
      apbh->read(addr_errcnt, dataOut);  // Read error count at this point
      file << std::to_string(dataOut);   // Write error count to file
			file << ",";							// Add delimiter between error counts
      apbh->write(addr_eyesurf, 0x0000); // Reset Ready bit for next loop
    }
    for (ew = 0; ew < 32;
         ew++) {                // This loop writes bottom right quarter of plot
         
      //printf("write bottom right..\n");
        ew_write = ew | 0x0100;                 // Set sign bit
      apbh->write(addr_ew, ew_write); // Write east-west coordinate
      apbh->write(addr_eyesurf, 0x8000); // Write Ready bit
      while((dataOut != 0xc000) && (timeout != 0)){ //If done bit set, or 1ms timeout
          apbh->read(addr_eyesurf, dataOut); //Read eye surf to see if done
          usleep(1);
          timeout--;
      }
      if(timeout == 0){
         printf("Timeout in Eye Surf during bottom right quadrant, dataOut = %x\n", dataOut); 
         return;
      }
      timeout = timeout_max;
      apbh->read(addr_errcnt, dataOut);  // Read error count at this point
      file << std::to_string(dataOut);   // Write error count to file
			file << ",";							// Add delimiter between error counts
      apbh->write(addr_eyesurf, 0x0000); // Reset Ready bit for next loop
    }
    file << "\n";
  }

  // Close output file and reset initialization registers
  file.close();

  apbh->read(addr_gcsm1, dataOut);      // Read current value of register
  dataWrite = dataOut | 0x0001;         // Set enable bit high
  apbh->write(addr_gcsm1, dataWrite);   // Write RX_REE_GCSM1_CTRL enable bit
  apbh->read(addr_gcsm2, dataOut);      // Read current value of register
  dataWrite = dataOut | 0x0001;         // Set enable bit high
  apbh->write(addr_gcsm2, dataWrite);   // Write RX_REE_GCSM2_CTRL enable bit
  apbh->read(addr_pergcsm, dataOut);    // Read current value of register
  dataWrite = dataOut | 0x0001;         // Set enable bit high
  apbh->write(addr_pergcsm, dataWrite); // Write RX_REE_PERGCSM_CTRL enable bit
  
  // If no further eye surf functions are to be run, you can enable these writes
  // This should be done via I2C outsie of this function.
  /*apbh->read(addr_A0, dataOut);					// Read current value of
  register
      dataWrite = dataOut & 0xFFFD;					// Set enable bit
  low
      apbh->write(addr_A0, dataWrite); 				// Disable analog receiver E path
  in RX_PSC_A0
      apbh->read(addr_A1, dataOut);					// Read current value of
  register
      dataWrite = dataOut & 0xFFFD;					// Set enable bit
  low
  apbh->write(addr_A1, dataWrite); 				// Disable analog
  receiver E path in RX_PSC_A1
      apbh->read(0x0049, dataOut);					// Read current value of
  register
      dataWrite = dataOut & 0xFDFF;					// Set enable bit
  low
  apbh->write(0x0049, dataWrite); 				// Switch off
  diagnostic switched power island in CMN_CDIAG_DIAG_PWRI_OVRD*/

  return;
}
