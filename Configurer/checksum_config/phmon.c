#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "varanus.h"


#define DESIRED_LOC 0x10510

void configphmon() {
  mask_t mask_inst, mask_inst2;
  act_conf_table_t action_mu1, action_mu2;

  mask_inst.care.pc_src    = 0x0000000000000000; // match all PC_src
  mask_inst.dont_care.pc_src   = 0xffffffffffffffff;
  mask_inst.care.pc_dst    = 0x0000000000000000; // match all PC_dst
  mask_inst.dont_care.pc_dst   = 0xffffffffffffffff;
  mask_inst.care.inst = 0x00000063; // match Branch insts
  mask_inst.dont_care.inst = 0xffffff80;
  mask_inst.care.rd = 0x0000000000000000;
  mask_inst.dont_care.rd = 0xffffffffffffffff;
  mask_inst.care.data = 0x0000000000000000;
  mask_inst.dont_care.data = 0xffffffffffffffff;
  mask_inst.care.instructiontag = 0x1;
  mask_inst.dont_care.instructiontag = 0x0;
  komodo_reset_val(0);
  komodo_pattern(0, &mask_inst);
  

  //-----------------------------------------MU1----------------------------------
  //Skip actions:  afl_end_code < cur_loc (MU_DATA)
  action_mu1.op_type = e_OP_ALU; //ALU operation
  action_mu1.in1 = e_IN_CONST; //Constant
  action_mu1.in2 = e_IN_DATA_MU; //MU_DATA
  action_mu1.fn = e_ALU_SEQ; //Set equal
  action_mu1.out = e_DONE; //Done (skip actions)
  action_mu1.data = DESIRED_LOC; //Constant Data = AFL_END_CODE
  komodo_action_config(0, &action_mu1);

  //Skip actions: cur_loc (MU_DATA) < afl_start_code
  action_mu1.op_type = e_OP_INTR; //ALU operation
  action_mu1.in1 = e_IN_CONST; //MU_DATA
  action_mu1.in2 = e_IN_DATA_MU; //Constant
  action_mu1.fn = e_ALU_SLT; //Set Less Than
  action_mu1.out = e_OUT_INTR; //Done (skip actions)
  action_mu1.data = 0; //Constant Data = AFL_START_CODE
  komodo_action_config(0, &action_mu1);


  
  xlen_t match_count = 0;

  // Set match conditions
  komodo_match_count(0, 1, &match_count);

  komodo_set_commit_index(0, 1); // PC_DEST

  // Set memory type
  komodo_set_mem_typ(0);


} 
