#include <stdio.h>
#include <stdlib.h>
#include "varanus.h"

int main(int argc, char *argv[]) {


  mask_t mask_inst;
  act_conf_table_t action_mu1;
  // Setup an instruction mask that'll match all program counters, but
  // only the breakpoint pc
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

  komodo_reset_val(0);
  komodo_pattern(0, &mask_inst);
  
  action_mu1.op_type = e_OP_INTR; //interrupt
  action_mu1.in1 = e_IN_CONST; //Local3
  action_mu1.in2 = e_IN_LOC3; //Constant
  action_mu1.fn = e_ALU_SLT; //Set Less Than
  action_mu1.out = e_OUT_INTR; //Interrupt reg
  action_mu1.data = 0;
  komodo_action_config(0, &action_mu1);
  
  xlen_t match_count = 0;
  
  komodo_match_count(0, 1, &match_count);
  
  komodo_set_commit_index(0, 0);
  
  komodo_set_mem_typ(3);
  //komodo_enable_all(); 

  return 0;
  
}
