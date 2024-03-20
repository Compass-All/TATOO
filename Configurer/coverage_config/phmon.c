#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "varanus.h"

#define MAP_SIZE ((1 << 16) - 1)
#define MAP_OFFSET (1<<16)
//#define AFL_END_CODE 0x3b7fc
#define AFL_END_CODE 0xefe7c//0x8b460
//0x817f4//nasm 0x618d0//tiffinfo 0x3c254//nmnew 0x96b9c//objdump 0xefe7c//readelf 0x8b460
//#define AFL_START_CODE 0x113d0
#define AFL_START_CODE 0x12e10//0x12380

//0x13540//nasm 0x11f70 //tiffinfo 0x118a0//nmnew 0x12880//objdump 0x12e10  //readelf 0x12380
//Local1: Shared memory base address
//Local2: prev_loc
//Local3: sp_offset

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
  mask_inst.care.instructiontag = 0x0;
  mask_inst.dont_care.instructiontag = 0xf;
  komodo_reset_val(0);
  komodo_pattern(0, &mask_inst);
  
  mask_inst2.care.pc_src    = 0x0000000000000000; // match all PC_src
  mask_inst2.dont_care.pc_src   = 0xffffffffffffffff;
  mask_inst2.care.pc_dst    = 0x0000000000000000; // match all PC_dst
  mask_inst2.dont_care.pc_dst   = 0xffffffffffffffff;
  mask_inst2.care.inst  = 0x00000067; // match JAL and JALR
  mask_inst2.dont_care.inst = 0xffffff88;
  mask_inst2.care.rd = 0x0000000000000000;
  mask_inst2.dont_care.rd = 0xffffffffffffffff;
  mask_inst2.care.data = 0x0000000000000000;
  mask_inst2.dont_care.data = 0xffffffffffffffff;
  mask_inst2.care.instructiontag = 0x0;
  mask_inst2.dont_care.instructiontag = 0xf;

  komodo_reset_val(1);
  komodo_pattern(1, &mask_inst2);
 
  //-----------------------------------------MU1----------------------------------
  //Skip actions:  afl_end_code < cur_loc (MU_DATA)
  action_mu1.op_type = e_OP_ALU; //ALU operation
  action_mu1.in1 = e_IN_CONST; //Constant
  action_mu1.in2 = e_IN_DATA_MU; //MU_DATA
  action_mu1.fn = e_ALU_SLT; //Set Less Than
  action_mu1.out = e_DONE; //Done (skip actions)
  action_mu1.data = AFL_END_CODE; //Constant Data = AFL_END_CODE
  komodo_action_config(0, &action_mu1);

  //Skip actions: cur_loc (MU_DATA) < afl_start_code
  action_mu1.op_type = e_OP_ALU; //ALU operation
  action_mu1.in1 = e_IN_DATA_MU; //MU_DATA
  action_mu1.in2 = e_IN_CONST; //Constant
  action_mu1.fn = e_ALU_SLT; //Set Less Than
  action_mu1.out = e_DONE; //Done (skip actions)
  action_mu1.data = AFL_START_CODE; //Constant Data = AFL_START_CODE
  komodo_action_config(0, &action_mu1);

  //MU_ADDR = cur_loc (MU_DATA) >> 4
  action_mu1.op_type = e_OP_ALU; //ALU operation
  action_mu1.in1 = e_IN_DATA_MU; //MU_DATA
  action_mu1.in2 = e_IN_CONST; //Constant
  action_mu1.fn = e_ALU_SR; //Shift Right
  action_mu1.out = e_OUT_ADDR; //MU_ADDR
  action_mu1.data = 4; //Constant Data = 4
  komodo_action_config(0, &action_mu1);

  //MU_DATA = cur_loc (MU_DATA) << 8
  action_mu1.op_type = e_OP_ALU; //ALU operation
  action_mu1.in1 = e_IN_DATA_MU; //MU_DATA
  action_mu1.in2 = e_IN_CONST; //Constant
  action_mu1.fn = e_ALU_SL; //Shift Left
  action_mu1.out = e_OUT_DATA; //MU_DATA
  action_mu1.data = 8; //Constant Data = 8
  komodo_action_config(0, &action_mu1);
  
  //MU_DATA = (cur_loc << 4 ^ cur_loc >> 8)
  action_mu1.op_type = e_OP_ALU; //ALU operation
  action_mu1.in1 = e_IN_DATA_MU; //MU_DATA
  action_mu1.in2 = e_IN_ADDR_MU; //MU_ADDR
  action_mu1.fn = e_ALU_XOR; //XOR
  action_mu1.out = e_OUT_DATA; //MU_DATA
  action_mu1.data = 0; //No canstant data
  komodo_action_config(0, &action_mu1);

  // MU_DATA &= MAP_SIZE
  action_mu1.op_type = e_OP_ALU; //ALU operation
  action_mu1.in1 = e_IN_DATA_MU; //MU_DATA
  action_mu1.in2 = e_IN_CONST; //Constant
  action_mu1.fn = e_ALU_AND; //AND
  action_mu1.out = e_OUT_DATA; //MU_DATA
  action_mu1.data = MAP_SIZE; //Constant Data = MAP_SIZE
  komodo_action_config(0, &action_mu1);

  // MU_ADDR = cur_loc (MU_DATA) ^ prev_loc (Local2)
  action_mu1.op_type = e_OP_ALU; //ALU operation
  action_mu1.in1 = e_IN_DATA_MU; //MU_DATA
  action_mu1.in2 = e_IN_LOC2; //Local2
  action_mu1.fn = e_ALU_XOR; //XOR
  action_mu1.out = e_OUT_ADDR; //MU_ADDR 
  action_mu1.data = 0; //No constant data
  komodo_action_config(0, &action_mu1);

  // MU_ADDR = (cur_loc ^ prev_loc) + base
  action_mu1.op_type = e_OP_ALU; //ALU operation
  action_mu1.in1 = e_IN_DATA_MU; //MU_ADDR
  action_mu1.in2 = e_IN_LOC1; //Local1
  action_mu1.fn = e_ALU_ADD; //ADD
  action_mu1.out = e_OUT_ADDR; //MU_ADDR
  action_mu1.data = 0; //No constant data
  komodo_action_config(0, &action_mu1);
  
  // prev_loc = cur_loc (MU_DATA) >> 1
  action_mu1.op_type = e_OP_ALU; //ALU operation
  action_mu1.in1 = e_IN_DATA_MU; //MU_DATA
  action_mu1.in2 = e_IN_CONST; //Constant
  action_mu1.fn = e_ALU_SR; //Shift Right
  action_mu1.out = e_OUT_LOC2; //Local2
  action_mu1.data = 1; //Constant Data = 1
  komodo_action_config(0, &action_mu1);

  // Local3 = MU_ADDR
  action_mu1.op_type = e_OP_ALU; //ALU operation
  action_mu1.in1 = e_IN_ADDR_MU; //MU_ADDR
  action_mu1.in2 = e_IN_CONST; //Constant
  action_mu1.fn = e_ALU_ADD; //ADD
  action_mu1.out = e_OUT_LOC3; //Local3
  action_mu1.data = 0; //No constant data
  komodo_action_config(0, &action_mu1);

  // Read afl_area_ptr[cir_loc ^ prev_loc]
  action_mu1.op_type = e_OP_MEM_RD; // Memory Read
  action_mu1.in1 = e_IN_DATA_MU; // MU_DATA (Do not care)
  action_mu1.in2 = e_IN_ADDR_MU; // MU_ADDR
  action_mu1.fn = e_ALU_NOP; //NOP
  action_mu1.out = e_OUT_LOC1; //Doesn't matter, it get stored in mu_resp
  action_mu1.data = 0; //No constant data
  komodo_action_config(0, &action_mu1);

  // MU_DATA = MU_RESP_DATA + 1
  action_mu1.op_type = e_OP_ALU; //ALU operation
  action_mu1.in1 = e_IN_DATA_RESP; //MU_RESP_DATA
  action_mu1.in2 = e_IN_CONST; //Constant
  action_mu1.fn = e_ALU_ADD; //ADD
  action_mu1.out = e_OUT_DATA; //MU_DATA
  action_mu1.data = 1; //Constant Data = 1
  komodo_action_config(0, &action_mu1);

  // Write MU_DATA in afl_area_ptr[cir_loc ^ prev_loc]
  action_mu1.op_type = e_OP_MEM_WR; // Memory Write
  action_mu1.in1 = e_IN_DATA_MU; // MU_DATA
  action_mu1.in2 = e_IN_ADDR_MU; // MU_ADDR
  action_mu1.fn = e_ALU_NOP; //NOP
  action_mu1.out = e_OUT_LOC1;//Doesn't matter, it get stored in mu_resp
  action_mu1.data = 0;
  komodo_action_config(0, &action_mu1);
  
  //----------------------------------------MU2------------------------------------
  //Skip actions:  afl_end_code < cur_loc (MU_DATA)
  action_mu2.op_type = e_OP_ALU; //ALU operation
  action_mu2.in1 = e_IN_CONST; //Constant
  action_mu2.in2 = e_IN_DATA_MU; //MU_DATA
  action_mu2.fn = e_ALU_SLT; //Set Less Than
  action_mu2.out = e_DONE; //Done (skip actions)
  action_mu2.data = AFL_END_CODE; //Constant Data = AFL_END_CODE
  komodo_action_config(1, &action_mu2);

  //Skip actions: cur_loc (MU_DATA) < afl_start_code
  action_mu2.op_type = e_OP_ALU; //ALU operation
  action_mu2.in1 = e_IN_DATA_MU; //MU_DATA
  action_mu2.in2 = e_IN_CONST; //Constant
  action_mu2.fn = e_ALU_SLT; //Set Less Than
  action_mu2.out = e_DONE; //Done (skip actions)
  action_mu2.data = AFL_START_CODE; //Constant Data = AFL_START_CODE
  komodo_action_config(1, &action_mu2);

  //MU_ADDR = cur_loc (MU_DATA) >> 4
  action_mu2.op_type = e_OP_ALU; //ALU operation
  action_mu2.in1 = e_IN_DATA_MU; //MU_DATA
  action_mu2.in2 = e_IN_CONST; //Constant
  action_mu2.fn = e_ALU_SR; //Shift Right
  action_mu2.out = e_OUT_ADDR; //MU_ADDR
  action_mu2.data = 4; //Constant Data = 4
  komodo_action_config(1, &action_mu2);

  //MU_DATA = cur_loc (MU_DATA) << 8
  action_mu2.op_type = e_OP_ALU; //ALU operation
  action_mu2.in1 = e_IN_DATA_MU; //MU_DATA
  action_mu2.in2 = e_IN_CONST; //Constant
  action_mu2.fn = e_ALU_SL; //Shift Left
  action_mu2.out = e_OUT_DATA; //MU_DATA
  action_mu2.data = 8; //Constant Data = 8
  komodo_action_config(1, &action_mu2);
  
  //MU_DATA = (cur_loc << 4 ^ cur_loc >> 8)
  action_mu2.op_type = e_OP_ALU; //ALU operation
  action_mu2.in1 = e_IN_DATA_MU; //MU_DATA
  action_mu2.in2 = e_IN_ADDR_MU; //MU_ADDR
  action_mu2.fn = e_ALU_XOR; //XOR
  action_mu2.out = e_OUT_DATA; //MU_DATA
  action_mu2.data = 0; //No canstant data
  komodo_action_config(1, &action_mu2);

  // MU_DATA &= MAP_SIZE
  action_mu2.op_type = e_OP_ALU; //ALU operation
  action_mu2.in1 = e_IN_DATA_MU; //MU_DATA
  action_mu2.in2 = e_IN_CONST; //Constant
  action_mu2.fn = e_ALU_AND; //AND
  action_mu2.out = e_OUT_DATA; //MU_DATA
  action_mu2.data = MAP_SIZE; //Constant Data = MAP_SIZE
  komodo_action_config(1, &action_mu2);

  // MU_ADDR = cur_loc (MU_DATA) ^ prev_loc (Local2)
  action_mu2.op_type = e_OP_ALU; //ALU operation
  action_mu2.in1 = e_IN_DATA_MU; //MU_DATA
  action_mu2.in2 = e_IN_LOC2; //Local2
  action_mu2.fn = e_ALU_XOR; //XOR
  action_mu2.out = e_OUT_ADDR; //MU_ADDR 
  action_mu2.data = 0; //No constant data
  komodo_action_config(1, &action_mu2);

  // MU_ADDR = (cur_loc ^ prev_loc) + base
  action_mu2.op_type = e_OP_ALU; //ALU operation
  action_mu2.in1 = e_IN_ADDR_MU; //MU_ADDR
  action_mu2.in2 = e_IN_LOC1; //Local1
  action_mu2.fn = e_ALU_ADD; //ADD
  action_mu2.out = e_OUT_ADDR; //MU_ADDR
  action_mu2.data = 0; //No constant data
  komodo_action_config(1, &action_mu2);
  
  // prev_loc = cur_loc (MU_DATA) >> 1
  action_mu2.op_type = e_OP_ALU; //ALU operation
  action_mu2.in1 = e_IN_DATA_MU; //MU_DATA
  action_mu2.in2 = e_IN_CONST; //Constant
  action_mu2.fn = e_ALU_SR; //Shift Right
  action_mu2.out = e_OUT_LOC2; //Local2
  action_mu2.data = 1; //Constant Data = 1
  komodo_action_config(1, &action_mu2);

  // Local3 = MU_ADDR
  action_mu2.op_type = e_OP_ALU; //ALU operation
  action_mu2.in1 = e_IN_ADDR_MU; //MU_ADDR
  action_mu2.in2 = e_IN_CONST; //Constant
  action_mu2.fn = e_ALU_ADD; //ADD
  action_mu2.out = e_OUT_LOC3; //Local3
  action_mu2.data = 0; //No constant data
  komodo_action_config(1, &action_mu2);
  
  // Read afl_area_ptr[cur_loc ^ prev_loc]
  action_mu2.op_type = e_OP_MEM_RD; // Memory Read
  action_mu2.in1 = e_IN_DATA_MU; // MU_DATA (Do not care)
  action_mu2.in2 = e_IN_ADDR_MU; // MU_ADDR
  action_mu2.fn = e_ALU_NOP; //NOP
  action_mu2.out = e_OUT_LOC1;//Doesn't matter, it get stored in mu_resp
  action_mu2.data = 0;
  komodo_action_config(1, &action_mu2);

  // MU_DATA = MU_RESP_DATA + 1
  action_mu2.op_type = e_OP_ALU; //ALU operation
  action_mu2.in1 = e_IN_DATA_RESP; //MU_RESP_DATA
  action_mu2.in2 = e_IN_CONST; //Constant
  action_mu2.fn = e_ALU_ADD; //ADD
  action_mu2.out = e_OUT_DATA; //MU_DATA
  action_mu2.data = 1; //Constant Data = 1
  komodo_action_config(1, &action_mu2);
  
  // Write MU_DATA in afl_area_ptr[cir_loc ^ prev_loc]
  action_mu2.op_type = e_OP_MEM_WR; // Memory Write
  action_mu2.in1 = e_IN_DATA_MU; // MU_DATA
  action_mu2.in2 = e_IN_ADDR_MU; // MU_ADDR
  action_mu2.fn = e_ALU_NOP; //NOP
  action_mu2.out = e_OUT_LOC1;//Doesn't matter, it get stored in mu_resp
  action_mu2.data = 0;
  komodo_action_config(1, &action_mu2);
  
  xlen_t match_count = 0;
  xlen_t match_count1 = 0;

  // Set match conditions
  komodo_match_count(0, 1, &match_count);
  komodo_match_count(1, 1, &match_count1);

  komodo_set_commit_index(0, 0); // PC_SRC
  komodo_set_commit_index(1, 0); // PC_SRC

  // Set memory type
  komodo_set_mem_typ(0);


} 
