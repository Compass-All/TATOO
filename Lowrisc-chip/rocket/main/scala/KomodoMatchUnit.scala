package rocket

import Chisel._
import Chisel.ImplicitConversions._
import Util._
import junctions._
import cde.{Parameters, Field}


class KomodoMatchUnitReq(implicit val p: Parameters)
    extends ParameterizedBundle()(p) with HasCoreParameters {
  val inst = new RoCCInstruction
  val rs1 = UInt(width = xLen)
  val rs2 = UInt(width = xLen)
}

class DoorbellResp(implicit val p: Parameters)
    extends ParameterizedBundle()(p) with KomodoParameters with HasCoreParameters {
  val addr = UInt(width = xLen)
  val data = UInt(width = xLen)
  val in1bits = UInt(width = xLen)
  val in2bits = UInt(width = xLen)
  //val hash = UInt(width = xLen)
  val tag   = UInt(width = log2Up(numUnits))
  //val insn_type = UInt(width = 1) // RVC = 1; RV = 0
  
}

class KomodoMatchUnitResp(implicit val p: Parameters)
    extends ParameterizedBundle()(p) with HasCoreParameters {
  val doorbell = Decoupled(new DoorbellResp)
}

class KomodoMatchUnitInterface(implicit val p: Parameters)
    extends ParameterizedBundle()(p) with HasCoreParameters {
  val cmd = Valid(new KomodoMatchUnitReq).flip
  val commitLog = Valid(new CommitLog).flip
  val resp = new KomodoMatchUnitResp
  val read_cmd = Valid(UInt(width=xLen))
}

class Comparator(implicit val p: Parameters)
    extends ParameterizedBundle()(p) with HasCoreParameters {
  val maskCare = new CommitLog
  val maskDontCare = new CommitLog
  val count = UInt(width = xLen)
  val countMatch = UInt(width = xLen)
  val commitIndex = UInt(width=log2Up(5))
}

class KomodoMatchUnit(id: Int)(implicit val p: Parameters) extends Module
    with KomodoParameters with KomodoEnums with HasCoreParameters{
  val io = new KomodoMatchUnitInterface

  val comp = Reg(Valid(new Comparator))

  val set_mask = io.cmd.valid && (io.cmd.bits.inst.funct === UInt(0))
  val read_mask = io.cmd.valid && (io.cmd.bits.inst.funct === UInt(12))
  val read_commit_index = io.cmd.valid && (io.cmd.bits.inst.funct === UInt(14))
  val ctrl = io.cmd.valid && (io.cmd.bits.inst.funct === UInt(1))
  val action = io.cmd.bits.rs1(63,32)
  val enable = io.cmd.valid && (io.cmd.bits.inst.funct === UInt(3))
  val disable = io.cmd.valid && (io.cmd.bits.inst.funct === UInt(4))
  val is_reset = io.cmd.valid && (io.cmd.bits.inst.funct === UInt(2))
  val index = comp.bits.commitIndex



  def isMatch(en: Bool, x: Comparator, log: CommitLog): Bool = {
    
    en && (~(x.maskCare.toBits ^ log.toBits) | x.maskDontCare.toBits).andR }
  /*
  when(comp.valid){
  printf("log.toBits %x comp.maskCare.toBits %x comp.maskDontCare.toBits %x\n",io.commitLog.bits.toBits,comp.bits.maskCare.toBits,comp.bits.maskDontCare.toBits)
  }
  */
  
  val triggered = isMatch(comp.valid & io.commitLog.valid, comp.bits, io.commitLog.bits) & (io.commitLog.bits.priv === UInt(0))
  //printf("io.commitLog.bits.priv %d\n",io.commitLog.bits.priv)
  comp.bits.maskCare.priv        := UInt(0)
  comp.bits.maskDontCare.priv    := UInt(1)
  //comp.bits.maskCare.is_compressed := Bool(false)
  //comp.bits.maskDontCare.is_compressed := Bool(true)
  comp.bits.maskCare.interrupt_replay := Bool(false)
  comp.bits.maskDontCare.interrupt_replay := Bool(true)
  /*wjt*/
  comp.bits.maskDontCare.in1bits:=Bits("hffffffffffffffff",64)
  comp.bits.maskDontCare.in2bits:=Bits("hffffffffffffffff",64)
  //comp.bits.maskDontCare.instructiontag:=Bits("3",2)
  /*wjt*/
  val data = io.cmd.bits.rs2
  io.resp.doorbell.bits.addr:=UInt(0)  
  io.resp.doorbell.bits.data:=UInt(0)  
  io.resp.doorbell.bits.in1bits:=UInt(0)  
  io.resp.doorbell.bits.in2bits:=UInt(0)  
  //io.resp.doorbell.bits.hash:=UInt(0)  
  io.resp.doorbell.bits.tag:=UInt(0)    
  //io.resp.doorbell.bits.instructiontag:=UInt(0)  
  io.read_cmd.valid:=Bool(false)
  io.read_cmd.bits:=UInt(0) 
  when (set_mask) {
    switch (action) {
      is (e_SM_PC_SRC_CARE)    { comp.bits.maskCare.pc_src      := data }
      is (e_SM_PC_DST_CARE)    { comp.bits.maskCare.pc_dst      := data }
      is (e_SM_INST_CARE)      { comp.bits.maskCare.inst        := data }
      is (e_SM_RD_CARE)        { comp.bits.maskCare.addr        := data }
      is (e_SM_DATA_CARE)      { comp.bits.maskCare.data        := data }
      is (e_SM_PC_SRC_DCARE)   { comp.bits.maskDontCare.pc_src  := data }
      is (e_SM_PC_DST_DCARE)   { comp.bits.maskDontCare.pc_dst  := data }
      is (e_SM_INST_DCARE)     { comp.bits.maskDontCare.inst    := data }
      is (e_SM_RD_DCARE)       { comp.bits.maskDontCare.addr    := data }
      is (e_SM_DATA_DCARE)     { comp.bits.maskDontCare.data    := data }
      is (e_SM_INSTR_TAG_CARE) { comp.bits.maskCare.instructiontag := data }
      is (e_SM_INSTR_TAG_DCARE){ comp.bits.maskDontCare.instructiontag := data }
    }
  }

  when (read_mask) {
    switch (action) {
      is (e_SM_PC_SRC_CARE)    { io.read_cmd.bits := comp.bits.maskCare.pc_src }
      is (e_SM_PC_DST_CARE)    { io.read_cmd.bits := comp.bits.maskCare.pc_dst }
      is (e_SM_INST_CARE)      { io.read_cmd.bits := comp.bits.maskCare.inst }
      is (e_SM_RD_CARE)        { io.read_cmd.bits := comp.bits.maskCare.addr }
      is (e_SM_DATA_CARE)      { io.read_cmd.bits := comp.bits.maskCare.data }
      is (e_SM_PC_SRC_DCARE)   { io.read_cmd.bits := comp.bits.maskDontCare.pc_src }
      is (e_SM_PC_DST_DCARE)   { io.read_cmd.bits := comp.bits.maskDontCare.pc_dst }
      is (e_SM_INST_DCARE)     { io.read_cmd.bits := comp.bits.maskDontCare.inst }
      is (e_SM_RD_DCARE)       { io.read_cmd.bits := comp.bits.maskDontCare.addr }
      is (e_SM_DATA_DCARE)     { io.read_cmd.bits := comp.bits.maskDontCare.data }
      is (e_SM_INSTR_TAG_CARE) { io.read_cmd.bits := comp.bits.maskCare.instructiontag }
      is (e_SM_INSTR_TAG_DCARE){ io.read_cmd.bits := comp.bits.maskDontCare.instructiontag }
    }
    io.read_cmd.valid := Bool(true)
  }

  when (read_commit_index) {
    io.read_cmd.bits := comp.bits.commitIndex
    io.read_cmd.valid := Bool(true)
  }

  when (enable) {
    printf("[KOMODO] Enable MU%d mask.care.inst: 0x%x comp.valid %x\n", UInt(id), comp.bits.maskCare.inst,comp.valid)
    comp.valid := Bool(true) }
    



  when (disable) {
    printf("[KOMODO] Disable MU%d\n", UInt(id))
    comp.valid := Bool(false) }

  when (is_reset) {
    comp.bits.count := UInt(0)
  }

  when (ctrl) {
    switch (action) {
      is (e_C_VALID)       { comp.valid                     := Bool(true)  
      printf("MU ctrl valid")}
      is (e_C_INVALID)     { comp.valid                     := Bool(false) 
      printf("MU ctrl invalid")}
      is (e_C_RESET)       { comp.bits.count                := UInt(0)
                             comp.bits.countMatch           := UInt(0)
                             comp.bits.commitIndex          := UInt(0)
      }
      is (e_C_M_COUNT)     { comp.bits.countMatch           := data        }
      is (e_C_COMMIT_IDX)  { comp.bits.commitIndex          := data        }
      is (e_C_WRITE_COUNT) { comp.bits.count                := data
    }
  }}

  val countInc = comp.bits.count + UInt(1)
  val fireCountMatch = triggered & (countInc === comp.bits.countMatch)
  
  when (fireCountMatch) {
    io.resp.doorbell.bits.addr := io.commitLog.bits.pc_src
    io.resp.doorbell.bits.in1bits := io.commitLog.bits.in1bits
    io.resp.doorbell.bits.in2bits := io.commitLog.bits.in2bits
    //io.resp.doorbell.bits.hash := io.commitLog.bits.inst(31,16)^io.commitLog.bits.inst(15,0)^io.commitLog.bits.pc_dst
    
    //io.resp.doorbell.bits.insn_type := io.commitLog.bits.is_compressed.asUInt()
    printf("[KOMODOMU] in2bits: 0x%x\n", io.commitLog.bits.in2bits)
    switch (index) {
      is (commit_PC_SRC) {
        io.resp.doorbell.bits.data := io.commitLog.bits.pc_src
      }
      is (commit_PC_DST) {
        io.resp.doorbell.bits.data := io.commitLog.bits.pc_dst
      }
      is (commit_INST) {
        io.resp.doorbell.bits.data := io.commitLog.bits.inst
      }
      is (commit_DATA) {
        io.resp.doorbell.bits.data := io.commitLog.bits.data
      }
      is (commit_ADDR) {
        io.resp.doorbell.bits.data := io.commitLog.bits.addr
      }

    }
  }

  io.resp.doorbell.valid := fireCountMatch
  io.resp.doorbell.bits.tag := UInt(id)
  when (triggered) {
    comp.bits.count := Mux(fireCountMatch, UInt(0), countInc)
    when (fireCountMatch) {
      val log = io.commitLog.bits
      printf("[DEBUG] Matched comp Unit %d: %x,%x,%x,%x,%x\n",
        UInt(id), log.pc_src, log.pc_dst, log.inst, log.addr, log.data)
    }
  }

  when (reset) { comp.valid := Bool(false) 
  printf("MU reset")}
}
