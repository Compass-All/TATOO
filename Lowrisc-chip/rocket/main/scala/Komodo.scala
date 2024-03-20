package rocket

import Chisel._
// import chisel3.RegInit
import Util._
import Chisel.ImplicitConversions._
import junctions._
import cde.{Parameters, Field}
import scala.collection.mutable.ArrayBuffer
import TinyALU._

case object KomodoMatchUnits extends Field[Int]
case object DebugKomodo extends Field[Boolean]
// case object Xlen extends Field[Int]

      
 
trait KomodoParameters {
  implicit val p: Parameters
  val numUnits = p(KomodoMatchUnits)
  val debugKomodo = p(DebugKomodo)
//   val xlen =p(Xlen)
}

trait KomodoEnums {
  val (e_SM_PC_SRC_CARE :: e_SM_PC_DST_CARE :: e_SM_INST_CARE :: e_SM_RD_CARE :: e_SM_DATA_CARE ::
    e_SM_PC_SRC_DCARE :: e_SM_PC_DST_DCARE :: e_SM_INST_DCARE :: e_SM_RD_DCARE :: e_SM_DATA_DCARE :: 
    e_SM_INSTR_TAG_CARE :: e_SM_INSTR_TAG_DCARE ::
    Nil) =
    Enum(UInt(), 12)
  val (e_C_VALID :: e_C_INVALID :: e_C_RESET :: e_C_M_COUNT :: e_C_LOCAL :: e_C_COMMIT_IDX :: e_C_INFO_SP_OFFSET :: e_C_WRITE_COUNT :: e_C_MEM_TYPE :: e_C_DONE :: Nil) =
    Enum(UInt(), 10)

  val commit_PC_SRC :: commit_PC_DST :: commit_INST :: commit_DATA :: commit_ADDR :: Nil = Enum(UInt(), 5)

  val (e_ACT_INTR :: e_ACT_MEM_RD :: e_ACT_MEM_WR :: Nil) = Enum(UInt(), 3)

}

class PHMonRoCC(opcodes: OpcodeSet)(implicit p: Parameters) extends RoCC()(p)  {
 // lazy val module = Module(new Komodo(this))
}

/*wjt
class RegFile(n: Int, w: Int, zero: Boolean = false) {
  val rf = Mem(n, UInt(width=64))
  private def access(addr: UInt) = rf(~addr(log2Up(n)-1,0))
  private val reads = ArrayBuffer[(UInt,UInt)]()
  private var canRead = true
  def read(addr: UInt) = {
    require(canRead)
    reads += addr -> Wire(UInt())
    reads.last._2 := Mux(Bool(zero) && addr === UInt(0), UInt(0), access(addr))
    reads.last._2
  }
  def write(addr: UInt, data: UInt) = {
    canRead = false
    when (addr =/= UInt(0)) {
      access(addr) := data
      for ((raddr, rdata) <- reads)
        when (addr === raddr) { rdata := data }
    }
  }
}


class Komodo1()(implicit p: Parameters) extends RoCC()(p)   {
io.mem.invalidate_lr := Bool(false)
  io.resp.valid:=Bool(false)
  //io.cmd.valid
  io.resp.bits.data:=UInt(0)
  val wait_for_resp = RegInit(init=Bool(false))
  val rq = RegInit(init=Bool(false))
  io.mem.req.bits.addr := io.cmd.bits.rs1
  io.mem.req.bits.data := io.cmd.bits.rs2
  io.mem.req.bits.cmd :=  UInt("b00000")
  io.mem.req.bits.tag := UInt(0)
  io.mem.req.bits.typ := UInt("b0011")
  //io.mem.tag_ctrl := new TagCtrlSig().fromBits(UInt(0,xLen))
  io.mem.req.bits.pc := UInt(123456) //controlUnit.act_mem_req.bits.pc 
  io.mem.req.bits.dtag := UInt(0) //controlUnit.act_mem_req.bits.dtag 
  //io.mem.tag_xcpt := Bool(false)
  //io.mem.ex_xcpt := UInt(0)
  //io.mem.tag_replay := Bool(false)
  //io.mem.s1_dtag := UInt(0)
  io.mem.invalidate_lr := Bool(false)
  //rq:=io.cmd.valid
  io.mem.req.bits.phys := Bool(true)
  val stallload = !io.mem.req.ready
  io.busy := io.cmd.valid || wait_for_resp
  //io.mem.req.bits.valid_req := rq
  io.mem.req.valid := io.cmd.valid && !stallload && !wait_for_resp
  io.autl.acquire.valid := Bool(false)
  io.autl.grant.ready := Bool(false)
   io.cmd.ready := !stallload  && !wait_for_resp
  when (io.mem.req.fire()) {
   
    wait_for_resp := Bool(true)
    printf("[MEM] Komodo memory request arrived, data: 0x%x, addr: 0x%x size %x cmd %x tag %x pc %x dtag %x phys %x\n", io.mem.req.bits.data, io.mem.req.bits.addr,io.mem.req.bits.typ,io.mem.req.bits.cmd,io.mem.req.bits.tag,io.mem.req.bits.pc,io.mem.req.bits.dtag,io.mem.req.bits.phys)
  }
   when(io.cmd.valid){
     printf("io.busy %x   %x\n",io.busy,stallload)
   }
  //rq:=Bool(false)
 // io.busy := Bool(false)
  when (io.mem.resp.valid && wait_for_resp) {
    
    wait_for_resp := Bool(false)
    io.resp.valid := Bool(true)
    //io.cmd.valid := Bool(false)
    printf("[MEM] Komodo memory response arrived, data: 0x%x\n", io.mem.resp.bits.data)
  }

}
*/
//class Komodo(outer: PHMonRoCC)(implicit p: Parameters) extends LazyRoCCModuleImp(outer) with HasCoreParameters with KomodoParameters with KomodoEnums   {
class Komodo()(implicit p: Parameters) extends RoCC()(p) with HasCoreParameters with KomodoParameters with KomodoEnums   {
  val matchUnits = Vec.tabulate(numUnits){
    (i: Int) => Module(new KomodoMatchUnit(i)(p)).io }
  val alu = Module(new TinyALU).io
  val controlUnit = Module(new ControlUnit).io
  val configUnits = Vec.tabulate(numUnits){
   (i: Int) => Module(new ActionConfigUnit(i)(p)).io }
  val activeUnit = Reg(UInt(width=log2Up(numUnits))) // The MU that its action is getting executed

  val activation_queue = Module(new Queue(new DoorbellResp, 1024))//.io
  
  val ctrl = io.cmd.valid && (io.cmd.bits.inst.funct === UInt(1))
  val enable = io.cmd.valid && (io.cmd.bits.inst.funct === UInt(3))
  val disable = io.cmd.valid && (io.cmd.bits.inst.funct === UInt(4))
  val is_reset = io.cmd.valid && (io.cmd.bits.inst.funct === UInt(2))
  val enabled = Reg(init=Bool(false))
  val resume = io.cmd.valid && (io.cmd.bits.inst.funct === UInt(15))
  val id = io.cmd.bits.rs1(31,0)
  val action = io.cmd.bits.rs1(63,32)
  val data = io.cmd.bits.rs2
  val interrupt_en = Wire(Bool())
  val busy_en = Reg(init=Bool(false))
  val intr_en = Reg(init=Bool(false))
  val mem_wait = Reg(init=Bool(false)) // A register to keep the memory request while RoCC is not ready to receive it
  val mem_req_typ = RegInit(UInt(3,width=3)) //Default: MT_D
  val wait_for_resp = RegInit(init=Bool(false)) // A debugging register to verify whether Varanus is waiting to receive the memory response from RoCC
  val wait_for_resp_after_assert = RegInit(init=Bool(false))
  val read_mask = io.cmd.valid && (io.cmd.bits.inst.funct === UInt(12))
  val read_conf = io.cmd.valid && (io.cmd.bits.inst.funct === UInt(13))
  val read_commit_index = io.cmd.valid && (io.cmd.bits.inst.funct === UInt(14))
  val threshold = RegInit(UInt(1000,width=xLen))

  io.cmd.ready := Bool(true)
  io.resp.bits.rd := io.cmd.bits.inst.rd
  io.resp.valid := Bool(false)
  io.resp.bits.data := UInt(0)
  io.commitLog.ready := Bool(true)

  controlUnit.conf_req.valid := ctrl && (action === e_C_LOCAL)
  controlUnit.conf_req.bits.index := UInt(0)
  controlUnit.conf_req.bits.data := UInt(0)
  controlUnit.act_alu_resp.valid := Bool(false)
  controlUnit.act_alu_resp.bits := UInt(0)

  (0 until numUnits).map(i => {
    matchUnits(i).cmd.bits := io.cmd.bits
    matchUnits(i).commitLog <> io.commitLog
    configUnits(i).req := Bool(false)
    configUnits(i).cu_wait := Bool(false)
    configUnits(i).skip_actions := Bool(false)
    configUnits(i).cmd.bits := io.cmd.bits
    configUnits(i).cmd.valid := io.cmd.valid & id === UInt(i)
    when (enable | disable | is_reset) {
      matchUnits(i).cmd.valid := io.cmd.valid }
    .otherwise {
      matchUnits(i).cmd.valid := io.cmd.valid & id === UInt(i) }})

  when (enable) {
    printf("helloenable\n")
    enabled := Bool(true)
  }
  .elsewhen (disable) {
    enabled := Bool(false)
  }

  when (is_reset) {
  printf("reset in komodo\n")
    mem_wait := Bool(false)
    intr_en := Bool(false)
    busy_en := Bool(false)
    io.mem.req.valid := Bool(false)
    wait_for_resp := Bool(false)
  }

  when (ctrl) {
    switch (action) {
      is (e_C_RESET)           { mem_wait := Bool(false)
        wait_for_resp := Bool(false)
        wait_for_resp_after_assert := Bool(false)}
      is (e_C_LOCAL)           { controlUnit.conf_req.bits.index := id
        controlUnit.conf_req.bits.data := data}
      is (e_C_INFO_SP_OFFSET)  { io.resp.valid := Bool(true)
        io.resp.bits.data := controlUnit.read_storage_resp(id) }
      is (e_C_MEM_TYPE)        { mem_req_typ := data(2,0) }
      is (e_C_DONE)            { io.resp.valid := Bool(true)
        io.resp.bits.data := activation_queue.io.count }
    }
  }

  activation_queue.io.enq.valid:= matchUnits.map(_.resp.doorbell.valid).reduce(_||_) //&&activation_queue.io.enq.ready
  
  activation_queue.io.enq.bits.addr:=UInt(0)  
  activation_queue.io.enq.bits.data:=UInt(0)  
  activation_queue.io.enq.bits.in1bits:=UInt(0)  
  activation_queue.io.enq.bits.in2bits:=UInt(0)  
  //activation_queue.io.enq.bits.hash:=UInt(0)  
  activation_queue.io.enq.bits.tag:=UInt(0)    
  when (matchUnits(0).resp.doorbell.valid) {
    printf("wjtvalid\n");
  }


  for (i <- 0 until numUnits) {
    when (matchUnits(i).resp.doorbell.valid && activation_queue.io.enq.ready) {
      activation_queue.io.enq.bits.addr := matchUnits(i).resp.doorbell.bits.addr
      activation_queue.io.enq.bits.data := matchUnits(i).resp.doorbell.bits.data
      activation_queue.io.enq.bits.tag := matchUnits(i).resp.doorbell.bits.tag
      activation_queue.io.enq.bits.in1bits := matchUnits(i).resp.doorbell.bits.in1bits
      activation_queue.io.enq.bits.in2bits := matchUnits(i).resp.doorbell.bits.in2bits
      //activation_queue.io.enq.bits.hash := matchUnits(i).resp.doorbell.bits.hash
      printf("[EXTRA] MU[%d] increases the counter, counter: %d\n", UInt(i), activation_queue.io.count)
    }
  }

  when (read_mask | read_commit_index) {
    io.resp.bits.data := matchUnits(id).read_cmd.bits
    io.resp.valid := Bool(true)
  }

  when (read_conf) {
    io.resp.bits.data := configUnits(id).conf_read.bits
    io.resp.valid := Bool(true)
  }

  alu.fn := UInt(9)
  alu.in1 := UInt(0)
  alu.in2 := UInt(0)

  activation_queue.io.deq.ready := controlUnit.ready
  controlUnit.is_reset := is_reset
  controlUnit.doorbell.bits.addr := activation_queue.io.deq.bits.addr
  controlUnit.doorbell.bits.data := activation_queue.io.deq.bits.data
  controlUnit.doorbell.bits.tag := activation_queue.io.deq.bits.tag
  //controlUnit.doorbell.bits.insn_type := activation_queue.io.deq.bits.insn_type
  controlUnit.doorbell.bits.in1bits := activation_queue.io.deq.bits.in1bits
  controlUnit.doorbell.bits.in2bits := activation_queue.io.deq.bits.in2bits
  //controlUnit.doorbell.bits.hash := activation_queue.io.deq.bits.hash
  controlUnit.doorbell.valid := activation_queue.io.deq.valid
  controlUnit.alu_req.valid := configUnits(activeUnit).resp.alu_req.valid
  controlUnit.alu_req.bits.fn := configUnits(activeUnit).resp.alu_req.bits.fn
  controlUnit.alu_req.bits.in1 := configUnits(activeUnit).resp.alu_req.bits.in1
  controlUnit.alu_req.bits.in2 := configUnits(activeUnit).resp.alu_req.bits.in2
  controlUnit.alu_req.bits.out := configUnits(activeUnit).resp.alu_req.bits.out
  controlUnit.alu_req.bits.data := configUnits(activeUnit).resp.alu_req.bits.data

  controlUnit.mem_req := configUnits(activeUnit).resp.mem_req
  controlUnit.act_done := configUnits(activeUnit).act_done
  configUnits(activeUnit).skip_actions := controlUnit.skip_actions

  configUnits(activeUnit).cu_wait := controlUnit.cu_wait

  when (activation_queue.io.deq.fire()) {
    printf("[smalldebug] %x %x %x %x\n",io.commitLog.valid,activation_queue.io.deq.valid,activation_queue.io.count, activation_queue.io.deq.ready)//,activation_queue.io.enq.valid)
    printf("[EXTRA] activation_queue.io dequeued MU%d data: 0x%x addr: 0x%x contorler: %d Count: %d\n", activation_queue.io.deq.bits.tag, activation_queue.io.deq.bits.data, activation_queue.io.deq.bits.addr, controlUnit.ready, activation_queue.io.count)
    activeUnit := activation_queue.io.deq.bits.tag
    configUnits(activation_queue.io.deq.bits.tag).req := Bool(true)
  }

  io.mem.req.bits.addr := controlUnit.act_mem_req.bits.addr
  io.mem.req.bits.data := controlUnit.act_mem_req.bits.data
  io.mem.req.bits.cmd := controlUnit.act_mem_req.bits.cmd
  io.mem.req.bits.tag := controlUnit.act_mem_req.bits.tag 
  io.mem.req.bits.typ := controlUnit.act_mem_req.bits.typ 
  //io.mem.tag_ctrl := new TagCtrlSig().fromBits(UInt(0,xLen))
  //io.mem.req.bits.pc := UInt(123456) //controlUnit.act_mem_req.bits.pc 
  io.mem.req.bits.dtag := UInt(0) //controlUnit.act_mem_req.bits.dtag 
  //io.mem.tag_xcpt := Bool(false)
  //io.mem.ex_xcpt := UInt(0)
  //io.mem.tag_replay := Bool(false)
  io.mem.invalidate_lr := Bool(false)
    //output io_mem_invalidate_lr
  /*
  io.mem.req.bits.phys := controlUnit.act_mem_req.bits.phys 
  io.mem.req.bits.valid_req := controlUnit.act_mem_req.bits.valid_req   
  */
//   io.mem.req.bits.phys := Bool(false)
//   io.mem.req.bits.size := log2Ceil(8).U
  io.mem.req.bits.phys := Bool(true)
  //io.mem.req.bits.valid_req := wait_for_resp_after_assert && (io.commitLog.bits.priv === UInt(0) || io.commitLog.bits.priv === UInt(1)) && (enabled)
  io.mem.req.valid := (controlUnit.act_mem_req.valid | mem_wait) && (io.commitLog.bits.priv === UInt(0) || io.commitLog.bits.priv === UInt(1)) && (enabled)
  

  when (mem_wait && io.mem.req.ready) {
    printf("[EXTRA] Komodo memory ready has arrived!; data: 0x%x, addr: 0x%x\n", io.mem.req.bits.data, io.mem.req.bits.addr)
  }

  when (controlUnit.act_mem_req.valid && (!io.mem.req.ready || (io.commitLog.bits.priv =/= UInt(0) && io.commitLog.bits.priv =/= UInt(1)) || !enabled)) {
    mem_wait := Bool(true)
    printf("[EXTRA] Komodo has to wait for memory ready; data: 0x%x, addr: 0x%x\n", io.mem.req.bits.data, io.mem.req.bits.addr)
  }

//   io.mem.req.bits.typ := mem_req_typ
//   io.mem.invalidate_lr := Bool(false)

  interrupt_en := controlUnit.interrupt_en || configUnits(activeUnit).resp.intr || io.commitLog.bits.interrupt_replay || (activation_queue.io.count === threshold)

  controlUnit.act_mem_resp.valid := io.mem.resp.valid && wait_for_resp
  controlUnit.act_mem_resp.bits := io.mem.resp.bits.data

  when (controlUnit.act_alu_req.valid) {
    alu.fn := controlUnit.act_alu_req.bits.fn
    alu.in1 := controlUnit.act_alu_req.bits.in1
    alu.in2 := controlUnit.act_alu_req.bits.in2
    printf("[KOMODO] Komodo alu request action, fn: %d, in1: 0x%x, in2: 0x%x, out: 0x%x\n", alu.fn, alu.in1, alu.in2, alu.out)
    controlUnit.act_alu_resp.valid := Bool(true)
    controlUnit.act_alu_resp.bits := alu.out
  }

  controlUnit.act_intr_done := Bool(false)
  when (resume) {
    controlUnit.act_intr_done := Bool(true)
  }
  controlUnit.act_intr := interrupt_en

  io.busy := Bool(false)
  io.interrupt := interrupt_en 
  when (io.interrupt) {
    printf("[KOMODO] Komodo: Interrupt\n")
  }

  when (io.mem.req.fire()) {
    busy_en := Bool(true)
    mem_wait := Bool(false)
    wait_for_resp := Bool(true)
    printf("[MEM] Komodo memory request arrived, data: 0x%x, addr: 0x%x size %x cmd %x tag %x pc %x dtag %x phys %x\n", io.mem.req.bits.data, io.mem.req.bits.addr,io.mem.req.bits.typ,io.mem.req.bits.cmd,io.mem.req.bits.tag,io.mem.req.bits.pc,io.mem.req.bits.dtag,io.mem.req.bits.phys)
  }
  when (io.mem.resp.valid && wait_for_resp) {
    busy_en := Bool(false)
    wait_for_resp := Bool(false)
    wait_for_resp_after_assert := Bool(false)
    printf("[MEM] Komodo memory response arrived, data: 0x%x\n", io.mem.resp.bits.data)
  }
  //when (io.mem.assertion && wait_for_resp) {
  when (wait_for_resp) {
    wait_for_resp_after_assert := Bool(true)
  }
  //io.mem.invalidate_lr := Bool(false)
  io.autl.acquire.valid := Bool(false)
  io.autl.grant.ready := Bool(false)
}
