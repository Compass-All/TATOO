// See LICENSE for license details.

package rocket

import Chisel._
import Util._
import Instructions._
import junctions._
import cde.{Parameters, Field}
import uncore._
import scala.math._
import junctions.AddrHashMap

class MStatus extends Bundle {
  val prv = UInt(width = PRV.SZ) // not truly part of mstatus, but convenient
  val sd = Bool()
  val zero3 = UInt(width = 31)
  val sd_rv32 = Bool()
  val zero2 = UInt(width = 2)
  val vm = UInt(width = 5)
  val zero1 = UInt(width = 5)
  val pum = Bool()
  val mprv = Bool()
  val xs = UInt(width = 2)
  val fs = UInt(width = 2)
  val mpp = UInt(width = 2)
  val hpp = UInt(width = 2)
  val spp = UInt(width = 1)
  val mpie = Bool()
  val hpie = Bool()
  val spie = Bool()
  val upie = Bool()
  val mie = Bool()
  val hie = Bool()
  val sie = Bool()
  val uie = Bool()
}

class MIP extends Bundle {
  val irq  = Bool()
  val rocc = Bool()
  val meip = Bool()
  val heip = Bool()
  val seip = Bool()
  val ueip = Bool()
  val mtip = Bool()
  val htip = Bool()
  val stip = Bool()
  val utip = Bool()
  val msip = Bool()
  val hsip = Bool()
  val ssip = Bool()
  val usip = Bool()
}

object PRV
{
  val SZ = 2
  val U = 0
  val S = 1
  val H = 2
  val M = 3
}

object CSR
{
  // commands
  val SZ = 3
  val X = BitPat.DC(SZ)
  val N = UInt(0,SZ)
  val W = UInt(1,SZ)
  val S = UInt(2,SZ)
  val C = UInt(3,SZ)
  val I = UInt(4,SZ)
  val R = UInt(5,SZ)

  val ADDRSZ = 12
}

class TagCtrlSig(implicit p: Parameters) extends CoreBundle {
  val maskFetchChck           = Bits(width = tgInstBits)
  val maskJmpProp             = Bits(width = tgBits)
  val maskJmpChck             = Bits(width = tgBits)
  val maskCFlowIndirBranchTgt = Bits(width = tgInstBits)
  val maskCFlowDirBranchTgt   = Bits(width = tgInstBits)
  val maskStoreKeep           = Bits(width = tgBits)
  val maskStoreProp           = Bits(width = tgBits)
  val maskStoreChck           = Bits(width = tgBits)
  val maskLoadProp            = Bits(width = tgBits)
  val maskLoadChck            = Bits(width = tgBits)
  val maskALUProp             = Bits(width = tgBits)
  val maskALUChck             = Bits(width = tgBits)
}

class CSRFileIO(implicit p: Parameters) extends CoreBundle {
  val prci = new PRCITileIO().flip
  val rw = new Bundle {
    val addr = UInt(INPUT, CSR.ADDRSZ)
    val cmd = Bits(INPUT, CSR.SZ)
    val rdata = Bits(OUTPUT, xLen)
    val rtag  = Bits(OUTPUT, tgBits)
    val wdata = Bits(INPUT, xLen)
    val wtag  = Bits(INPUT, tgBits)
  }

  val csr_stall = Bool(OUTPUT)
  val csr_xcpt = Bool(OUTPUT)
  val eret = Bool(OUTPUT)

  val prv = UInt(OUTPUT, PRV.SZ)
  val status = new MStatus().asOutput
  val ptbr = UInt(OUTPUT, paddrBits)
  val evec = UInt(OUTPUT, vaddrBitsExtended)
  val evec_tag = UInt(OUTPUT, tgBits)
  val exception = Bool(INPUT)
  val retire = UInt(INPUT, log2Up(1+retireWidth))
  val uarch_counters = Vec(16, UInt(INPUT, log2Up(1+retireWidth)))
  val custom_mrw_csrs = Vec(nCustomMrwCsrs, UInt(INPUT, xLen))
  val cause = UInt(INPUT, xLen)
  val pc = UInt(INPUT, vaddrBitsExtended)
  val pc_tag = UInt(INPUT, tgBits)
  val fatc = Bool(OUTPUT)
  val time = UInt(OUTPUT, xLen)
  val fcsr_rm = Bits(OUTPUT, FPConstants.RM_SZ)
  val fcsr_flags = Valid(Bits(width = FPConstants.FLAGS_SZ)).flip
  val rocc = new RoCCInterface().flip
  val interrupt = Bool(OUTPUT)
  val interrupt_cause = UInt(OUTPUT, xLen)
  val irq = Bool(INPUT)

  val tag_ctrl = new TagCtrlSig().asOutput
}

class CSRFile(id:Int)(implicit p: Parameters) extends CoreModule()(p)
{
  val io = new CSRFileIO

  val reset_mstatus = Wire(init=new MStatus().fromBits(0))
  reset_mstatus.mpp := PRV.M
  reset_mstatus.prv := PRV.M
  val reg_mstatus = Reg(init=reset_mstatus)

  val (supported_interrupts, delegable_interrupts) = {
    val sup = Wire(init=new MIP().fromBits(0))
    sup.ssip := Bool(p(UseVM))
    sup.msip := true
    sup.stip := Bool(p(UseVM))
    sup.mtip := true
    sup.meip := true
    sup.seip := Bool(p(UseVM))
    sup.rocc := usingRoCC
    sup.irq  := true

    val del = Wire(init=sup)
    del.msip := false
    del.mtip := false
    del.meip := false

    (sup.toBits, del.toBits)
  }
  val delegable_exceptions = UInt(Seq(
    Causes.misaligned_fetch,
    Causes.fault_fetch,
    Causes.breakpoint,
    Causes.fault_load,
    Causes.fault_store,
    Causes.user_ecall,
    Causes.tag_check_failure).map(1 << _).sum)

  val reg_mie = Reg(init=UInt(0, xLen))
  val reg_mideleg = Reg(init=UInt(0, xLen))
  val reg_medeleg = Reg(init=UInt(0, xLen))
  val reg_mip = Reg(new MIP)
  val reg_mepc = Reg(UInt(width = vaddrBitsExtended))
  val reg_mepc_tag = Reg(init=UInt(0, tgBits))
  val reg_mcause = Reg(Bits(width = xLen))
  val reg_mbadaddr = Reg(UInt(width = vaddrBitsExtended))
  val reg_mscratch = Reg(Bits(width = xLen))
  val reg_mscratch_tag = Reg(Bits(width = tgBits))
  val reg_mtvec = Reg(init=UInt(p(MtvecInit), paddrBits min xLen))
  val reg_mtvec_tag = Reg(init=UInt(0, tgBits))
  val reg_mucounteren = Reg(init=UInt(0, 32))
  val reg_mscounteren = Reg(UInt(0, 32))

  val reg_sepc = Reg(UInt(width = vaddrBitsExtended))
  val reg_sepc_tag = Reg(init=UInt(0, tgBits))
  val reg_scause = Reg(Bits(width = xLen))
  val reg_sbadaddr = Reg(UInt(width = vaddrBitsExtended))
  val reg_sscratch = Reg(Bits(width = xLen))
  val reg_sscratch_tag = Reg(Bits(width = tgBits))
  val reg_stvec = Reg(UInt(width = vaddrBits))
  val reg_stvec_tag = Reg(init=UInt(0, tgBits))
  val reg_sptbr = Reg(UInt(width = ppnBits))
  val reg_wfi = Reg(init=Bool(false))

  val reg_uarch_counters = io.uarch_counters.map(WideCounter(xLen, _))
  val reg_fflags = Reg(UInt(width = 5))
  val reg_frm = Reg(UInt(width = 3))

  val reg_instret = WideCounter(64, io.retire)
  val reg_cycle = if (enableCommitLog) reg_instret else WideCounter(64)

  val reg_tagctrl = Reg(init=UInt(0, xLen))
  val reg_mutagctrlen = Reg(init = ~UInt(0, xLen))
  val reg_mstagctrlen = Reg(init = ~UInt(0, xLen))

  val mip = Wire(init=reg_mip)
  mip.irq := io.irq
  mip.rocc := io.rocc.interrupt
  val read_mip = mip.toBits & supported_interrupts

  val pending_interrupts = read_mip & reg_mie
  val m_interrupts = Mux(reg_mstatus.prv < PRV.M || (reg_mstatus.prv === PRV.M && reg_mstatus.mie), pending_interrupts & ~reg_mideleg, UInt(0))
  val s_interrupts = Mux(reg_mstatus.prv < PRV.S || (reg_mstatus.prv === PRV.S && reg_mstatus.sie), pending_interrupts & reg_mideleg, UInt(0))
  val all_interrupts = m_interrupts | s_interrupts
  io.interrupt := all_interrupts.orR
  io.interrupt_cause := (io.interrupt << (xLen-1)) + PriorityEncoder(all_interrupts)

  val system_insn = io.rw.cmd === CSR.I
  val cpu_ren = io.rw.cmd =/= CSR.N && !system_insn

  val isa_string = "IMA" +
    (if (usingVM) "S" else "") +
    (if (usingFPU) "FD" else "") +
    (if (usingRoCC) "X" else "")
  val isa = ((if (xLen == 32) BigInt(0) else BigInt(2)) << (xLen-2)) |
    isa_string.map(x => 1 << (x - 'A')).reduce(_|_)
  val read_mstatus = io.status.toBits()(xLen-1,0)

  val read_mapping = collection.mutable.LinkedHashMap[Int,(Bits, Bits)](
    CSRs.mimpid ->          (UInt(2),      UInt(0)           ),          // open-source but not UCB repos
    CSRs.marchid ->         (UInt(0),      UInt(0)           ),
    CSRs.mvendorid ->       (UInt(0),      UInt(0)           ),
    CSRs.mcycle ->          (reg_cycle,    UInt(0)           ),
    CSRs.minstret ->        (reg_instret,  UInt(0)           ),
    CSRs.mucounteren ->     (UInt(0),      UInt(0)           ),
    CSRs.mutime_delta ->    (UInt(0),      UInt(0)           ),
    CSRs.mucycle_delta ->   (UInt(0),      UInt(0)           ),
    CSRs.muinstret_delta -> (UInt(0),      UInt(0)           ),
    CSRs.misa ->            (UInt(isa),    UInt(0)           ),
    CSRs.mstatus ->         (read_mstatus, UInt(0)           ),
    CSRs.mtvec ->           (reg_mtvec,    reg_mtvec_tag     ),
    CSRs.mip ->             (read_mip,     UInt(0)           ),
    CSRs.mie ->             (reg_mie,      UInt(0)           ),
    CSRs.mideleg ->         (reg_mideleg,  UInt(0)           ),
    CSRs.medeleg ->         (reg_medeleg,  UInt(0)           ),
    CSRs.mscratch ->        (reg_mscratch, reg_mscratch_tag  ),
    CSRs.mepc ->            (reg_mepc.sextTo(xLen),
                                           reg_mepc_tag      ),
    CSRs.mbadaddr ->        (reg_mbadaddr.sextTo(xLen),
                                           UInt(0)           ),
    CSRs.mcause ->          (reg_mcause,   UInt(0)           ),
    CSRs.mhartid ->         (UInt(id),     UInt(0)           ),
    CSRs.swtrace ->         (UInt(0),      UInt(0)           ))

  if (usingFPU) {
    read_mapping += CSRs.fflags ->    (reg_fflags,                  UInt(0))
    read_mapping += CSRs.frm ->       (reg_frm,                     UInt(0))
    read_mapping += CSRs.fcsr ->      (Cat(reg_frm, reg_fflags),    UInt(0))
  }

  if (usingVM) {
    val read_sie = reg_mie & reg_mideleg
    val read_sip = read_mip & reg_mideleg
    val read_sstatus = Wire(init=io.status)
    read_sstatus.vm := 0
    read_sstatus.mprv := 0
    read_sstatus.mpp := 0
    read_sstatus.hpp := 0
    read_sstatus.mpie := 0
    read_sstatus.hpie := 0
    read_sstatus.mie := 0
    read_sstatus.hie := 0

    read_mapping += CSRs.sstatus ->   ((read_sstatus.toBits())(xLen-1,0),
                                                                    UInt(0)           )
    read_mapping += CSRs.sip ->       (read_sip.toBits,             UInt(0)           )
    read_mapping += CSRs.sie ->       (read_sie.toBits,             UInt(0)           )
    read_mapping += CSRs.sscratch ->  (reg_sscratch,                reg_sscratch_tag  )
    read_mapping += CSRs.scause ->    (reg_scause,                  UInt(0)           )
    read_mapping += CSRs.sbadaddr ->  (reg_sbadaddr.sextTo(xLen),   UInt(0)           )
    read_mapping += CSRs.sptbr ->     (reg_sptbr,                   UInt(0)           )
    read_mapping += CSRs.sasid ->     (UInt(0),                     UInt(0)           )
    read_mapping += CSRs.sepc ->      (reg_sepc.sextTo(xLen),       reg_sepc_tag      )
    read_mapping += CSRs.stvec ->     (reg_stvec.sextTo(xLen),      reg_stvec_tag     )
    read_mapping += CSRs.mscounteren -> (reg_mscounteren,           UInt(0)           )
    read_mapping += CSRs.mstime_delta -> (UInt(0),                  UInt(0)           )
    read_mapping += CSRs.mscycle_delta -> (UInt(0),                 UInt(0)           )
    read_mapping += CSRs.msinstret_delta -> (UInt(0),               UInt(0)           )
    read_mapping += CSRs.cycle ->     (reg_cycle,                   UInt(0)           )
    read_mapping += CSRs.instret ->   (reg_instret,                 UInt(0)           )
  }

  if (usingVM) {  // should be usingUser
    read_mapping += CSRs.cycle ->     (reg_cycle,                   UInt(0)           )
    read_mapping += CSRs.time ->      (reg_cycle,                   UInt(0)           )   // should be a memory mapped register mtime
    read_mapping += CSRs.instret ->   (reg_instret,                 UInt(0)           )
  }

  if (useTagMem) {
    read_mapping += CSRs.utagctrl ->  (reg_tagctrl,                 UInt(0)           )
    read_mapping += CSRs.stagctrl ->  (reg_tagctrl,                 UInt(0)           )
    read_mapping += CSRs.mtagctrl ->  (reg_tagctrl,                 UInt(0)           )
    read_mapping += CSRs.mutagctrlen -> (reg_mutagctrlen,           UInt(0)           )
    read_mapping += CSRs.mstagctrlen -> (reg_mstagctrlen,           UInt(0)           )
  }

  if (xLen == 32) {
    read_mapping += CSRs.mcycleh ->   ((reg_cycle >> 32),           UInt(0)           )
    read_mapping += CSRs.minstreth -> ((reg_instret >> 32),         UInt(0)           )
    read_mapping += CSRs.mutime_deltah -> (UInt(0),                 UInt(0)           )
    read_mapping += CSRs.mucycle_deltah -> (UInt(0),                UInt(0)           )
    read_mapping += CSRs.muinstret_deltah -> (UInt(0),              UInt(0)           )
    if (usingVM) {
      read_mapping += CSRs.mstime_deltah -> (UInt(0),               UInt(0)           )
      read_mapping += CSRs.mscycle_deltah -> (UInt(0),              UInt(0)           )
      read_mapping += CSRs.msinstret_deltah -> (UInt(0),            UInt(0)           )
    }
  }

  for (i <- 0 until nCustomMrwCsrs) {
    val addr = 0xff0 + i
    require(addr < (1 << CSR.ADDRSZ))
    require(!read_mapping.contains(addr), "custom MRW CSR address " + i + " is already in use")
    read_mapping += addr ->           (io.custom_mrw_csrs(i),       UInt(0)           )
  }

  for ((addr, i) <- roccCsrs.zipWithIndex) {
    require(!read_mapping.contains(addr), "RoCC: CSR address " + addr + " is already in use")
    read_mapping += addr ->           (io.rocc.csr.rdata(i),        UInt(0)           )
  }

  val decoded_addr = read_mapping map { case (k, (v, _)) => k -> (io.rw.addr === k) }

  val addr_valid = decoded_addr.values.reduce(_||_)
  val fp_csr =
    if (usingFPU) decoded_addr(CSRs.fflags) || decoded_addr(CSRs.frm) || decoded_addr(CSRs.fcsr)
    else Bool(false)
  val hpm_csr = if (usingVM) io.rw.addr >= CSRs.cycle && io.rw.addr < CSRs.cycle + 3 else Bool(false)
  val hpm_en = reg_mstatus.prv === PRV.M ||
    (reg_mstatus.prv === PRV.S && reg_mscounteren(io.rw.addr(7, 0))) ||
    (reg_mstatus.prv === PRV.U && reg_mucounteren(io.rw.addr(7, 0)))
  val csr_addr_priv = io.rw.addr(9,8)
  val priv_sufficient = reg_mstatus.prv >= csr_addr_priv
  val read_only = io.rw.addr(11,10).andR
  val cpu_wen = cpu_ren && io.rw.cmd =/= CSR.R && priv_sufficient
  val wen = cpu_wen && !read_only
  val wdata = Mux(io.rw.cmd === CSR.S, io.rw.rdata | io.rw.wdata,
              Mux(io.rw.cmd === CSR.C, io.rw.rdata & ~io.rw.wdata,
              io.rw.wdata))
  val wtag  = io.rw.wtag

  val do_system_insn = priv_sufficient && system_insn
  val opcode = UInt(1) << io.rw.addr(2,0)
  val insn_call = do_system_insn && opcode(0)
  val insn_break = do_system_insn && opcode(1)
  val insn_ret = do_system_insn && opcode(2)
  val insn_sfence_vm = do_system_insn && opcode(4)
  val insn_wfi = do_system_insn && opcode(5)

  val csr_xcpt = (cpu_wen && read_only) ||
    (cpu_ren && (!priv_sufficient || !addr_valid || (hpm_csr && !hpm_en) || (fp_csr && !io.status.fs.orR))) |
    (system_insn && !priv_sufficient) ||
    insn_call || insn_break

  when (insn_wfi) { reg_wfi := true }
  when (read_mip.orR) { reg_wfi := false }

  val cause =
    Mux(!csr_xcpt, io.cause,
    Mux(insn_call, reg_mstatus.prv + Causes.user_ecall,
    Mux[UInt](insn_break, Causes.breakpoint, Causes.illegal_instruction)))
  val cause_lsbs = cause(log2Up(xLen)-1,0)
  val delegate = Bool(p(UseVM)) && reg_mstatus.prv < PRV.M && Mux(cause(xLen-1), reg_mideleg(cause_lsbs), reg_medeleg(cause_lsbs))
  val tvec = Mux(delegate, reg_stvec.sextTo(vaddrBitsExtended), reg_mtvec)
  val tvec_tag = Mux(delegate, reg_stvec_tag, reg_mtvec_tag)
  val epc = Mux(Bool(p(UseVM)) && !csr_addr_priv(1), reg_sepc, reg_mepc)
  val epc_tag = Mux(Bool(p(UseVM)) && !csr_addr_priv(1), reg_sepc_tag, reg_mepc_tag)
  io.fatc := insn_sfence_vm
  io.evec := Mux(io.exception || csr_xcpt, tvec, epc)
  io.evec_tag := Mux(io.exception || csr_xcpt, tvec_tag, epc_tag)
  io.ptbr := reg_sptbr
  io.csr_xcpt := csr_xcpt
  io.eret := insn_ret
  io.status := reg_mstatus
  io.status.sd := io.status.fs.andR || io.status.xs.andR
  if (xLen == 32)
    io.status.sd_rv32 := io.status.sd

  when (io.exception || csr_xcpt) {
    def compressVAddr(addr: UInt) =
      if (vaddrBitsExtended == vaddrBits) addr
      else {
        val (upper, lower) = Split(addr, vaddrBits)
        val sign = Mux(lower.toSInt < SInt(0), upper.andR, upper.orR)
        Cat(sign, lower)
      }
    val ldst =
      cause === Causes.fault_load || cause === Causes.misaligned_load ||
      cause === Causes.fault_store || cause === Causes.misaligned_store
    val badaddr = Mux(ldst, compressVAddr(io.rw.wdata), io.pc)
    val epc = ~(~io.pc | (coreInstBytes-1))
    val epc_tag = io.pc_tag
    val pie = read_mstatus(reg_mstatus.prv)

    when (delegate) {
      reg_sepc := epc
      reg_sepc_tag := epc_tag
      reg_scause := cause
      reg_sbadaddr := badaddr
      reg_mstatus.spie := pie
      reg_mstatus.spp := reg_mstatus.prv
      reg_mstatus.sie := false
      reg_mstatus.prv := PRV.S
    }.otherwise {
      reg_mepc := epc
      reg_mepc_tag := epc_tag
      reg_mcause := cause
      reg_mbadaddr := badaddr
      reg_mstatus.mpie := pie
      reg_mstatus.mpp := reg_mstatus.prv
      reg_mstatus.mie := false
      reg_mstatus.prv := PRV.M
    }
  }
  
  when (insn_ret) {
    when (Bool(p(UseVM)) && !csr_addr_priv(1)) {
      when (reg_mstatus.spp.toBool) { reg_mstatus.sie := reg_mstatus.spie }
      reg_mstatus.spie := false
      reg_mstatus.spp := PRV.U
      reg_mstatus.prv := reg_mstatus.spp
    }.otherwise {
      when (reg_mstatus.mpp(1)) { reg_mstatus.mie := reg_mstatus.mpie }
      when (reg_mstatus.mpp(0)) { reg_mstatus.sie := reg_mstatus.mpie }
      reg_mstatus.mpie := false
      reg_mstatus.mpp := PRV.U
      reg_mstatus.prv := reg_mstatus.mpp
    }
  }

  assert(PopCount(insn_ret :: io.exception :: csr_xcpt :: Nil) <= 1, "these conditions must be mutually exclusive")

  io.time := reg_cycle
  io.csr_stall := reg_wfi

  io.rw.rdata := Mux1H(for ((k, (v, _)) <- read_mapping) yield decoded_addr(k) -> v)
  io.rw.rtag  := Mux1H(for ((k, (_, v)) <- read_mapping) yield decoded_addr(k) -> v)

  io.fcsr_rm := reg_frm
  when (io.fcsr_flags.valid) {
    reg_fflags := reg_fflags | io.fcsr_flags.bits
  }

  when (wen) {
    when (decoded_addr(CSRs.mstatus)) {
      val new_mstatus = new MStatus().fromBits(wdata)
      reg_mstatus.mie := new_mstatus.mie
      reg_mstatus.mpie := new_mstatus.mpie

      val supportedModes = Vec((PRV.M :: PRV.U :: (if (usingVM) List(PRV.S) else Nil)).map(UInt(_)))
      if (supportedModes.size > 1) {
        reg_mstatus.mprv := new_mstatus.mprv
        when (supportedModes contains new_mstatus.mpp) { reg_mstatus.mpp := new_mstatus.mpp }
        if (supportedModes.size > 2) {
          //reg_mstatus.mxr := new_mstatus.mxr
          reg_mstatus.pum := new_mstatus.pum
          reg_mstatus.spp := new_mstatus.spp
          reg_mstatus.spie := new_mstatus.spie
          reg_mstatus.sie := new_mstatus.sie
        }
      }

      if (usingVM) {
        require(if (xLen == 32) pgLevels == 2 else pgLevels > 2 && pgLevels < 6)
        val vm_on = 6 + pgLevels // TODO Sv48 support should imply Sv39 support
        when (new_mstatus.vm === 0) { reg_mstatus.vm := 0 }
        when (new_mstatus.vm === vm_on) { reg_mstatus.vm := vm_on }
      }
      if (usingVM || usingFPU) reg_mstatus.fs := Fill(2, new_mstatus.fs.orR)
      if (usingRoCC) reg_mstatus.xs := Fill(2, new_mstatus.xs.orR)
    }
    when (decoded_addr(CSRs.mip)) {
      val new_mip = new MIP().fromBits(wdata)
      if (usingVM) {
        reg_mip.ssip := new_mip.ssip
        reg_mip.stip := new_mip.stip
      }
    }
    when (decoded_addr(CSRs.mie))      { reg_mie := wdata & supported_interrupts }
    when (decoded_addr(CSRs.mepc))     { reg_mepc := ~(~wdata | (coreInstBytes-1)); reg_mepc_tag := wtag }
    when (decoded_addr(CSRs.mscratch)) { reg_mscratch := wdata; reg_mscratch_tag := wtag }
    if (p(MtvecWritable))
      when (decoded_addr(CSRs.mtvec))  { reg_mtvec := wdata >> 2 << 2; reg_mtvec_tag := wtag }
    when (decoded_addr(CSRs.mcause))   { reg_mcause := wdata & UInt((BigInt(1) << (xLen-1)) + 31) /* only implement 5 LSBs and MSB */ }
    when (decoded_addr(CSRs.mbadaddr)) { reg_mbadaddr := wdata(vaddrBitsExtended-1,0) }
    writeCounter(CSRs.mcycle, reg_cycle, wdata)
    writeCounter(CSRs.minstret, reg_instret, wdata)
    if (usingFPU) {
      when (decoded_addr(CSRs.fflags)) { reg_fflags := wdata }
      when (decoded_addr(CSRs.frm))    { reg_frm := wdata }
      when (decoded_addr(CSRs.fcsr))   { reg_fflags := wdata; reg_frm := wdata >> reg_fflags.getWidth }
    }
    if (usingVM) {
      when (decoded_addr(CSRs.sstatus)) {
        val new_sstatus = new MStatus().fromBits(wdata)
        reg_mstatus.sie := new_sstatus.sie
        reg_mstatus.spie := new_sstatus.spie
        reg_mstatus.spp := new_sstatus.spp
        reg_mstatus.pum := new_sstatus.pum
        reg_mstatus.fs := Fill(2, new_sstatus.fs.orR) // even without an FPU
        if (usingRoCC) reg_mstatus.xs := Fill(2, new_sstatus.xs.orR)
      }
      when (decoded_addr(CSRs.sip)) {
        val new_sip = new MIP().fromBits(wdata)
        reg_mip.ssip := new_sip.ssip
      }
      when (decoded_addr(CSRs.sie))      { reg_mie := (reg_mie & ~reg_mideleg) | (wdata & reg_mideleg) }
      when (decoded_addr(CSRs.sscratch)) { reg_sscratch := wdata; reg_sscratch_tag := wtag }
      when (decoded_addr(CSRs.sptbr))    { reg_sptbr := wdata }
      when (decoded_addr(CSRs.sepc))     { reg_sepc := wdata >> log2Up(coreInstBytes) << log2Up(coreInstBytes); reg_sepc_tag := wtag }
      when (decoded_addr(CSRs.stvec))    { reg_stvec := wdata >> 2 << 2; reg_stvec_tag := wtag }
      when (decoded_addr(CSRs.scause))   { reg_scause := wdata & UInt((BigInt(1) << (xLen-1)) + 31) /* only implement 5 LSBs and MSB */ }
      when (decoded_addr(CSRs.sbadaddr)) { reg_sbadaddr := wdata(vaddrBitsExtended-1,0) }
      when (decoded_addr(CSRs.mideleg))  { reg_mideleg := wdata & delegable_interrupts }
      when (decoded_addr(CSRs.medeleg))  { reg_medeleg := wdata & delegable_exceptions }
      when (decoded_addr(CSRs.mscounteren)) { reg_mscounteren := wdata & 7 }
    }
    if (usingVM) {
      when (decoded_addr(CSRs.mucounteren)) { reg_mucounteren := wdata & 7 }
    }
    if (useTagMem) {
      when (decoded_addr(CSRs.utagctrl))    { reg_tagctrl := (wdata & reg_mutagctrlen) | (reg_tagctrl & ~reg_mutagctrlen) }
      when (decoded_addr(CSRs.stagctrl))    { reg_tagctrl := (wdata & reg_mstagctrlen) | (reg_tagctrl & ~reg_mstagctrlen) }
      when (decoded_addr(CSRs.mtagctrl))    { reg_tagctrl := wdata }
      when (decoded_addr(CSRs.mutagctrlen)) { reg_mutagctrlen := wdata }
      when (decoded_addr(CSRs.mstagctrlen)) { reg_mstagctrlen := wdata }
    }
  }

  reg_mip := io.prci.interrupts

  io.rocc.csr.waddr := io.rw.addr
  io.rocc.csr.wdata := wdata
  io.rocc.csr.wen := wen

  if (useTagMem) {
    io.tag_ctrl := new TagCtrlSig().fromBits(reg_tagctrl)
  } else {
    io.tag_ctrl := new TagCtrlSig().fromBits(UInt(0,xLen))
  }

  def writeCounter(lo: Int, ctr: WideCounter, wdata: UInt) = {
    if (xLen == 32) {
      val hi = lo + CSRs.mcycleh - CSRs.mcycle
      when (decoded_addr(lo)) { ctr := Cat(ctr(63, 32), wdata) }
      when (decoded_addr(hi)) { ctr := Cat(wdata, ctr(31, 0)) }
    } else {
      when (decoded_addr(lo)) { ctr := wdata }
    }
  }
}
