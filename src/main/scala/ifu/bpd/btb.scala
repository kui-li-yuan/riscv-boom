package boom.ifu

import chisel3._
import chisel3.util._

import org.chipsalliance.cde.config.{Field, Parameters}
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.tilelink._

import boom.common._
import boom.util.{BoomCoreStringPrefix}

import scala.math.min

case class BoomBTBParams(
  nSets: Int = 128,
  nWays: Int = 2,
  offsetSz: Int = 13,
  extendedNSets: Int = 128
)


class BTBBranchPredictorBank(params: BoomBTBParams = BoomBTBParams())(implicit p: Parameters) extends BranchPredictorBank()(p)
{
  override val nSets         = params.nSets
  override val nWays         = params.nWays
  val tagSz         = vaddrBitsExtended - log2Ceil(nSets) - log2Ceil(fetchWidth) - 1
  val offsetSz      = params.offsetSz
  val extendedNSets = params.extendedNSets

  require(isPow2(nSets))
  require(isPow2(extendedNSets) || extendedNSets == 0)
  require(extendedNSets <= nSets)
  require(extendedNSets >= 1)

  class BTBEntry extends Bundle {
    val offset   = SInt(offsetSz.W)
    val extended = Bool()
  }
  val btbEntrySz = offsetSz + 1

  class BTBMeta extends Bundle {
    val is_br = Bool()
    val tag   = UInt(tagSz.W)
  }
  val btbMetaSz = tagSz + 1

  class BTBPredictMeta extends Bundle {
    val write_way = UInt(log2Ceil(nWays).W)
  }

  val s1_meta = Wire(new BTBPredictMeta)
  val f3_meta = RegNext(RegNext(s1_meta))


  io.f3_meta := f3_meta.asUInt

  override val metaSz = s1_meta.asUInt.getWidth

  // ==========================================
  // [NEW] 1. 实例化安全组件
  // BOOM 是多发射的，一次可能读取 bankWidth 个预测目标
  // 所以我们需要生成 bankWidth 个安全组件实体
  // ==========================================
  val btb_sec = Seq.fill(bankWidth) { Module(new BTBSecurityComponent(dataWidth = vaddrBitsExtended)) }
  
  for (w <- 0 until bankWidth) {
    btb_sec(w).io.asid := 0.U
    btb_sec(w).io.vmid := 0.U
    btb_sec(w).io.ss   := 0.U
    btb_sec(w).io.el   := 0.U
    btb_sec(w).io.event_tick := false.B
    btb_sec(w).io.seed_valid := false.B
    btb_sec(w).io.seed_value := 0.U
    
    // 初始化时将加密口置 0，稍后专人专用
    btb_sec(w).io.enc_plaintext := 0.U
    btb_sec(w).io.dec_ciphertext := 0.U
  }
  // ==========================================

  val doing_reset = RegInit(true.B)
  val reset_idx   = RegInit(0.U(log2Ceil(nSets).W))
  reset_idx := reset_idx + doing_reset
  when (reset_idx === (nSets-1).U) { doing_reset := false.B }

  val meta     = Seq.fill(nWays) { SyncReadMem(nSets, Vec(bankWidth, UInt(btbMetaSz.W))) }
  val btb      = Seq.fill(nWays) { SyncReadMem(nSets, Vec(bankWidth, UInt(btbEntrySz.W))) }
  val ebtb     = SyncReadMem(extendedNSets, UInt(vaddrBitsExtended.W))

  val mems = (((0 until nWays) map ({w:Int => Seq(
    (f"btb_meta_way$w", nSets, bankWidth * btbMetaSz),
    (f"btb_data_way$w", nSets, bankWidth * btbEntrySz))})).flatten ++ Seq(("ebtb", extendedNSets, vaddrBitsExtended)))

  val s1_req_rbtb  = VecInit(btb.map { b => VecInit(b.read(s0_idx , s0_valid).map(_.asTypeOf(new BTBEntry))) })
  val s1_req_rmeta = VecInit(meta.map { m => VecInit(m.read(s0_idx, s0_valid).map(_.asTypeOf(new BTBMeta))) })
  val s1_req_rebtb = ebtb.read(s0_idx, s0_valid)
  val s1_req_tag   = s1_idx >> log2Ceil(nSets)

  val s1_resp   = Wire(Vec(bankWidth, Valid(UInt(vaddrBitsExtended.W))))
  val s1_is_br  = Wire(Vec(bankWidth, Bool()))
  val s1_is_jal = Wire(Vec(bankWidth, Bool()))

  val s1_hit_ohs = VecInit((0 until bankWidth) map { i =>
    VecInit((0 until nWays) map { w =>
      s1_req_rmeta(w)(i).tag === s1_req_tag(tagSz-1,0)
    })
  })
  val s1_hits     = s1_hit_ohs.map { oh => oh.reduce(_||_) }
  val s1_hit_ways = s1_hit_ohs.map { oh => PriorityEncoder(oh) }

  for (w <- 0 until bankWidth) {
    val entry_meta = s1_req_rmeta(s1_hit_ways(w))(w)
    val entry_btb  = s1_req_rbtb(s1_hit_ways(w))(w)
    s1_resp(w).valid := !doing_reset && s1_valid && s1_hits(w)

    // ==========================================
    // [MODIFIED] 2. 拦截并解密预测地址
    // ==========================================
    // 先把原本算出来的 target 存到一个中间变量里
    /*
    val raw_target = Mux(
      entry_btb.extended,
      s1_req_rebtb,
      (s1_pc.asSInt + (w << 1).S + entry_btb.offset).asUInt)

    // 把读出的数据喂给解密器
    btb_sec(w).io.dec_ciphertext := raw_target
    
    // 输出给流水线的最终地址，使用解密后的明文
    s1_resp(w).bits := btb_sec(w).io.dec_plaintext
    */
    val raw_target = Mux(
    entry_btb.extended,
    s1_req_rebtb,
    (s1_pc.asSInt + (w << 1).S + entry_btb.offset).asUInt
  )

  // 只对 extended 走解密
  val final_target = Mux(
    entry_btb.extended,
    btb_sec(w).io.dec_plaintext,
    raw_target
  )

  // 只有 extended 才送入 decrypt
  btb_sec(w).io.dec_ciphertext := raw_target

  s1_resp(w).bits := final_target
    // ==========================================

    /*
    s1_resp(w).bits  := Mux(
      entry_btb.extended,
      s1_req_rebtb,
      (s1_pc.asSInt + (w << 1).S + entry_btb.offset).asUInt)*/
    s1_is_br(w)  := !doing_reset && s1_resp(w).valid &&  entry_meta.is_br
    s1_is_jal(w) := !doing_reset && s1_resp(w).valid && !entry_meta.is_br


    io.resp.f2(w) := io.resp_in(0).f2(w)
    io.resp.f3(w) := io.resp_in(0).f3(w)
    when (RegNext(s1_hits(w))) {
      io.resp.f2(w).predicted_pc := RegNext(s1_resp(w))
      io.resp.f2(w).is_br        := RegNext(s1_is_br(w))
      io.resp.f2(w).is_jal       := RegNext(s1_is_jal(w))
      when (RegNext(s1_is_jal(w))) {
        io.resp.f2(w).taken      := true.B
      }
    }
    when (RegNext(RegNext(s1_hits(w)))) {
      io.resp.f3(w).predicted_pc := RegNext(io.resp.f2(w).predicted_pc)
      io.resp.f3(w).is_br        := RegNext(io.resp.f2(w).is_br)
      io.resp.f3(w).is_jal       := RegNext(io.resp.f2(w).is_jal)
      when (RegNext(RegNext(s1_is_jal(w)))) {
        io.resp.f3(w).taken      := true.B
      }
    }
  }

  val alloc_way = if (nWays > 1) {
    val r_metas = Cat(VecInit(s1_req_rmeta.map { w => VecInit(w.map(_.tag)) }).asUInt, s1_req_tag(tagSz-1,0))
    val l = log2Ceil(nWays)
    val nChunks = (r_metas.getWidth + l - 1) / l
    val chunks = (0 until nChunks) map { i =>
      r_metas(min((i+1)*l, r_metas.getWidth)-1, i*l)
    }
    chunks.reduce(_^_)
  } else {
    0.U
  }
  s1_meta.write_way := Mux(s1_hits.reduce(_||_),
    PriorityEncoder(s1_hit_ohs.map(_.asUInt).reduce(_|_)),
    alloc_way)

  val s1_update_cfi_idx = s1_update.bits.cfi_idx.bits
  val s1_update_meta    = s1_update.bits.meta.asTypeOf(new BTBPredictMeta)

  // ==========================================
  // [NEW] 3. 拦截并加密要存入 BTB 的目标地址
  // 写入端口每周期只有一个，我们借用第 0 号组件的加密通道
  // ==========================================
  /*
  btb_sec(0).io.enc_plaintext := s1_update.bits.target

  val safe_update_target = Mux(
    offset_is_extended,
    btb_sec(0).io.enc_ciphertext,
    raw_target
  )
  // ==========================================

  val max_offset_value = Cat(0.B, ~(0.U((offsetSz-1).W))).asSInt
  val min_offset_value = Cat(1.B,  (0.U((offsetSz-1).W))).asSInt
  // ==========================================
  // [NEW] Only encrypt extended target
  // ==========================================
  btb_sec(0).io.enc_plaintext := s1_update.bits.target

  safe_update_target = Mux(
    offset_is_extended,
    btb_sec(0).io.enc_ciphertext,
    s1_update.bits.target
  )
  // [MODIFIED] 把 s1_update.bits.target 替换为 safe_update_target
  // val new_offset_value = (safe_update_target.asSInt -
    // (s1_update.bits.pc + (s1_update.bits.cfi_idx.bits << 1)).asSInt)
  // val new_offset_value = (s1_update.bits.target.asSInt -
    // (s1_update.bits.pc + (s1_update.bits.cfi_idx.bits << 1)).asSInt)

  val new_offset_value = (raw_target.asSInt -
    (s1_update.bits.pc + (s1_update.bits.cfi_idx.bits << 1)).asSInt)
  val offset_is_extended = (new_offset_value > max_offset_value ||
                            new_offset_value < min_offset_value)

*/
  // 1. 先计算边界和 new_offset_value (这里必须用 s1_update.bits.target，而不是 raw_target)
  val max_offset_value = Cat(0.B, ~(0.U((offsetSz-1).W))).asSInt
  val min_offset_value = Cat(1.B,  (0.U((offsetSz-1).W))).asSInt

  val new_offset_value = (s1_update.bits.target.asSInt -
    (s1_update.bits.pc + (s1_update.bits.cfi_idx.bits << 1)).asSInt)
  
  // 2. 判断是否超出了 offset 能表示的范围 (是否需要存在 ebtb 中)
  val offset_is_extended = (new_offset_value > max_offset_value ||
                            new_offset_value < min_offset_value)

  // 3. 将流水线传来的明文 target 送入第 0 个安全组件进行加密
  btb_sec(0).io.enc_plaintext := s1_update.bits.target

  // 4. 只有当 target 需要放进 extended BTB (ebtb) 时，才存入加密后的密文
  // 如果没有 extended，存入的 offset 本质上没有走这段逻辑，但为了严谨我们加上 Mux
  val safe_update_target = Mux(
    offset_is_extended,
    btb_sec(0).io.enc_ciphertext,
    s1_update.bits.target
  )
  
  val s1_update_wbtb_data  = Wire(new BTBEntry)
  s1_update_wbtb_data.extended := offset_is_extended
  s1_update_wbtb_data.offset   := new_offset_value
  val s1_update_wbtb_mask = (UIntToOH(s1_update_cfi_idx) &
    Fill(bankWidth, s1_update.bits.cfi_idx.valid && s1_update.valid && s1_update.bits.cfi_taken && s1_update.bits.is_commit_update))

  val s1_update_wmeta_mask = ((s1_update_wbtb_mask | s1_update.bits.br_mask) &
    (Fill(bankWidth, s1_update.valid && s1_update.bits.is_commit_update) |
     (Fill(bankWidth, s1_update.valid) & s1_update.bits.btb_mispredicts)
    )
  )
  val s1_update_wmeta_data = Wire(Vec(bankWidth, new BTBMeta))

  for (w <- 0 until bankWidth) {
    s1_update_wmeta_data(w).tag     := Mux(s1_update.bits.btb_mispredicts(w), 0.U, s1_update_idx >> log2Ceil(nSets))
    s1_update_wmeta_data(w).is_br   := s1_update.bits.br_mask(w)
  }

  for (w <- 0 until nWays) {
    when (doing_reset || s1_update_meta.write_way === w.U || (w == 0 && nWays == 1).B) {
      btb(w).write(
        Mux(doing_reset,
          reset_idx,
          s1_update_idx),
        Mux(doing_reset,
          VecInit(Seq.fill(bankWidth) { 0.U(btbEntrySz.W) }),
          VecInit(Seq.fill(bankWidth) { s1_update_wbtb_data.asUInt })),
        Mux(doing_reset,
          (~(0.U(bankWidth.W))),
          s1_update_wbtb_mask).asBools
      )
      meta(w).write(
        Mux(doing_reset,
          reset_idx,
          s1_update_idx),
        Mux(doing_reset,
          VecInit(Seq.fill(bankWidth) { 0.U(btbMetaSz.W) }),
          VecInit(s1_update_wmeta_data.map(_.asUInt))),
        Mux(doing_reset,
          (~(0.U(bankWidth.W))),
          s1_update_wmeta_mask).asBools
      )


    }
  }
  /*
  when (s1_update_wbtb_mask =/= 0.U && offset_is_extended) {
    ebtb.write(s1_update_idx, s1_update.bits.target)
  }
  */
    when (s1_update_wbtb_mask =/= 0.U && offset_is_extended) {
    // [MODIFIED] 把 s1_update.bits.target 替换为 safe_update_target
    ebtb.write(s1_update_idx, safe_update_target)
  }
  
}

