package boom.ifu

import chisel3._
import chisel3.util._
import org.chipsalliance.cde.config.Parameters
import boom.common._

// =========================================================
// IO 接口定义
// =========================================================
class BTBSecurityIO(val dataWidth: Int, val entropyWidth: Int) extends Bundle {
  val asid = Input(UInt(16.W))
  val vmid = Input(UInt(16.W))
  val ss   = Input(UInt(2.W))
  val el   = Input(UInt(2.W))

  val enc_plaintext  = Input(UInt(dataWidth.W))
  val enc_ciphertext = Output(UInt(dataWidth.W))

  val dec_ciphertext = Input(UInt(dataWidth.W))
  val dec_plaintext  = Output(UInt(dataWidth.W))

  val event_tick = Input(Bool())
  val seed_valid = Input(Bool())
  val seed_value = Input(UInt(entropyWidth.W))

  val key_ready   = Output(Bool())
  val dbg_key     = Output(UInt(dataWidth.W))
  val dbg_entropy = Output(UInt(entropyWidth.W))
}

// =========================================================
// XOR 模块与 Entropy Table
// =========================================================
class BTBXor(val width: Int) extends Module {
  val io = IO(new Bundle {
    val in  = Input(UInt(width.W))
    val key = Input(UInt(width.W))
    val out = Output(UInt(width.W))
  })
  io.out := io.in ^ io.key
}

class BTBEntropyTable(val tableDepthLog2: Int = 4, val entropyWidth: Int = 32) extends Module {
  val io = IO(new Bundle {
    val asid        = Input(UInt(16.W))
    val vmid        = Input(UInt(16.W))
    val ss          = Input(UInt(2.W))
    val el          = Input(UInt(2.W))
    val event_tick  = Input(Bool())
    val seed_valid  = Input(Bool())
    val seed_value  = Input(UInt(entropyWidth.W))
    val entropy_out = Output(UInt(entropyWidth.W))
  })

  val idx = io.asid(3,0) ^ io.vmid(3,0) ^ Cat(io.ss, io.el)
  val lfsr = RegInit("hdeadbeef".U(entropyWidth.W))
  val feedback = lfsr(31) ^ lfsr(21) ^ lfsr(1) ^ lfsr(0)
  val next_lfsr = Cat(lfsr(entropyWidth-2, 0), feedback)

  when (io.seed_valid) { lfsr := io.seed_value }
  .otherwise { lfsr := next_lfsr }

  val depth = 1 << tableDepthLog2
  val table = RegInit(VecInit(Seq.fill(depth)(0.U(entropyWidth.W))))

  when (io.event_tick) { table(idx) := lfsr }
  io.entropy_out := table(idx)
}

// =========================================================
// PRINCE Cipher 数学操作封装 (加入 4 种 S-Box 支持)
// =========================================================
object PrinceMath {

  // --- S-Box 0 (PRINCE-like) ---
  val s0Fwd = Seq("hC","h5","h6","hB","h9","h0","hA","hD","h3","hE","hF","h8","h4","h7","h1","h2").map(_.U(4.W))
  val s0Inv = Seq("h5","hE","hF","h8","hC","h1","h2","hD","hB","h4","h6","h3","h0","h7","h9","hA").map(_.U(4.W))

  // --- S-Box 1 (PRINCE) ---
  val s1Fwd = Seq("hB","hF","h3","h2","hA","hC","h9","h1","h6","h7","h8","h0","hE","h5","hD","h4").map(_.U(4.W))
  val s1Inv = Seq("hB","h7","h3","h2","hF","hD","h8","h9","hA","h6","h4","h0","h5","hE","hC","h1").map(_.U(4.W))

  // --- S-Box 2 (GIFT) ---
  val s2Fwd = Seq("h1","hA","h4","hC","h6","hF","h3","h9","h2","hD","hB","h7","h5","h0","h8","hE").map(_.U(4.W))
  val s2Inv = Seq("hD","h0","h8","h6","h2","hC","h4","hB","hE","h7","h1","hA","h3","h9","hF","h5").map(_.U(4.W))

  // --- S-Box 3 (Piccolo) ---
  val s3Fwd = Seq("hE","h4","hB","h2","h3","h8","h0","h9","h1","hA","h7","hF","h6","hC","h5","hD").map(_.U(4.W))
  val s3Inv = Seq("h6","h8","h3","h4","h1","hE","hC","hA","h5","h7","h9","h2","hD","hF","h0","hB").map(_.U(4.W))

  // 按类型查表函数
  def sboxFwdNib(n: UInt, sboxType: Int): UInt = {
    val table = sboxType match {
      case 0 => s0Fwd; case 1 => s1Fwd; case 2 => s2Fwd; case 3 => s3Fwd; case _ => s1Fwd
    }
    VecInit(table)(n)
  }
  
  def sboxInvNib(n: UInt, sboxType: Int): UInt = {
    val table = sboxType match {
      case 0 => s0Inv; case 1 => s1Inv; case 2 => s2Inv; case 3 => s3Inv; case _ => s1Inv
    }
    VecInit(table)(n)
  }

  // 64-bit 透传
  def sboxFwd(in: UInt, sboxType: Int): UInt = Cat((0 until 16).reverse.map(i => sboxFwdNib(in(i*4+3, i*4), sboxType)))
  def sboxInv(in: UInt, sboxType: Int): UInt = Cat((0 until 16).reverse.map(i => sboxInvNib(in(i*4+3, i*4), sboxType)))

  // ShiftRows 和基础矩阵 M'
  def shiftRowsFwd(in: UInt): UInt = {
    val idx = Seq(15, 10, 5, 0, 11, 6, 1, 12, 7, 2, 13, 8, 3, 14, 9, 4)
    Cat(idx.map(i => in(i*4+3, i*4)))
  }
  def shiftRowsInv(in: UInt): UInt = {
    val idx = Seq(15, 2, 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12)
    Cat(idx.map(i => in(i*4+3, i*4)))
  }

  def m0Sub(in: UInt): UInt = {
    val x0 = in(15,12); val x1 = in(11,8); val x2 = in(7,4); val x3 = in(3,0)
    val y0 = Cat(x1(3)^x2(3)^x3(3), x0(2)^x2(2)^x3(2), x0(1)^x1(1)^x3(1), x0(0)^x1(0)^x2(0))
    val y1 = Cat(x0(3)^x1(3)^x2(3), x1(2)^x2(2)^x3(2), x0(1)^x2(1)^x3(1), x0(0)^x1(0)^x3(0))
    val y2 = Cat(x0(3)^x1(3)^x3(3), x0(2)^x1(2)^x2(2), x1(1)^x2(1)^x3(1), x0(0)^x2(0)^x3(0))
    val y3 = Cat(x0(3)^x2(3)^x3(3), x0(2)^x1(2)^x3(2), x0(1)^x1(1)^x2(1), x1(0)^x2(0)^x3(0))
    Cat(y0, y1, y2, y3)
  }
  def m1Sub(in: UInt): UInt = {
    val x0 = in(15,12); val x1 = in(11,8); val x2 = in(7,4); val x3 = in(3,0)
    val y0 = Cat(x0(3)^x1(3)^x2(3), x1(2)^x2(2)^x3(2), x0(1)^x2(1)^x3(1), x0(0)^x1(0)^x3(0))
    val y1 = Cat(x0(3)^x1(3)^x3(3), x0(2)^x1(2)^x2(2), x1(1)^x2(1)^x3(1), x0(0)^x2(0)^x3(0))
    val y2 = Cat(x0(3)^x2(3)^x3(3), x0(2)^x1(2)^x3(2), x0(1)^x1(1)^x2(1), x1(0)^x2(0)^x3(0))
    val y3 = Cat(x1(3)^x2(3)^x3(3), x0(2)^x2(2)^x3(2), x0(1)^x1(1)^x3(1), x0(0)^x1(0)^x2(0))
    Cat(y0, y1, y2, y3)
  }
  def mPrime(in: UInt): UInt = Cat(m0Sub(in(63,48)), m1Sub(in(47,32)), m1Sub(in(31,16)), m0Sub(in(15,0)))
  def mInvLayer(in: UInt): UInt = mPrime(shiftRowsInv(in))

  // ==========================================
  // 融合 S+M'+XOR (前向)
  // ==========================================
  def m0SboxFwdXor(n0: UInt, n1: UInt, n2: UInt, n3: UInt, rk: UInt, sboxType: Int): UInt = {
    val s0 = sboxFwdNib(n0, sboxType); val s1 = sboxFwdNib(n1, sboxType)
    val s2 = sboxFwdNib(n2, sboxType); val s3 = sboxFwdNib(n3, sboxType)
    val r0 = rk(15,12); val r1 = rk(11,8); val r2 = rk(7,4); val r3 = rk(3,0)
    val y0 = Cat(s1(3)^s2(3)^s3(3)^r0(3), s0(2)^s2(2)^s3(2)^r0(2), s0(1)^s1(1)^s3(1)^r0(1), s0(0)^s1(0)^s2(0)^r0(0))
    val y1 = Cat(s0(3)^s1(3)^s2(3)^r1(3), s1(2)^s2(2)^s3(2)^r1(2), s0(1)^s2(1)^s3(1)^r1(1), s0(0)^s1(0)^s3(0)^r1(0))
    val y2 = Cat(s0(3)^s1(3)^s3(3)^r2(3), s0(2)^s1(2)^s2(2)^r2(2), s1(1)^s2(1)^s3(1)^r2(1), s0(0)^s2(0)^s3(0)^r2(0))
    val y3 = Cat(s0(3)^s2(3)^s3(3)^r3(3), s0(2)^s1(2)^s3(2)^r3(2), s0(1)^s1(1)^s2(1)^r3(1), s1(0)^s2(0)^s3(0)^r3(0))
    Cat(y0, y1, y2, y3)
  }

  def m1SboxFwdXor(n0: UInt, n1: UInt, n2: UInt, n3: UInt, rk: UInt, sboxType: Int): UInt = {
    val s0 = sboxFwdNib(n0, sboxType); val s1 = sboxFwdNib(n1, sboxType)
    val s2 = sboxFwdNib(n2, sboxType); val s3 = sboxFwdNib(n3, sboxType)
    val r0 = rk(15,12); val r1 = rk(11,8); val r2 = rk(7,4); val r3 = rk(3,0)
    val y0 = Cat(s0(3)^s1(3)^s2(3)^r0(3), s1(2)^s2(2)^s3(2)^r0(2), s0(1)^s2(1)^s3(1)^r0(1), s0(0)^s1(0)^s3(0)^r0(0))
    val y1 = Cat(s0(3)^s1(3)^s3(3)^r1(3), s0(2)^s1(2)^s2(2)^r1(2), s1(1)^s2(1)^s3(1)^r1(1), s0(0)^s2(0)^s3(0)^r1(0))
    val y2 = Cat(s0(3)^s2(3)^s3(3)^r2(3), s0(2)^s1(2)^s3(2)^r2(2), s0(1)^s1(1)^s2(1)^r2(1), s1(0)^s2(0)^s3(0)^r2(0))
    val y3 = Cat(s1(3)^s2(3)^s3(3)^r3(3), s0(2)^s2(2)^s3(2)^r3(2), s0(1)^s1(1)^s3(1)^r3(1), s0(0)^s1(0)^s2(0)^r3(0))
    Cat(y0, y1, y2, y3)
  }

  def sboxMPrimeFwdXor(in: UInt, rk: UInt, sboxType: Int): UInt = Cat(
    m0SboxFwdXor(in(63,60), in(59,56), in(55,52), in(51,48), rk(63,48), sboxType),
    m1SboxFwdXor(in(47,44), in(43,40), in(39,36), in(35,32), rk(47,32), sboxType),
    m1SboxFwdXor(in(31,28), in(27,24), in(23,20), in(19,16), rk(31,16), sboxType),
    m0SboxFwdXor(in(15,12), in(11,8),  in(7,4),   in(3,0),   rk(15,0),  sboxType)
  )

  // ==========================================
  // 融合 M'+XOR+S⁻¹ (后向)
  // ==========================================
  def m0XorSboxInv(n0: UInt, n1: UInt, n2: UInt, n3: UInt, rk: UInt, sboxType: Int): UInt = {
    val r0 = rk(15,12); val r1 = rk(11,8); val r2 = rk(7,4); val r3 = rk(3,0)
    val y0 = Cat(n1(3)^n2(3)^n3(3)^r0(3), n0(2)^n2(2)^n3(2)^r0(2), n0(1)^n1(1)^n3(1)^r0(1), n0(0)^n1(0)^n2(0)^r0(0))
    val y1 = Cat(n0(3)^n1(3)^n2(3)^r1(3), n1(2)^n2(2)^n3(2)^r1(2), n0(1)^n2(1)^n3(1)^r1(1), n0(0)^n1(0)^n3(0)^r1(0))
    val y2 = Cat(n0(3)^n1(3)^n3(3)^r2(3), n0(2)^n1(2)^n2(2)^r2(2), n1(1)^n2(1)^n3(1)^r2(1), n0(0)^n2(0)^n3(0)^r2(0))
    val y3 = Cat(n0(3)^n2(3)^n3(3)^r3(3), n0(2)^n1(2)^n3(2)^r3(2), n0(1)^n1(1)^n2(1)^r3(1), n1(0)^n2(0)^n3(0)^r3(0))
    Cat(sboxInvNib(y0, sboxType), sboxInvNib(y1, sboxType), sboxInvNib(y2, sboxType), sboxInvNib(y3, sboxType))
  }

  def m1XorSboxInv(n0: UInt, n1: UInt, n2: UInt, n3: UInt, rk: UInt, sboxType: Int): UInt = {
    val r0 = rk(15,12); val r1 = rk(11,8); val r2 = rk(7,4); val r3 = rk(3,0)
    val y0 = Cat(n0(3)^n1(3)^n2(3)^r0(3), n1(2)^n2(2)^n3(2)^r0(2), n0(1)^n2(1)^n3(1)^r0(1), n0(0)^n1(0)^n3(0)^r0(0))
    val y1 = Cat(n0(3)^n1(3)^n3(3)^r1(3), n0(2)^n1(2)^n2(2)^r1(2), n1(1)^n2(1)^n3(1)^r1(1), n0(0)^n2(0)^n3(0)^r1(0))
    val y2 = Cat(n0(3)^n2(3)^n3(3)^r2(3), n0(2)^n1(2)^n3(2)^r2(2), n0(1)^n1(1)^n2(1)^r2(1), n1(0)^n2(0)^n3(0)^r2(0))
    val y3 = Cat(n1(3)^n2(3)^n3(3)^r3(3), n0(2)^n2(2)^n3(2)^r3(2), n0(1)^n1(1)^n3(1)^r3(1), n0(0)^n1(0)^n2(0)^r3(0))
    Cat(sboxInvNib(y0, sboxType), sboxInvNib(y1, sboxType), sboxInvNib(y2, sboxType), sboxInvNib(y3, sboxType))
  }

  def mPrimeXorSboxInv(in: UInt, rk: UInt, sboxType: Int): UInt = Cat(
    m0XorSboxInv(in(63,60), in(59,56), in(55,52), in(51,48), rk(63,48), sboxType),
    m1XorSboxInv(in(47,44), in(43,40), in(39,36), in(35,32), rk(47,32), sboxType),
    m1XorSboxInv(in(31,28), in(27,24), in(23,20), in(19,16), rk(31,16), sboxType),
    m0XorSboxInv(in(15,12), in(11,8),  in(7,4),   in(3,0),   rk(15,0),  sboxType)
  )
}

// =========================================================
// Key Generation Pipeline
// =========================================================
class BTBKeyGen(val keyWidth: Int = 64, val entropyWidth: Int = 32) extends Module {
  val io = IO(new Bundle {
    val ena       = Input(Bool())
    val asid      = Input(UInt(16.W))
    val vmid      = Input(UInt(16.W))
    val ss        = Input(UInt(2.W))
    val el        = Input(UInt(2.W))
    val entropy   = Input(UInt(entropyWidth.W))
    
    val out_valid = Output(Bool())
    val key       = Output(UInt(keyWidth.W))
  })

  import PrinceMath._

  // ----------------------------------------------------------------
  // [关键配置区]：S-Box 轮次映射 (S-Box Round Configuration)
  // 根据你同学的需求，配置每一轮使用哪个 S-Box (0, 1, 2, 3)
  // ----------------------------------------------------------------
  def getSboxType(round: Int): Int = {
    round match {
      case 1 => 0  // 轮次1：使用 sbox_0 (PRINCE-like)
      case 2 => 1  // 轮次2：使用 sbox_1 (PRINCE)
      case 3 => 2  // 轮次3：使用 sbox_2 (GIFT)
      case 4 => 3  // 轮次4：使用 sbox_3 (Piccolo)
      
      // 中间层 (Middle layer)
      case 100 => 0 // 假设中间层前向用 S-box 0
      case 101 => 0 // 假设中间层逆向用 S-box 0

      // 回归轮次 (后向)
      case 5 => 3  // 轮次5
      case 6 => 2  // 轮次6
      case 7 => 1  // 轮次7
      case 8 => 0  // 轮次8
      case 9 => 0  // 轮次9
      case 10=> 1  // 轮次10
      case _ => 1  // 默认兜底
    }
  }

  val RC = VecInit(Seq(
    "h0000000000000000".U, "h13198a2e03707344".U, "ha4093822299f31d0".U, "h082efa98ec4e6c89".U,
    "h452821e638d01377".U, "hbe5466cf34e90c6c".U, "h7ef84f78fd955cb1".U, "h85840851f1ac43aa".U,
    "hc882d32f25323c54".U, "h64a51195e0e3610d".U, "hd3b5a399ca0c2399".U, "hc0ac29b7c97c50dd".U
  ).map(_.apply(63, 0)))

  // --- Stage 0: Input Registration ---
  val p0_valid   = RegNext(io.ena, false.B)
  val p0_asid    = RegEnable(io.asid, io.ena)
  val p0_vmid    = RegEnable(io.vmid, io.ena)
  val p0_ss      = RegEnable(io.ss, io.ena)
  val p0_el      = RegEnable(io.el, io.ena)
  val p0_entropy = RegEnable(io.entropy, io.ena)

  // --- Stage 1: Key Derivation & R1-R3 ---
  val context_in = Cat(p0_asid, p0_vmid, p0_ss, p0_el)
  
  val k0_base = Cat(context_in, context_in(35,8) ^ context_in(27,0)) ^ Cat(p0_entropy, p0_entropy)
  val k1_base = Cat(context_in(27,0), context_in) ^ Cat(~p0_entropy, p0_entropy ^ "h13198A2E".U(32.W))
  val k0_prime = Cat(k0_base(0), k0_base(63,1)) ^ Cat(0.U(63.W), k0_base(63))
  val plaintext = Cat(p0_entropy, p0_entropy ^ context_in(31,0))

  // 生成索引长度为 4 的序列，0占位，1~3有用
  val rk_fwd_sr = (0 to 3).map(i => if(i==0) 0.U(64.W) else shiftRowsInv(k1_base ^ RC(i)))
  val s1_rk4_sr = shiftRowsInv(k1_base ^ RC(4))
  val s1_rk5_sr = shiftRowsInv(k1_base ^ RC(5))
  val s1_rk6_fused = mInvLayer(k1_base ^ RC(6))

  var st1 = plaintext ^ k0_base ^ k1_base ^ RC(0)
  for (r <- 1 to 3) {
    // 【注入 S-Box 配置】：传入 getSboxType(r) 告诉底层用第几套 S-Box
    st1 = shiftRowsFwd(sboxMPrimeFwdXor(st1, rk_fwd_sr(r), getSboxType(r)))
  }
  val s1_result = st1

  // Pipeline register 1
  val p1_valid     = RegNext(p0_valid, false.B)
  val p1_state     = RegEnable(s1_result, p0_valid)
  val p1_k1        = RegEnable(k1_base, p0_valid)
  val p1_k0p       = RegEnable(k0_prime, p0_valid)
  val p1_rk4_sr    = RegEnable(s1_rk4_sr, p0_valid)
  val p1_rk5_sr    = RegEnable(s1_rk5_sr, p0_valid)
  val p1_rk6_fused = RegEnable(s1_rk6_fused, p0_valid)

  // --- Stage 2: R4 + R5 + Middle + R6 ---
  var st2 = p1_state
  st2 = shiftRowsFwd(sboxMPrimeFwdXor(st2, p1_rk4_sr, getSboxType(4)))
  st2 = shiftRowsFwd(sboxMPrimeFwdXor(st2, p1_rk5_sr, getSboxType(5)))
  
  // 中间层 (Middle Layer): forward (配置100) -> inverse (配置101)
  st2 = sboxInv(sboxMPrimeFwdXor(st2, 0.U(64.W), getSboxType(100)), getSboxType(101))
  
  // R6 Backward
  st2 = mPrimeXorSboxInv(shiftRowsInv(st2), p1_rk6_fused, getSboxType(6))
  val s2_result = st2

  // 生成 0到10 的序列，7到10有用
  val s2_rk_bwd_fused = (0 to 10).map(i => if(i<7) 0.U(64.W) else mInvLayer(p1_k1 ^ RC(i)))
  val s2_post_white_key = p1_k1 ^ RC(11) ^ p1_k0p

  // Pipeline register 2
  val p2_valid = RegNext(p1_valid, false.B)
  val p2_state = RegEnable(s2_result, p1_valid)
  val p2_rk_bwd_fused = s2_rk_bwd_fused.map(rk => RegEnable(rk, p1_valid))
  val p2_post_white_key = RegEnable(s2_post_white_key, p1_valid)

  // --- Stage 3: R7-R10 + Post ---
  var st3 = p2_state
  for (r <- 7 to 10) {
    // 【注入 S-Box 配置】
    st3 = mPrimeXorSboxInv(shiftRowsInv(st3), p2_rk_bwd_fused(r), getSboxType(r))
  }
  val s3_result = st3 ^ p2_post_white_key

  // Output Register
  io.out_valid := RegNext(p2_valid, false.B)
  io.key       := RegEnable(s3_result, p2_valid)
}

// =========================================================
// BTB Security Component 顶层
// =========================================================
class BTBSecurityComponent(
  val dataWidth: Int = 64,
  val entropyWidth: Int = 32
)(implicit p: Parameters) extends BoomModule {

  val io = IO(new BTBSecurityIO(dataWidth, entropyWidth))

  val entropyTable = Module(new BTBEntropyTable())
  entropyTable.io.asid := io.asid
  entropyTable.io.vmid := io.vmid
  entropyTable.io.ss   := io.ss
  entropyTable.io.el   := io.el
  entropyTable.io.event_tick := false.B
  entropyTable.io.seed_valid := io.seed_valid
  entropyTable.io.seed_value := io.seed_value

  val entropy = entropyTable.io.entropy_out

  val asid_prev    = RegInit(0.U(16.W))
  val vmid_prev    = RegInit(0.U(16.W))
  val ss_prev      = RegInit(0.U(2.W))
  val el_prev      = RegInit(0.U(2.W))
  val entropy_prev = RegInit(0.U(entropyWidth.W))

  val context_changed =
    (io.asid =/= asid_prev) ||
    (io.vmid =/= vmid_prev) ||
    (io.ss   =/= ss_prev)   ||
    (io.el   =/= el_prev)   ||
    (entropy =/= entropy_prev)

  asid_prev    := io.asid
  vmid_prev    := io.vmid
  ss_prev      := io.ss
  el_prev      := io.el
  entropy_prev := entropy

  val is_init = RegInit(true.B)
  when (is_init) { is_init := false.B }
  
  val trigger_keygen = context_changed || is_init

  val keyGen = Module(new BTBKeyGen(dataWidth, entropyWidth))
  keyGen.io.ena     := trigger_keygen
  keyGen.io.asid    := io.asid
  keyGen.io.vmid    := io.vmid
  keyGen.io.ss      := io.ss
  keyGen.io.el      := io.el
  keyGen.io.entropy := entropy

  val key_reg   = RegInit(0.U(dataWidth.W))
  val key_ready = RegInit(false.B)

  when (trigger_keygen) {
    key_ready := false.B
  } .elsewhen (keyGen.io.out_valid) {
    key_ready := true.B
    key_reg   := keyGen.io.key
  }

  val xorEnc = Module(new BTBXor(dataWidth))
  val xorDec = Module(new BTBXor(dataWidth))

  xorEnc.io.in  := io.enc_plaintext
  xorEnc.io.key := key_reg
  io.enc_ciphertext := xorEnc.io.out

  xorDec.io.in  := io.dec_ciphertext
  xorDec.io.key := key_reg
  io.dec_plaintext := xorDec.io.out

  io.key_ready   := key_ready
  io.dbg_key     := key_reg
  io.dbg_entropy := entropy
}