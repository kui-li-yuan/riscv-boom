package boom.ifu

import chisel3._
import chisel3.util._
import org.chipsalliance.cde.config.Parameters
import boom.common._

// 1. 定义 IO 接口 (完全映射你的 Verilog 端口，但省去了 clock 和 reset，因为 Chisel 会自动接)
class BTBSecurityIO(val dataWidth: Int, val entropyWidth: Int) extends Bundle {
  // ARM context (RISC-V 里暂时用不到这么多，留着做兼容)
  val asid = Input(UInt(16.W))
  val vmid = Input(UInt(16.W))
  val ss   = Input(UInt(2.W))
  val el   = Input(UInt(2.W))

  // 加密路径 (Encrypt)
  val enc_plaintext  = Input(UInt(dataWidth.W))
  val enc_ciphertext = Output(UInt(dataWidth.W))

  // 解密路径 (Decrypt)
  val dec_ciphertext = Input(UInt(dataWidth.W))
  val dec_plaintext  = Output(UInt(dataWidth.W))

  // 控制与事件 (Control & Events)
  val event_tick = Input(Bool())
  val seed_valid = Input(Bool())
  val seed_value = Input(UInt(entropyWidth.W))

  // 状态与调试 (Status & Debug)
  val key_ready   = Output(Bool())
  val dbg_key     = Output(UInt(dataWidth.W))
  val dbg_entropy = Output(UInt(entropyWidth.W))
}

// 统一enc/dec模块
class BTBXor(val width: Int) extends Module {
  val io = IO(new Bundle {
    val in  = Input(UInt(width.W))
    val key = Input(UInt(width.W))
    val out = Output(UInt(width.W))
  })

  io.out := io.in ^ io.key
}

// entropy table 模块
class BTBEntropyTable(
  val tableDepthLog2: Int = 4,
  val entropyWidth: Int = 32
) extends Module {

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

  // ===== Index =====
  val idx = io.asid(3,0) ^ io.vmid(3,0) ^ Cat(io.ss, io.el)

  // ===== LFSR =====
  val lfsr = RegInit("hdeadbeef".U(entropyWidth.W))
  val feedback = lfsr(31) ^ lfsr(21) ^ lfsr(1) ^ lfsr(0)
  val next_lfsr = Cat(lfsr(entropyWidth-2, 0), feedback)

  when (io.seed_valid) {
    lfsr := io.seed_value
  } .otherwise {
    lfsr := next_lfsr
  }

  // ===== Table =====
  val depth = 1 << tableDepthLog2
  val table = RegInit(VecInit(Seq.fill(depth)(0.U(entropyWidth.W))))

  when (io.event_tick) {
    table(idx) := lfsr
  }

  // ===== Output =====
  io.entropy_out := table(idx)
}

// key gen 模块
class BTBKeyGen(val keyWidth: Int = 64, val entropyWidth: Int = 32) extends Module {
  val io = IO(new Bundle {
    val asid    = Input(UInt(16.W))
    val vmid    = Input(UInt(16.W))
    val ss      = Input(UInt(2.W))
    val el      = Input(UInt(2.W))
    val entropy = Input(UInt(entropyWidth.W))
    val key     = Output(UInt(keyWidth.W))
  })

  // ===== Stage 1: context =====
  val ctx = Cat(io.asid, io.vmid, io.ss, io.el) // 36-bit

  val ctx_expanded = Cat(
    ctx,
    ctx(35,8) ^ ctx(27,0)
  ) // 64-bit

  // ===== Stage 2: XOR entropy =====
  val mixed = ctx_expanded ^ Cat(io.entropy, io.entropy)

  // ===== Stage 3: S-Box =====
  val subVec = Wire(Vec(16, UInt(4.W)))

  for (i <- 0 until 16) {
    val nibble = mixed(4*i+3, 4*i)
    subVec(i) := BTBSBox(nibble)   // 你后面给我 sbox，我帮你写
  }

  val sub = subVec.reverse.reduce(Cat(_, _))

  // ===== Stage 4: rotation =====
  def rol(x: UInt, n: Int) = (x << n) | (x >> (keyWidth - n))

  val key = sub ^ rol(sub,7) ^ rol(sub,13) ^ rol(sub,29)

  io.key := key
}

// sbox模块
// ======================================================
// BTB S-Box 模块模板
// ======================================================
class BTBSBox extends Module {
  val io = IO(new Bundle {
    val in  = Input(UInt(4.W))
    val out = Output(UInt(4.W))
  })

  // ==== 暂时透传 ====
  io.out := io.in
}

// ======================================================
// 方便在 KeyGen 里调用
// 用 apply 构造函数，语法和 object 类似，但是 class
// ======================================================
object BTBSBox {
  def apply(in: UInt): UInt = {
    val sbox = Module(new BTBSBox)
    sbox.io.in := in
    sbox.io.out
  }
}
// 2. 定义模块本体
/*
class BTBSecurityComponent(val dataWidth: Int = 64, val entropyWidth: Int = 32)(implicit p: Parameters) extends BoomModule {
  val io = IO(new BTBSecurityIO(dataWidth, entropyWidth))

  // ==========================================
  // 【核心框架：Dummy 逻辑，后续把真实的加解密写在这里】
  // ==========================================

  // 接入entropy table(但不让它乱变)
  val entropyTable = Module(new BTBEntropyTable())

  entropyTable.io.asid := io.asid
  entropyTable.io.vmid := io.vmid
  entropyTable.io.ss   := io.ss
  entropyTable.io.el   := io.el

  entropyTable.io.event_tick := false.B   // 先冻结
  entropyTable.io.seed_valid := io.seed_valid
  entropyTable.io.seed_value := io.seed_value

  //暂时不接key
  val entropy = entropyTable.io.entropy_out

  // 真正接入 异或
  val xorEnc = Module(new BTBXor(dataWidth))
  val xorDec = Module(new BTBXor(dataWidth))

  // 接入key gen
  val keyGen = Module(new BTBKeyGen(dataWidth, entropyWidth))

  keyGen.io.asid    := io.asid
  keyGen.io.vmid    := io.vmid
  keyGen.io.ss      := io.ss
  keyGen.io.el      := io.el
  keyGen.io.entropy := entropy

  // 加变化检测
  val asid_prev    = RegNext(io.asid)
  val vmid_prev    = RegNext(io.vmid)
  val ss_prev      = RegNext(io.ss)
  val el_prev      = RegNext(io.el)
  val entropy_prev = RegNext(entropy)

  val change_detected =
    (io.asid =/= asid_prev) ||
    (io.vmid =/= vmid_prev) ||
    (io.ss   =/= ss_prev)   ||
    (io.el   =/= el_prev)   ||
    (entropy =/= entropy_prev)

  // key register
  val key_reg   = RegInit(0.U(dataWidth.W))
  val key_ready = RegInit(false.B)

  when (!change_detected) {
    key_reg   := keyGen.io.key
    key_ready := true.B
  } .otherwise {
    key_ready := false.B
  }

  // key 目前先用一个简单版本（后面再换 key_gen）
  val key = RegInit(0.U(dataWidth.W))

  // ===== Encrypt =====
  xorEnc.io.in  := io.enc_plaintext
  xorEnc.io.key := key_reg
  io.enc_ciphertext := xorEnc.io.out

  // ===== Decrypt =====
  xorDec.io.in  := io.dec_ciphertext
  xorDec.io.key := key_reg
  io.dec_plaintext := xorDec.io.out

  // ===== 先保持简单 =====
  io.key_ready := true.B
  io.dbg_key   := key
  io.dbg_entropy := 0.U

}
*/

class BTBSecurityComponent(
  val dataWidth: Int = 64,
  val entropyWidth: Int = 32
)(implicit p: Parameters) extends BoomModule {

  val io = IO(new BTBSecurityIO(dataWidth, entropyWidth))

  // =========================================================
  // 1. Entropy Table
  // =========================================================
  val entropyTable = Module(new BTBEntropyTable())

  entropyTable.io.asid := io.asid
  entropyTable.io.vmid := io.vmid
  entropyTable.io.ss   := io.ss
  entropyTable.io.el   := io.el

  // Phase 1: freeze entropy（非常重要）
  entropyTable.io.event_tick := false.B
  entropyTable.io.seed_valid := io.seed_valid
  entropyTable.io.seed_value := io.seed_value

  val entropy = entropyTable.io.entropy_out

  // =========================================================
  // 2. Key Generation（组合）
  // =========================================================
  val keyGen = Module(new BTBKeyGen(dataWidth, entropyWidth))

  keyGen.io.asid    := io.asid
  keyGen.io.vmid    := io.vmid
  keyGen.io.ss      := io.ss
  keyGen.io.el      := io.el
  keyGen.io.entropy := entropy

  // =========================================================
  // 3. Change Detection（修复版本）
  // =========================================================
  val asid_prev    = RegInit(0.U(16.W))
  val vmid_prev    = RegInit(0.U(16.W))
  val ss_prev      = RegInit(0.U(2.W))
  val el_prev      = RegInit(0.U(2.W))
  val entropy_prev = RegInit(0.U(entropyWidth.W))

  val change_detected =
    (io.asid =/= asid_prev) ||
    (io.vmid =/= vmid_prev) ||
    (io.ss   =/= ss_prev)   ||
    (io.el   =/= el_prev)   ||
    (entropy =/= entropy_prev)

  // 更新 prev（注意顺序）
  asid_prev    := io.asid
  vmid_prev    := io.vmid
  ss_prev      := io.ss
  el_prev      := io.el
  entropy_prev := entropy

  // =========================================================
  // 4. Key Register（核心）
  // =========================================================
  val key_reg   = RegInit(0.U(dataWidth.W))
  val key_ready = RegInit(false.B)

  when (!change_detected) {
    key_reg   := keyGen.io.key
    key_ready := true.B
  } .otherwise {
    key_ready := false.B
  }

  // =========================================================
  // 5. XOR Encrypt / Decrypt
  // =========================================================
  val xorEnc = Module(new BTBXor(dataWidth))
  val xorDec = Module(new BTBXor(dataWidth))

  xorEnc.io.in  := io.enc_plaintext
  xorEnc.io.key := key_reg
  io.enc_ciphertext := xorEnc.io.out

  xorDec.io.in  := io.dec_ciphertext
  xorDec.io.key := key_reg
  io.dec_plaintext := xorDec.io.out

  // =========================================================
  // 6. Debug & Status
  // =========================================================
  io.key_ready   := key_ready
  io.dbg_key     := key_reg
  io.dbg_entropy := entropy
}