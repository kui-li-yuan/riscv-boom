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

// 2. 定义模块本体
class BTBSecurityComponent(val dataWidth: Int = 64, val entropyWidth: Int = 32)(implicit p: Parameters) extends BoomModule {
  val io = IO(new BTBSecurityIO(dataWidth, entropyWidth))

  // ==========================================
  // 【核心框架：Dummy 逻辑，后续把真实的加解密写在这里】
  // ==========================================

  // 真正接入 异或
  val xorEnc = Module(new BTBXor(dataWidth))
  val xorDec = Module(new BTBXor(dataWidth))

  // key 目前先用一个简单版本（后面再换 key_gen）
  val key = RegInit(0.U(dataWidth.W))

  // ===== Encrypt =====
  xorEnc.io.in  := io.enc_plaintext
  xorEnc.io.key := key
  io.enc_ciphertext := xorEnc.io.out

  // ===== Decrypt =====
  xorDec.io.in  := io.dec_ciphertext
  xorDec.io.key := key
  io.dec_plaintext := xorDec.io.out

  // ===== 先保持简单 =====
  io.key_ready := true.B
  io.dbg_key   := key
  io.dbg_entropy := 0.U

}