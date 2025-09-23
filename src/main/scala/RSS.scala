package icenet

import chisel3._
import chisel3.util._
import freechips.rocketchip.util._
import IceNetConsts._
import scala.math.max

class HashIO(nCores: Int) extends Bundle {
  val in = Flipped(Valid(new Bundle {
    val src_ip   = Input(UInt(32.W)) 
    val dst_ip   = Input(UInt(32.W)) 
    val src_port = Input(UInt(32.W))
    val dst_port = Input(UInt(32.W))
    val protocol = Input(UInt(8.W))
  }))

  val out = Valid(UInt(log2Ceil(nCores).W))
}

/*
 * ToeplitzHash same as Intel DPDK
 *
 * @hashBits Width of hash result(in bits)
 * @entires Entries of indirection table
 * @nCores Number of cores
 */
class Hash(hashBits: Int = 32, entries: Int = 16, nCores: Int) extends Module {
  val io = IO(new HashIO(hashBits))

  private val rss_key = VecInit(Seq(
    0x6d.U(8.W), 0x5a.U(8.W), 0x56.U(8.W), 0xda.U(8.W),
    0x25.U(8.W), 0x5b.U(8.W), 0x0e.U(8.W), 0xc2.U(8.W),
    0x41.U(8.W), 0x67.U(8.W), 0x25.U(8.W), 0x3d.U(8.W),
    0x43.U(8.W), 0xa3.U(8.W), 0x8f.U(8.W), 0xb0.U(8.W),
    0xd0.U(8.W), 0xca.U(8.W), 0x2b.U(8.W), 0xcb.U(8.W),
    0xae.U(8.W), 0x7b.U(8.W), 0x30.U(8.W), 0xb4.U(8.W),
    0x77.U(8.W), 0xcb.U(8.W), 0x2d.U(8.W), 0xa3.U(8.W),
    0x80.U(8.W), 0x30.U(8.W), 0xf2.U(8.W), 0x0c.U(8.W),
    0x6a.U(8.W), 0x42.U(8.W), 0xb7.U(8.W), 0x3b.U(8.W),
    0xbe.U(8.W), 0xac.U(8.W), 0x01.U(8.W), 0xfa.U(8.W)
  )).asUInt

  private val rss_len: Int = rss_key.widthOption.get

  def ToeplitzHash(array: UInt) = {
    require(array.widthOption.get > 0)
    (0 until array.widthOption.get).foldLeft(0.U(hashBits.W)) { (p, k) => 
      p ^ Mux (((array >> k) & 1.U) === 0.U, 0.U, 
        rss_key(rss_len - k - 1, rss_len - k - hashBits - 1))
    }
  }

  val hash_array = Cat(io.in.bits.src_ip, io.in.bits.dst_ip, 
    io.in.bits.src_port, io.in.bits.dst_port, io.in.bits.protocol)
  val hash_num = ToeplitzHash(hash_array)

  val next = RegInit(0.U(log2Ceil(nCores).W))
  val indirection_table = RegInit(VecInit(Seq.fill(entries)(0.U(log2Ceil(nCores).W))))
  val indirection_flag  = RegInit(VecInit(Seq.fill(entries)(0.U(8.W))))
  val lsb = hash_num(log2Ceil(entries) + log2Ceil(nCores) - 1, 0)
  indirection_flag(lsb) := indirection_flag(lsb) + 1.U

  when (io.in.valid) { next := next + 1.U }

  io.out.valid := io.in.valid
  when (indirection_flag(lsb) === 0.U) {
    indirection_table(lsb) := next
  }
  io.out.bits := Mux (indirection_flag(lsb) === 0.U, indirection_table(lsb), next)
}

/**
 * identify IP address and port number of packets
 * then implement hash function
 * @nCores Number of cores
 */
class RSS(nCores: Int) extends Module 
  with NetworkEndianHelpers {
  val io = IO(new Bundle {
    val in = Flipped(Decoupled(new StreamChannel(NET_IF_WIDTH)))
    // selected core to send packets to
    val hash_core = Valid(UInt(log2Ceil(nCores).W))
  })
  io.in.ready := true.B
  /*
   * identify IP address and port number of packets
   */

  // reservation need to save the header until identifying the protocol, ip and port  
  val resevationBytes = ETH_HEAD_BYTES + IPV4_HEAD_BYTES 
    + IPV4_OPTIONAL_MAX_BYTES + max(TCP_HEAD_BYTES, UDP_HEAD_BYTES)

  val slots = resevationBytes / NET_IF_BYTES
  val ethSlots = ETH_HEAD_BYTES / NET_IF_BYTES
  val ipSlots = IPV4_HEAD_BYTES / NET_IF_BYTES
  val tcpSlots = TCP_HEAD_BYTES / NET_IF_BYTES
  val udpSlots = UDP_HEAD_BYTES / NET_IF_BYTES

  // save eth header only
  val ethReserve = Reg(Vec(slots, UInt(NET_IF_WIDTH.W)))
  // save ip header only
  val ipReserve = Reg(Vec(ipSlots, UInt(NET_IF_WIDTH.W)))
  // save tcp header only
  val tcpReserve = Reg(Vec(tcpSlots, UInt(NET_IF_WIDTH.W)))
  // save udp header only
  val udpReserve = Reg(Vec(udpSlots, UInt(NET_IF_WIDTH.W)))

  val ethHeader = ethReserve.asTypeOf(new EthernetHeader)
  val ipHeader = ipReserve.asTypeOf(new IPv4Header)
  val tcpHeader = tcpReserve.asTypeOf(new TCPHeader)
  val udpHeader = udpReserve.asTypeOf(new UDPHeader)

  val s_head :: s_eth :: s_ip :: s_ip_opt :: s_tail :: Nil = Enum(5)
  val state = RegInit(s_head)

  val reserveIdx = RegInit(0.U(log2Ceil(slots).W))
  val preHeader = RegInit(0.U(log2Ceil(slots).W))

  val isIP  = ethHeader.ethType === IPV4_ETHTYPE.U
  val isTCP = isIP && ipHeader.protocol === TCP_PROTOCOL.U
  val isUDP = isIP && ipHeader.protocol === UDP_PROTOCOL.U

  val ipv4_header_bytes = ipHeader.ihl
  val src_ip = ntohl(ipHeader.source_ip)
  val dst_ip = ntohl(ipHeader.dest_ip)
  val protocol = ipHeader.protocol // tcp or udp
  val src_port = Mux(isTCP, tcpHeader.source_port, udpHeader.source_port)
  val dst_port = Mux(isTCP, tcpHeader.dest_port, udpHeader.dest_port)

  // time to hash when the datagram 1) is not ip, 2) is not tcp or udp
  val toEnd = (state === s_eth && !isIP) || (state === s_ip && !isTCP && !isUDP) || (state === s_tail)

  val hash = Module(new Hash(hashBits = 32, nCores = nCores))
  hash.io.in.bits.src_ip := src_ip
  hash.io.in.bits.dst_ip := dst_ip
  hash.io.in.bits.src_port := src_port
  hash.io.in.bits.dst_port := dst_port
  hash.io.in.bits.protocol := protocol
  hash.io.in.valid := toEnd

  io.hash_core.valid := hash.io.out.valid
  io.hash_core.bits := hash.io.out.bits

  /*
   * State Machine
   */

  when (io.in.fire) {
    val data = io.in.bits.data

    switch (state) {

      is (s_head) {
        ethReserve(reserveIdx) := data
        reserveIdx := reserveIdx + 1.U
        when (reserveIdx === (ethSlots - 1).U) { 
          state := s_eth 
          preHeader := preHeader + ethSlots.U
        }
      }

      is (s_eth) {
        ipReserve(reserveIdx - preHeader) := data
        reserveIdx := reserveIdx + 1.U
        when (reserveIdx === preHeader + IPV4_HEAD_BYTES.U - 1.U) { 
          state := s_ip 
          preHeader := preHeader + IPV4_HEAD_BYTES.U
        }
      }

      is (s_ip) {
        reserveIdx := reserveIdx + 1.U

        // TODO(qxh): This may be a bug: what happens when ipv4_header_bytes === IPV4_HEAD_BYTES?
        when (reserveIdx === preHeader - IPV4_HEAD_BYTES.U + ipv4_header_bytes - 1.U) { 
          state := s_ip_opt 
          preHeader := preHeader - IPV4_HEAD_BYTES.U + ipv4_header_bytes
        }
      }

      is (s_ip_opt) {
        reserveIdx := reserveIdx + 1.U
        tcpReserve(reserveIdx - preHeader) := data
        udpReserve(reserveIdx - preHeader) := data

        when (reserveIdx === preHeader +
          Mux(isTCP, TCP_HEAD_BYTES.U, UDP_HEAD_BYTES.U) - 1.U) {
          state := s_tail
        }
      }
    }

    when (io.in.bits.last) {
      state := s_head
      reserveIdx := 0.U
    }
  }
}