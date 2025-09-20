package icenet

import chisel3._
import chisel3.util._
import freechips.rocketchip.util._
import IceNetConsts._
import scala.math.max

class RSS extends Module {
// TODO(qxh)
}

/**
 * Retain the input stream until IP address and port number are identified
 */
class Reservation extends Module 
  with NetworkEndianHelpers {
  val io = IO(new Bundle {
    val in = Flipped(Decoupled(new StreamChannel(NET_IF_WIDTH)))
    val out = Decoupled(new StreamChannel(NET_IF_WIDTH))
    // TODO(qxh): configure this to the length of max(core numbers)
    val core = Valid(UInt(8.W))
  })

  // reservation need to save the header until identifying the protocol, ip and port  
  val resevationBytes = ETH_HEAD_BYTES + IPV4_HEAD_BYTES 
    + IPV4_OPTIONAL_MAX_BYTES + max(TCP_HEADER_BTYES, UDP_HEADER_BYTES)

  val slots = resevationBytes / NET_IF_BYTES
  val ethSlots = ETH_HEAD_BYTES / NET_IF_BYTES
  val ipSlots = IPV4_HEAD_BYTES / NET_IF_BYTES
  val tcpSlots = TCP_HEADER_BTYES / NET_IF_BYTES
  val udpSlots = UDP_HEADER_BYTES / NET_IF_BYTES

  // save eth, ip, xdp datagrams
  val reserve = Reg(Vec(slots, UInt(NET_IF_WIDTH.W)))
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
  val protocol = ipHeader.protocol // tcp or udp
  val src_port = when (isTCP) tcpHeader.source_port else udpHeader.source_port
  val dst_port = when (isTCP) tcpHeader.dest_port else udpHeader.dest_port

  // early exit when the datagram 1) is not ip, 2) is not tcp or udp
  val toEnd = (state === s_eth && !isIP) || (state === s_ip && !isTCP && !isUDP) || (state === s_tail)

  when (toEnd) { 
    // TODO(qxh)
  }

  when (io.in.fire) {
    val data = io.in.bits.data

    switch (state) {

      is (s_head) {
        reserve(reserveIdx) := data
        reserveIdx := reserveIdx + 1
        when (reserveIdx === (ethSlots - 1).U) { 
          state := s_eth 
          preHeader := preHeader + ethSlots.U
        }
      }

      is (s_eth) {
        reserve(reserveIdx) := data
        ipReserve(reserveIdx - preHeader) := data
        reserveIdx := reserveIdx + 1
        when (reserveIdx == preHeader + IPV4_HEAD_BYTES - 1.U) { 
          state := s_ip 
          preHeader := preHeader + IPV4_HEAD_BYTES
        }
      }

      is (s_ip) {
        reserve(reserveIdx) := data
        reserveIdx := reserveIdx + 1

        // TODO(qxh): This may be a bug: what happens when ipv4_header_bytes === IPV4_HEAD_BYTES?
        when (reserveIdx == preHeader - IPV4_HEAD_BYTES + ipv4_header_bytes - 1.U) { 
          state := s_ip_opt 
          preHeader := preHeader - IPV4_HEAD_BYTES + ipv4_header_bytes
        }
      }

      is (s_ip_opt) {
        reserve(reserveIdx) := data
        reserveIdx := reserveIdx + 1
        tcpReserve(reserveIdx - preHeader) := data
        udpReserve(reserveIdx - preHeader) := data

        when (reserveIdx === preHeader +
          Mux(isTCP, TCP_HEADER_BTYES, UDP_HEADER_BYTES) - 1.U) {
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