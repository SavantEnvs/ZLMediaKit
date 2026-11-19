// SRT over UDP as SrtTransport::inputSockData sees it: a sequence of u16-length-prefixed datagrams,
// each classified data/control and parsed by the matching packet class (handshake + HSREQ /
// stream-id / key-material extensions, ACK, ACKACK, NAK loss lists, drop requests, keep-alive,
// shutdown, user-defined KM packets). Data packets go through the receive queue
// (PacketRecvQueue: cycle buffer, loss detection, drop), as handleDataPacket/handleDropReq do.
#include "fuzz_common.h"
#include "Packet.hpp"
#include "Ack.hpp"
#include "HSExt.hpp"
#include "PacketQueue.hpp"

using namespace SRT;

namespace {
template <typename P>
std::shared_ptr<P> load(uint8_t *buf, size_t len) {
    auto pkt = std::make_shared<P>();
    if (!pkt->loadFromData(buf, len)) {
        return nullptr;
    }
    return pkt;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 6) {
        return -1;
    }
    fuzz::Reader in(data, size);
    // Receive queue parameters, which a real transport takes from the peer's handshake.
    uint32_t init_seq = in.u32() & 0x7FFFFFFF;
    uint8_t flag = in.u8();
    uint32_t latency = 20 + in.u8() * 10;
    // SrtTransport::handleHandshakeConclusion: PacketRecvQueue(getPktBufSize(), init seq, latency, srt_flag).
    std::shared_ptr<PacketQueueInterface> queue = std::make_shared<PacketRecvQueue>(8192, init_seq, latency, flag);

    while (in.remain() > 2) {
        std::string dgram = in.take(in.u16());
        uint8_t *buf = (uint8_t *)&dgram[0];
        size_t len = dgram.size();
        if (!len) {
            continue;
        }
        std::list<DataPacket::Ptr> out;
        try {
            if (DataPacket::isDataPacket(buf, len)) {
                (void)DataPacket::getSocketID(buf, len);
                auto pkt = load<DataPacket>(buf, len);
                if (pkt) {
                    (void)pkt->payloadSize();
                    queue->inputPacket(pkt, out);
                    (void)queue->getLostSeq();
                    (void)queue->getExpectedSeq();
                    (void)queue->getAvailableBufferSize();
                }
                continue;
            }
            if (!ControlPacket::isControlPacket(buf, len)) {
                continue;
            }
            (void)ControlPacket::getSocketID(buf, len);
            switch (ControlPacket::getControlType(buf, len)) {
            case ControlPacket::HANDSHAKE: {
                if (!HandshakePacket::isHandshakePacket(buf, len)) {
                    break;
                }
                (void)HandshakePacket::getSynCookie(buf, len);
                auto pkt = load<HandshakePacket>(buf, len);
                if (pkt) {
                    (void)pkt->dump();
                    (void)pkt->isReject();
                    for (auto &ext : pkt->ext_list) {
                        (void)ext->dump();
                    }
                }
                break;
            }
            case ControlPacket::KEEPALIVE: load<KeepLivePacket>(buf, len); break;
            case ControlPacket::ACK: {
                auto pkt = load<ACKPacket>(buf, len);
                if (pkt) {
                    (void)pkt->dump();
                }
                break;
            }
            case ControlPacket::ACKACK: load<ACKACKPacket>(buf, len); break;
            case ControlPacket::NAK: {
                auto pkt = load<NAKPacket>(buf, len);
                if (pkt) {
                    (void)pkt->dump();
                }
                break;
            }
            case ControlPacket::SHUTDOWN: load<ShutDownPacket>(buf, len); break;
            case ControlPacket::DROPREQ: {
                auto pkt = load<MsgDropReqPacket>(buf, len);
                if (pkt) {
                    queue->drop(pkt->first_pkt_seq_num, pkt->last_pkt_seq_num, out);
                }
                break;
            }
            case ControlPacket::USERDEFINEDTYPE: {
                auto sub = ControlPacket::getSubType(buf, len);
                if (sub == HSExt::SRT_CMD_KMREQ || sub == HSExt::SRT_CMD_KMRSP) {
                    load<KeyMaterialPacket>(buf, len);
                }
                break;
            }
            default: break;
            }
        } catch (std::exception &) {
        }
    }
    (void)queue->dump();
    return 0;
}
