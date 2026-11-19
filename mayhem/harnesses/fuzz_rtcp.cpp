// Compound RTCP packets (RTSP interleaved / UDP RTCP ports, WebRTC): RtcpHeader::loadFromBytes
// (header validation + network-to-host conversion of SR/RR/SDES/BYE/APP/RTPFB/PSFB/XR), dumpString,
// and the per-type parsing a receiver does: report blocks, BYE SSRCs, and the feedback FCIs
// (NACK, TWCC, REMB, SLI, FIR, TMMBR) via RtcpFB::getFci.
#include "fuzz_common.h"
#include "Rtcp/Rtcp.h"
#include "Rtcp/RtcpFCI.h"

using namespace mediakit;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // loadFromBytes converts in place, so work on a private exact-size heap copy.
    std::vector<char> buf(data, data + size);
    try {
        for (auto rtcp : RtcpHeader::loadFromBytes(buf.data(), buf.size())) {
            (void)rtcp->dumpString();
            (void)rtcp->getSize();
            (void)rtcp->getPaddingSize();
            switch ((RtcpType)rtcp->pt) {
            case RtcpType::RTCP_SR: {
                auto sr = (RtcpSR *)rtcp;
                (void)sr->getNtpUnixStampMS();
                for (auto item : sr->getItemList()) {
                    (void)item->ssrc;
                }
                break;
            }
            case RtcpType::RTCP_RR: {
                for (auto item : ((RtcpRR *)rtcp)->getItemList()) {
                    (void)item->ssrc;
                }
                break;
            }
            case RtcpType::RTCP_BYE: {
                auto bye = (RtcpBye *)rtcp;
                for (auto ssrc : bye->getSSRC()) {
                    (void)*ssrc;
                }
                (void)bye->getReason();
                break;
            }
            case RtcpType::RTCP_RTPFB: {
                auto fb = (RtcpFB *)rtcp;
                try {
                    switch ((RTPFBType)rtcp->report_count) {
                    case RTPFBType::RTCP_RTPFB_NACK: {
                        auto &fci = fb->getFci<FCI_NACK>();
                        (void)fci.getBitArray();
                        (void)fci.dumpString();
                        break;
                    }
                    case RTPFBType::RTCP_RTPFB_TWCC: {
                        auto &fci = fb->getFci<FCI_TWCC>();
                        (void)fci.getPacketChunkList(fb->getFciSize());
                        (void)fci.dumpString(fb->getFciSize());
                        break;
                    }
                    default: break;
                    }
                } catch (std::exception &) {
                }
                break;
            }
            case RtcpType::RTCP_PSFB: {
                auto fb = (RtcpFB *)rtcp;
                try {
                    switch ((PSFBType)rtcp->report_count) {
                    case PSFBType::RTCP_PSFB_REMB: {
                        auto &fci = const_cast<FCI_REMB &>(fb->getFci<FCI_REMB>());
                        (void)fci.getSSRC();
                        (void)fci.getBitRate();
                        (void)fci.dumpString();
                        break;
                    }
                    case PSFBType::RTCP_PSFB_SLI: (void)fb->getFci<FCI_SLI>().dumpString(); break;
                    case PSFBType::RTCP_PSFB_FIR: (void)fb->getFci<FCI_FIR>().dumpString(); break;
                    default: break;
                    }
                } catch (std::exception &) {
                }
                break;
            }
            default: break;
            }
        }
    } catch (std::exception &) {
    }
    return 0;
}
