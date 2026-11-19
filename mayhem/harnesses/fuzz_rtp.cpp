// RTP payload depacketizers, as RtspSession/RtspPlayer/WebRTC run them: an SDP (one of a fixed
// set, chosen by byte 0) sets up RtspDemuxer's video+audio tracks, then the rest of the input is a
// sequence of u16-length-prefixed RTP packets that go through RtpTrack (header parsing, SSRC/seq
// sorting in PacketSortor) and into the codec's RTP decoder (H264 STAP/FU-A, H265 AP/FU, VP8, VP9,
// AV1 OBU aggregation, JPEG, MPV, AAC AU headers, G711, Opus, MP3/MPA, L16) and its Track.
#include "fuzz_common.h"
#include "Rtsp/RtspDemuxer.h"
#include "Rtsp/RtpReceiver.h"

using namespace mediakit;

namespace {
const char *kVideo[] = {
    "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n"
    "a=fmtp:96 packetization-mode=1;profile-level-id=42C01E\r\n",
    "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\n",
        "m=video 0 RTP/AVP 96\r\na=rtpmap:96 VP8/90000\r\n",
    "m=video 0 RTP/AVP 96\r\na=rtpmap:96 VP9/90000\r\n",
    "m=video 0 RTP/AVP 96\r\na=rtpmap:96 AV1/90000\r\n",
    "m=video 0 RTP/AVP 26\r\na=rtpmap:26 JPEG/90000\r\n",
    "m=video 0 RTP/AVP 32\r\na=rtpmap:32 MPV/90000\r\n",
    "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=0\r\n",
};
const char *kAudio[] = {
    "m=audio 0 RTP/AVP 97\r\na=rtpmap:97 mpeg4-generic/44100/2\r\n"
    "a=fmtp:97 streamtype=5;profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=1210\r\n",
    "m=audio 0 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n",
    "m=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
    "m=audio 0 RTP/AVP 97\r\na=rtpmap:97 opus/48000/2\r\n",
    "m=audio 0 RTP/AVP 14\r\na=rtpmap:14 MPA/90000\r\n",
    "m=audio 0 RTP/AVP 97\r\na=rtpmap:97 MP3/90000\r\n",
    "m=audio 0 RTP/AVP 97\r\na=rtpmap:97 L16/44100/2\r\n",
    "m=audio 0 RTP/AVP 97\r\na=rtpmap:97 mpeg4-generic/48000/2\r\n"
    "a=fmtp:97 streamtype=5;profile-level-id=1;mode=AAC-lbr;sizelength=6;indexlength=2;indexdeltalength=2;config=1190\r\n",
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return -1;
    }
    fuzz::Reader in(data, size);
    uint8_t sel = in.u8();
    std::string sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=fuzz\r\nt=0 0\r\n";
    sdp += kVideo[sel & 7];
    sdp += kAudio[(sel >> 3) & 7];

    fuzz::TrackSink sink;
    RtspDemuxer demuxer;
    demuxer.setTrackListener(&sink);
    try {
        demuxer.loadSdp(sdp);
    } catch (std::exception &) {
        return 0;
    }
    SdpParser parser(sdp);
    auto video = parser.getTrack(TrackVideo);
    auto audio = parser.getTrack(TrackAudio);

    RtpTrackImp tracks[2];
    for (auto &t : tracks) {
        t.setOnSorted([&demuxer](RtpPacket::Ptr rtp) { demuxer.inputRtp(rtp); });
    }
    while (in.remain() > 2) {
        size_t len = in.u16();
        std::string pkt = in.take(len);
        if (pkt.size() < 2) {
            break;
        }
        // The RTP payload type picks the m-line, as RtspSession::getTrackIndexByPT does.
        int pt = (uint8_t)pkt[1] & 0x7F;
        bool is_video = video && pt == video->_pt;
        auto &sdp_track = is_video ? video : audio;
        if (!sdp_track) {
            continue;
        }
        try {
            tracks[is_video ? 0 : 1].inputRtp(sdp_track->_type, sdp_track->_samplerate, (uint8_t *)pkt.data(), pkt.size());
        } catch (std::exception &) {
            // RtpTrack::BadRtpException and decoder asserts: the session drops this packet.
        }
    }
    sink.inspect();
    return 0;
}
