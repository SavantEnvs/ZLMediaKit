// WebRTC offers (WHIP/WHEP and the /index/api/webrtc HTTP endpoint take an SDP from the browser):
// RtcSession::loadFrom (session + media sections, ~20 a= attribute parsers: rtpmap/fmtp/rtcp-fb,
// ssrc/ssrc-group, simulcast/rid, extmap, candidate, fingerprint, setup, sctp), checkValid,
// re-serialization, and answer negotiation with RtcConfigure::createAnswer.
#include "fuzz_common.h"
#include "webrtc/Sdp.h"

using namespace mediakit;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string sdp((const char *)data, size);
    try {
        RtcSession offer;
        offer.loadFrom(sdp);
        (void)offer.toString();
        offer.checkValid();
        (void)offer.toRtspSdp();
        (void)offer.supportSimulcast();
        (void)offer.isOnlyDatachannel();

        SdpAttrFingerprint fingerprint;
        fingerprint.algorithm = "sha-256";
        fingerprint.hash = "FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:"
                           "FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00";
        RtcConfigure configure;
        configure.setDefaultSetting("fuzzUfrag", "fuzzPassword1234567890", RtpDirection::recvonly, fingerprint);
        auto answer = configure.createAnswer(offer);
        if (answer) {
            (void)answer->toString();
            answer->checkValid();
        }
    } catch (std::exception &) {
        // Invalid offers are rejected by throwing; the HTTP API answers with an error.
    }
    return 0;
}
