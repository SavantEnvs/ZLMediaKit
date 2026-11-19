// STUN/TURN messages (every UDP datagram the WebRTC ICE agent receives on its port):
// StunPacket::parse (header, attributes: XOR-MAPPED-ADDRESS, USERNAME, ERROR-CODE, PRIORITY,
// MESSAGE-INTEGRITY, FINGERPRINT, ...), dumpString, short-term credential checking
// (HMAC-SHA1 message integrity) and building the success response, as IceTransport does.
#include "fuzz_common.h"
#include "webrtc/StunPacket.hpp"

using namespace RTC;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    try {
        if (!StunPacket::isStun(data, size)) {
            return 0;
        }
        (void)StunPacket::getClass(data, size);
        (void)StunPacket::getMethod(data, size);
        auto packet = StunPacket::parse(data, size);
        if (!packet) {
            return 0;
        }
        (void)packet->dumpString(true);
        (void)packet->getUsername();
        (void)packet->getPriority();
        (void)packet->getErrorCode();
        (void)packet->checkAuthentication("fuzzUfrag", "fuzzPassword1234567890");
        if (packet->getClass() == StunPacket::Class::REQUEST) {
            auto response = packet->createSuccessResponse();
            if (response) {
                response->serialize();
            }
        }
    } catch (std::exception &) {
    }
    return 0;
}
