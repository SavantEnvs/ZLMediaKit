// AMF0 / AMF3 decoder (RTMP command and data messages, FLV script tags): AMFDecoder::load<AMFValue>
// with nesting-depth limit, amfLoadLeadingString, then re-encode the decoded values with AMFEncoder.
#include "fuzz_common.h"
#include "Rtmp/amf.h"
#include "Util/util.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return -1;
    }
    // Byte 0 picks how the message is decoded: AMF0 vs AMF3 (MSG_CMD vs MSG_CMD3 in RtmpSession)
    // and whether it starts with a leading command/notify name (amfLoadLeadingString).
    uint8_t mode = data[0];
    toolkit::BufferLikeString buf(std::string((const char *)data + 1, size - 1));
    try {
        AMFDecoder dec(buf, 0, (mode & 1) ? 3 : 0);
        if (mode & 2) {
            (void)amfLoadLeadingString(dec);
        }
        AMFEncoder enc;
        for (int i = 0; i < 64 && dec.remain(); ++i) {
            AMFValue val = dec.load<AMFValue>();
            (void)val.to_string();
            enc << val;
        }
        // Round-trip what was encoded.
        toolkit::BufferLikeString again(enc.data());
        AMFDecoder dec2(again, 0);
        for (int i = 0; i < 64 && dec2.remain(); ++i) {
            (void)dec2.load<AMFValue>();
        }
    } catch (std::exception &) {
    }
    return 0;
}
