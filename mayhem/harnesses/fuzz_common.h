// Shared helpers for the ZLMediaKit fuzz harnesses (mayhem/ layer, not upstream code).
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include "Common/MediaSink.h"
#include "Extension/Track.h"
#include "Extension/Frame.h"
#include "Util/logger.h"

namespace fuzz {

// A MediaSinkInterface that keeps the tracks it is given and routes every frame back into the
// matching track, so the codec tracks parse their parameter sets (SPS/PPS/VPS, AAC config, ...)
// exactly as a real MediaSink does before muxing. Created fresh for every input.
class TrackSink : public mediakit::MediaSinkInterface {
public:
    bool addTrack(const mediakit::Track::Ptr &track) override {
        if (!track || _tracks.size() >= 16) {
            return false;
        }
        _tracks.push_back(track);
        return true;
    }
    void addTrackCompleted() override {}
    void resetTracks() override { _tracks.clear(); }
    bool inputFrame(const mediakit::Frame::Ptr &frame) override {
        if (!frame) {
            return false;
        }
        for (auto &track : _tracks) {
            if (track->getCodecId() == frame->getCodecId()) {
                track->inputFrame(frame);
            }
        }
        _bytes += frame->size();
        return true;
    }
    // Query the derived properties of every track (what MediaSource registration would do).
    void inspect() {
        for (auto &track : _tracks) {
            (void)track->ready();
            (void)track->getBitRate();
            auto video = std::dynamic_pointer_cast<mediakit::VideoTrack>(track);
            if (video) {
                (void)video->getVideoWidth();
                (void)video->getVideoHeight();
                (void)video->getVideoFps();
            }
            auto audio = std::dynamic_pointer_cast<mediakit::AudioTrack>(track);
            if (audio) {
                (void)audio->getAudioSampleRate();
                (void)audio->getAudioChannel();
            }
            try {
                auto sdp = track->getSdp(96);
                if (sdp) {
                    (void)sdp->getSdp();
                }
            } catch (std::exception &) {
            }
        }
    }
    size_t _bytes = 0;
    std::vector<mediakit::Track::Ptr> _tracks;
};

// Consumes the input front to back, the way a byte-oriented fuzzed-data provider does.
class Reader {
public:
    Reader(const uint8_t *data, size_t size) : _p(data), _n(size) {}
    size_t remain() const { return _n; }
    uint8_t u8() {
        if (!_n) return 0;
        --_n;
        return *_p++;
    }
    uint16_t u16() { uint16_t v = u8(); return (uint16_t)((v << 8) | u8()); }
    uint32_t u32() { uint32_t v = u16(); return (v << 16) | u16(); }
    // Take up to len bytes.
    std::string take(size_t len) {
        if (len > _n) len = _n;
        std::string out((const char *)_p, len);
        _p += len;
        _n -= len;
        return out;
    }
    std::string rest() { return take(_n); }

private:
    const uint8_t *_p;
    size_t _n;
};

// Socket data reaches ZLMediaKit's splitters in ZLToolKit buffers, which always reserve one
// writable byte past the payload (HttpRequestSplitter::input temporarily NUL-terminates
// data[len] relying on it, see the comment there). Give each input the same layout: a private
// copy with one spare byte.
inline std::vector<char> socketCopy(const uint8_t *data, size_t size) {
    std::vector<char> buf(size + 1, 0);
    if (size) {
        memcpy(buf.data(), data, size);
    }
    return buf;
}

// ZLToolKit's Logger is not thread-safe without a LogWriter: Logger::write() then calls
// writeChannels() on the logging thread, which assigns the unguarded _last_log. ZLMediaKit's real
// entry points (server/main.cpp, api/source/mk_common.cpp) always install a writer before anything
// logs, so all writes reach the logger from one thread. The harnesses log from the main thread
// and from ZLToolKit's millisecond stamp thread ("Stamp thread started"), so they need one too.
// Install a writer that drops every record (the harnesses have no log channel anyway): race-free,
// with no extra thread or log I/O. Read-only after LLVMFuzzerInitialize.
class DropLogWriter : public toolkit::LogWriter {
public:
    void write(const toolkit::LogContextPtr &, toolkit::Logger &) override {}
};

} // namespace fuzz

// Every harness binary includes this header exactly once.
extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    toolkit::Logger::Instance().setWriter(std::make_shared<fuzz::DropLogWriter>());
    return 0;
}
