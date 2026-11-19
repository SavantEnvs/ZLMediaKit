// MP4 / fMP4 files (on-demand playback of recorded or uploaded files, loadMP4File): MP4Demuxer
// openMP4 -> libmov box parsing (moov/trak/stbl/moof), track setup with codec extradata
// (avcC/hvcC/esds/...), then frame reading and seeking.
#include "fuzz_common.h"
#include "Record/MP4Demuxer.h"
#include <unistd.h>
#include <stdlib.h>

using namespace mediakit;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // MP4Demuxer only opens files by path: stage the input in a private scratch file.
    const char *tmp = getenv("TMPDIR");
    std::string path = std::string(tmp && *tmp ? tmp : "/tmp") + "/zlm_fuzz_mp4_XXXXXX";
    int fd = mkstemp(&path[0]);
    if (fd < 0) {
        return 0;
    }
    size_t off = 0;
    while (off < size) {
        ssize_t n = write(fd, data + off, size - off);
        if (n <= 0) {
            break;
        }
        off += n;
    }
    close(fd);
    {
        MP4Demuxer demuxer;
        try {
            demuxer.openMP4(path);
            for (auto &track : demuxer.getTracks(false)) {
                (void)track->getCodecName();
            }
            (void)demuxer.getDurationMS();
            bool key = false, eof = false;
            for (int i = 0; i < 256 && !eof; ++i) {
                auto frame = demuxer.readFrame(key, eof);
                if (!frame && !eof) {
                    break;
                }
            }
            demuxer.seekTo(0);
            for (int i = 0; i < 16 && !eof; ++i) {
                demuxer.readFrame(key, eof);
            }
        } catch (std::exception &) {
        }
    }
    unlink(path.c_str());
    return 0;
}
