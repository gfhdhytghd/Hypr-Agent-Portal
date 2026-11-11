#include "plugin/screenshot_readback.hpp"

#include <array>
#include <cassert>
#include <iostream>
#include <vector>

using namespace hypr_agent_portal;

int main() {
    // Asymmetric 3x2 panel transformed to the logical framebuffer by FULL_FAKE.
    // The portal must preserve these pixels, including reflections, without
    // applying the output transform a second time.
    constexpr int logical[8][6] = {
        {1, 2, 3, 4, 5, 6}, {4, 1, 5, 2, 6, 3},
        {6, 5, 4, 3, 2, 1}, {3, 6, 2, 5, 1, 4},
        {3, 2, 1, 6, 5, 4}, {1, 4, 2, 5, 3, 6},
        {4, 5, 6, 1, 2, 3}, {6, 3, 5, 2, 4, 1},
    };
    for (int transform = 0; transform < 8; ++transform) {
        const int width = transform % 2 ? 2 : 3;
        const int height = transform % 2 ? 3 : 2;
        // Full monitor, off-center window, partial and entirely outside crops.
        for (const auto crop : {std::array{0, 0, width, height}, {0, 0, 2, 1},
                                {1, 1, 1, 1}, {-1, -1, 3, 3},
                                {width - 1, height - 1, 3, 2}, {width + 2, 0, 2, 1}}) {
            RgbaReadbackRegion region;
            assert(prepareRgbaReadbackRegion(width, height, crop[0], crop[1], crop[2], crop[3], region));
            assert(region.outputCropX == crop[0] && region.outputCropTopY == crop[1]);
            assert(region.outputWidth == crop[2] && region.outputHeight == crop[3]);
            std::vector<unsigned char> output(region.outputBytes, 0);
            // Model glReadPixels(srcX, srcTopY, ...) and row copying. GL row 0
            // is the logical top for this export projection, even on transform 0.
            for (int y = 0; y < region.srcHeight; ++y)
                for (int x = 0; x < region.srcWidth; ++x)
                    for (int channel = 0; channel < 4; ++channel)
                        output[((region.dstY + y) * region.outputWidth + region.dstX + x) * 4 + channel] =
                            logical[transform][(region.srcTopY + y) * width + region.srcX + x] * 10 + channel;
            for (int y = 0; y < crop[3]; ++y)
                for (int x = 0; x < crop[2]; ++x) {
                    const int sx = crop[0] + x, sy = crop[1] + y;
                    for (int channel = 0; channel < 4; ++channel) {
                        const int expected = sx >= 0 && sy >= 0 && sx < width && sy < height
                            ? logical[transform][sy * width + sx] * 10 + channel : 0;
                        assert(output[(y * crop[2] + x) * 4 + channel] == expected);
                    }
                }
        }
    }
    RgbaReadbackRegion region;
    assert(!prepareRgbaReadbackRegion(3, 2, 0, 0, 0, 1, region));
    assert(!prepareRgbaReadbackRegion(3, 2, 0, 0, 32769, 1, region));
    assert(!prepareRgbaReadbackRegion(3, 2, 0, 0, 32768, 32768, region));
    std::cout << "all 8 transforms: logical monitor pixels, window crops and padding passed\n";
}
