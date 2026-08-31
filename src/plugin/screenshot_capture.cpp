#include "plugin/screenshot_capture.hpp"

#include <hyprland/src/plugins/PluginAPI.hpp>

#define private public
#define protected public
#include <hyprland/src/Compositor.hpp>
#include <hyprland/src/desktop/Workspace.hpp>
#include <hyprland/src/desktop/state/ViewState.hpp>
#include <hyprland/src/desktop/state/WindowState.hpp>
#include <hyprland/src/desktop/view/WLSurface.hpp>
#include <hyprland/src/helpers/time/Time.hpp>
#include <hyprland/src/managers/input/InputManager.hpp>
#include <hyprland/src/render/OpenGL.hpp>
#include <hyprland/src/render/Renderer.hpp>
#include <hyprland/src/render/gl/GLFramebuffer.hpp>
#include <hyprland/src/state/MonitorState.hpp>
#undef protected
#undef private

#include <GLES2/gl2.h>
#include <drm_fourcc.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/random.h>
#include <unistd.h>
#include <vector>

using Render::GL::g_pHyprOpenGL;

namespace hypr_agent_portal {
namespace {

using Json = nlohmann::ordered_json;

constexpr int         MAX_RGBA_READBACK_DIMENSION = 32768;
constexpr std::size_t MAX_RGBA_READBACK_BYTES = 512ULL * 1024ULL * 1024ULL;
constexpr std::size_t RGBA_BYTES_PER_PIXEL = 4;

struct RgbaReadbackRegion {
    int         outputCropX = 0;
    int         outputCropTopY = 0;
    int         outputWidth = 0;
    int         outputHeight = 0;
    int         srcX = 0;
    int         srcTopY = 0;
    int         srcWidth = 0;
    int         srcHeight = 0;
    int         dstX = 0;
    int         dstY = 0;
    std::size_t outputBytes = 0;
    std::size_t sourceBytes = 0;
};

struct RgbaReadback {
    std::vector<unsigned char> pixels;
    int                        cropX = 0;
    int                        cropTopY = 0;
    int                        width = 0;
    int                        height = 0;
};

std::string pointerId(const void* ptr) {
    std::ostringstream out;
    out << std::hex << reinterpret_cast<std::uintptr_t>(ptr);
    return out.str();
}

std::string boundedString(const std::string& value, std::size_t maxBytes) {
    if (value.size() <= maxBytes)
        return value;
    return value.substr(0, maxBytes);
}

int positiveRoundedIntFromDouble(double value) {
    if (!std::isfinite(value) || value <= 0.0)
        return 1;
    if (value >= static_cast<double>(std::numeric_limits<int>::max()))
        return std::numeric_limits<int>::max();
    return std::max(1, static_cast<int>(std::lround(value)));
}

int positiveIntFromDouble(double value) {
    if (!std::isfinite(value) || value <= 0.0)
        return 1;
    if (value >= static_cast<double>(std::numeric_limits<int>::max()))
        return std::numeric_limits<int>::max();
    return std::max(1, static_cast<int>(value));
}

int clampedIntFromDouble(double value) {
    if (!std::isfinite(value))
        return value < 0.0 ? std::numeric_limits<int>::min() : std::numeric_limits<int>::max();
    if (value <= static_cast<double>(std::numeric_limits<int>::min()))
        return std::numeric_limits<int>::min();
    if (value >= static_cast<double>(std::numeric_limits<int>::max()))
        return std::numeric_limits<int>::max();
    return static_cast<int>(value);
}

int clampToFramebuffer(std::int64_t value, int framebufferExtent) {
    if (value <= 0)
        return 0;
    if (value >= framebufferExtent)
        return framebufferExtent;
    return static_cast<int>(value);
}

bool checkedRgbaByteSize(int width, int height, std::size_t& bytes) {
    bytes = 0;
    if (width <= 0 || height <= 0 || width > MAX_RGBA_READBACK_DIMENSION || height > MAX_RGBA_READBACK_DIMENSION)
        return false;

    const auto w = static_cast<std::size_t>(width);
    const auto h = static_cast<std::size_t>(height);
    if (w > std::numeric_limits<std::size_t>::max() / h)
        return false;

    const auto pixels = w * h;
    if (pixels > std::numeric_limits<std::size_t>::max() / RGBA_BYTES_PER_PIXEL)
        return false;

    bytes = pixels * RGBA_BYTES_PER_PIXEL;
    return bytes <= MAX_RGBA_READBACK_BYTES;
}

bool prepareRgbaReadbackRegion(int framebufferWidth,
                               int framebufferHeight,
                               int cropX,
                               int cropTopY,
                               int cropWidth,
                               int cropHeight,
                               RgbaReadbackRegion& region) {
    region = {};
    if (framebufferWidth <= 0 || framebufferHeight <= 0 || cropWidth <= 0 || cropHeight <= 0)
        return false;

    const auto cropLeft = static_cast<std::int64_t>(cropX);
    const auto cropTop = static_cast<std::int64_t>(cropTopY);
    const auto cropRight = cropLeft + static_cast<std::int64_t>(cropWidth);
    const auto cropBottom = cropTop + static_cast<std::int64_t>(cropHeight);

    region.srcX = clampToFramebuffer(cropLeft, framebufferWidth);
    region.srcTopY = clampToFramebuffer(cropTop, framebufferHeight);
    const int srcRight = clampToFramebuffer(cropRight, framebufferWidth);
    const int srcBottom = clampToFramebuffer(cropBottom, framebufferHeight);
    region.srcWidth = srcRight - region.srcX;
    region.srcHeight = srcBottom - region.srcTopY;

    if (!checkedRgbaByteSize(cropWidth, cropHeight, region.outputBytes))
        return false;
    if (region.srcWidth > 0 && region.srcHeight > 0 && !checkedRgbaByteSize(region.srcWidth, region.srcHeight, region.sourceBytes))
        return false;

    region.outputCropX = cropX;
    region.outputCropTopY = cropTopY;
    region.outputWidth = cropWidth;
    region.outputHeight = cropHeight;
    region.dstX = region.srcX - cropX;
    region.dstY = region.srcTopY - cropTopY;
    return true;
}

RgbaReadback readRgbaFramebufferRegion(Render::GL::CGLFramebuffer& framebuffer, int cropX, int cropTopY, int cropWidth, int cropHeight) {
    const int framebufferWidth = positiveRoundedIntFromDouble(framebuffer.m_size.x);
    const int framebufferHeight = positiveRoundedIntFromDouble(framebuffer.m_size.y);
    RgbaReadbackRegion region;
    if (!prepareRgbaReadbackRegion(framebufferWidth, framebufferHeight, cropX, cropTopY, cropWidth, cropHeight, region))
        return {};

    RgbaReadback readback;
    readback.cropX = region.outputCropX;
    readback.cropTopY = region.outputCropTopY;
    readback.width = region.outputWidth;
    readback.height = region.outputHeight;
    readback.pixels.assign(region.outputBytes, 0);

    if (region.srcWidth <= 0 || region.srcHeight <= 0)
        return readback;

    std::vector<unsigned char> rows(region.sourceBytes);
    GLint previousReadFramebuffer = 0;
    glGetIntegerv(GL_READ_FRAMEBUFFER_BINDING, &previousReadFramebuffer);
    glBindFramebuffer(GL_READ_FRAMEBUFFER, framebuffer.getFBID());
    glPixelStorei(GL_PACK_ALIGNMENT, 1);
    const int readY = framebufferHeight - region.srcTopY - region.srcHeight;
    glReadPixels(region.srcX, readY, region.srcWidth, region.srcHeight, GL_RGBA, GL_UNSIGNED_BYTE, rows.data());
    glBindFramebuffer(GL_READ_FRAMEBUFFER, previousReadFramebuffer);

    for (int y = 0; y < region.srcHeight; ++y) {
        const auto* src = rows.data() + static_cast<std::size_t>(y) * region.srcWidth * RGBA_BYTES_PER_PIXEL;
        auto*       dst = readback.pixels.data() +
            (static_cast<std::size_t>(region.dstY + y) * region.outputWidth + region.dstX) * RGBA_BYTES_PER_PIXEL;
        std::copy(src, src + static_cast<std::size_t>(region.srcWidth) * RGBA_BYTES_PER_PIXEL, dst);
    }

    return readback;
}

bool unlinkIfSameFile(const std::filesystem::path& path, dev_t device, ino_t inode) {
    struct stat current {};
    if (lstat(path.c_str(), &current) != 0)
        return errno == ENOENT;
    if (!S_ISREG(current.st_mode) || current.st_dev != device || current.st_ino != inode)
        return false;
    return unlink(path.c_str()) == 0;
}

bool writeFileExclusive(const std::filesystem::path& path, const std::vector<unsigned char>& bytes) {
    const auto native = path.string();
    const int  fd = open(native.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return false;

    struct stat info {};
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != geteuid() ||
        (info.st_mode & (S_IRWXG | S_IRWXO)) != 0 || fchmod(fd, 0600) != 0) {
        close(fd);
        if (info.st_ino != 0)
            unlinkIfSameFile(path, info.st_dev, info.st_ino);
        return false;
    }

    const auto* data = reinterpret_cast<const char*>(bytes.data());
    std::size_t written = 0;
    while (written < bytes.size()) {
        const ssize_t chunk = write(fd, data + written, bytes.size() - written);
        if (chunk < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            unlinkIfSameFile(path, info.st_dev, info.st_ino);
            return false;
        }
        if (chunk == 0) {
            close(fd);
            unlinkIfSameFile(path, info.st_dev, info.st_ino);
            return false;
        }
        written += static_cast<std::size_t>(chunk);
    }

    if (close(fd) != 0) {
        unlinkIfSameFile(path, info.st_dev, info.st_ino);
        return false;
    }
    return true;
}

void unpremultiplyAlpha(RgbaReadback& readback) {
    if (readback.pixels.empty())
        return;

    for (std::size_t i = 0; i + 3 < readback.pixels.size(); i += 4U) {
        const auto alpha = readback.pixels[i + 3];
        if (alpha == 0) {
            readback.pixels[i] = 0;
            readback.pixels[i + 1] = 0;
            readback.pixels[i + 2] = 0;
            continue;
        }
        if (alpha == 255)
            continue;

        for (int channel = 0; channel < 3; ++channel) {
            const int straight = (static_cast<int>(readback.pixels[i + channel]) * 255 + alpha / 2) / alpha;
            readback.pixels[i + channel] = static_cast<unsigned char>(std::min(255, straight));
        }
    }
}

class FullSurfaceVisibleRegionOverride {
  public:
    explicit FullSurfaceVisibleRegionOverride(const PHLWINDOW& window) {
        if (!window || !window->wlSurface() || !window->wlSurface()->resource())
            return;

        window->wlSurface()->resource()->breadthfirst(
            [this](SP<CWLSurfaceResource> resource, const Vector2D&, void*) {
                auto surface = Desktop::View::CWLSurface::fromResource(resource);
                if (!surface)
                    return;

                m_records.push_back({.surface = surface, .visibleRegion = surface->m_visibleRegion});

                const int width = std::max(1, static_cast<int>(std::lround(resource->m_current.bufferSize.x > 0 ? resource->m_current.bufferSize.x :
                                                                                                                 resource->m_current.size.x)));
                const int height = std::max(1, static_cast<int>(std::lround(resource->m_current.bufferSize.y > 0 ? resource->m_current.bufferSize.y :
                                                                                                                   resource->m_current.size.y)));
                surface->m_visibleRegion = CRegion{0, 0, width, height};
            },
            nullptr);
    }

    ~FullSurfaceVisibleRegionOverride() {
        for (auto& record : m_records) {
            if (record.surface)
                record.surface->m_visibleRegion = record.visibleRegion;
        }
    }

    FullSurfaceVisibleRegionOverride(const FullSurfaceVisibleRegionOverride&) = delete;
    FullSurfaceVisibleRegionOverride& operator=(const FullSurfaceVisibleRegionOverride&) = delete;

  private:
    struct Record {
        SP<Desktop::View::CWLSurface> surface;
        CRegion                      visibleRegion;
    };

    std::vector<Record> m_records;
};

CBox renderedWindowBox(const PHLWINDOW& window, CBox box) {
    if (window->m_workspace && !window->m_pinned)
        box.translate(window->m_workspace->m_renderOffset->value());
    box.translate(window->m_floatingOffset);
    return box;
}

CBox renderedWindowMainSurfaceBox(const PHLWINDOW& window) {
    if (!window || !window->positionAnimation() || !window->sizeAnimation())
        return {};

    CBox box{window->positionAnimation()->goal().x, window->positionAnimation()->goal().y, window->sizeAnimation()->goal().x,
             window->sizeAnimation()->goal().y};
    return renderedWindowBox(window, box);
}

CBox inputWindowBox(const PHLWINDOW& window, CBox renderedBox) {
    if (window->m_workspace && !window->m_pinned)
        renderedBox.translate(-window->m_workspace->m_renderOffset->value());
    renderedBox.translate(-window->m_floatingOffset);
    return renderedBox;
}

class WindowAnimationGoalOverride {
  public:
    explicit WindowAnimationGoalOverride(const PHLWINDOW& window) : m_window(window) {
        if (!m_window || !m_window->positionAnimation() || !m_window->sizeAnimation())
            return;

        m_position = m_window->positionAnimation()->value();
        m_size = m_window->sizeAnimation()->value();
        m_active = true;
        setPositionOffset({});
    }

    void setPositionOffset(const Vector2D& offset) {
        if (!m_active || !m_window || !m_window->positionAnimation() || !m_window->sizeAnimation())
            return;

        m_window->positionAnimation()->value() = m_window->positionAnimation()->goal() + offset;
        m_window->sizeAnimation()->value() = m_window->sizeAnimation()->goal();
        m_window->updateWindowDecos();
    }

    ~WindowAnimationGoalOverride() {
        if (!m_active || !m_window || !m_window->positionAnimation() || !m_window->sizeAnimation())
            return;

        m_window->positionAnimation()->value() = m_position;
        m_window->sizeAnimation()->value() = m_size;
        m_window->updateWindowDecos();
    }

    WindowAnimationGoalOverride(const WindowAnimationGoalOverride&) = delete;
    WindowAnimationGoalOverride& operator=(const WindowAnimationGoalOverride&) = delete;

  private:
    PHLWINDOW m_window;
    Vector2D  m_position;
    Vector2D  m_size;
    bool      m_active = false;
};

bool renderMonitorArtifact(const PHLMONITOR& monitor, const Time::steady_tp& frozenTime, const std::filesystem::path& path, int& width, int& height) {
    if (!monitor || !monitor->m_activeWorkspace || !g_pHyprRenderer || !g_pHyprOpenGL)
        return false;

    width = positiveRoundedIntFromDouble(monitor->m_pixelSize.x);
    height = positiveRoundedIntFromDouble(monitor->m_pixelSize.y);
    std::size_t framebufferBytes = 0;
    if (!checkedRgbaByteSize(width, height, framebufferBytes))
        return false;

    auto       framebuffer = makeShared<Render::GL::CGLFramebuffer>();
    const auto   drmFormat = monitor->m_output && monitor->m_output->state ? monitor->m_output->state->state().drmFormat : DRM_FORMAT_ABGR8888;
    if (!framebuffer->alloc(width, height, drmFormat) && !framebuffer->alloc(width, height, DRM_FORMAT_ABGR8888))
        return false;

    const bool previousBlockFeedback = g_pHyprRenderer->m_bBlockSurfaceFeedback;
    const bool previousBlockShader = g_pHyprRenderer->m_renderData.blockScreenShader;
    CRegion    fakeDamage{0, 0, width, height};

    g_pHyprOpenGL->makeEGLCurrent();
    g_pHyprRenderer->m_bBlockSurfaceFeedback = true;
    if (!g_pHyprRenderer->beginRender(monitor, fakeDamage, Render::RENDER_MODE_FULL_FAKE, nullptr, framebuffer)) {
        g_pHyprRenderer->m_bBlockSurfaceFeedback = previousBlockFeedback;
        return false;
    }

    glClearColor(0.F, 0.F, 0.F, 1.F);
    glClear(GL_COLOR_BUFFER_BIT);
    g_pHyprRenderer->renderWorkspace(monitor, monitor->m_activeWorkspace, frozenTime, CBox{0, 0, static_cast<double>(width), static_cast<double>(height)});
    g_pHyprRenderer->m_renderData.blockScreenShader = true;
    g_pHyprRenderer->endRender();
    g_pHyprRenderer->m_renderData.blockScreenShader = previousBlockShader;
    g_pHyprRenderer->m_bBlockSurfaceFeedback = previousBlockFeedback;

    const auto readback = readRgbaFramebufferRegion(*framebuffer, 0, 0, width, height);
    return !readback.pixels.empty() && writeFileExclusive(path, readback.pixels);
}

bool renderWindowArtifact(const PHLWINDOW& window,
                          const PHLMONITOR& monitor,
                          const Time::steady_tp& frozenTime,
                          const std::filesystem::path& path,
                          int& width,
                          int& height,
                          CBox& artifactBox) {
    if (!window || !monitor || !g_pHyprRenderer || !g_pHyprOpenGL)
        return false;

    WindowAnimationGoalOverride windowGoal(window);
    const CBox mainBox = renderedWindowMainSurfaceBox(window);
    CBox sourceCropBox = mainBox.copy().translate(-monitor->m_position).scale(monitor->m_scale <= 0.0 ? 1.0 : monitor->m_scale).round();
    width = positiveIntFromDouble(sourceCropBox.w);
    height = positiveIntFromDouble(sourceCropBox.h);

    const int framebufferWidth = positiveRoundedIntFromDouble(monitor->m_pixelSize.x);
    const int framebufferHeight = positiveRoundedIntFromDouble(monitor->m_pixelSize.y);
    std::size_t framebufferBytes = 0;
    std::size_t cropBytes = 0;
    if (!checkedRgbaByteSize(framebufferWidth, framebufferHeight, framebufferBytes) || !checkedRgbaByteSize(width, height, cropBytes))
        return false;

    const double scale = monitor->m_scale <= 0.0 ? 1.0 : monitor->m_scale;
    const int targetCropX = width < framebufferWidth ? (framebufferWidth - width) / 2 : 0;
    const int targetCropY = height < framebufferHeight ? (framebufferHeight - height) / 2 : 0;
    const Vector2D renderOffset = monitor->m_position + Vector2D{targetCropX / scale, targetCropY / scale} - mainBox.pos();
    windowGoal.setPositionOffset(renderOffset);
    CBox renderCropBox = mainBox.copy().translate(renderOffset).translate(-monitor->m_position).scale(scale).round();

    auto       framebuffer = makeShared<Render::GL::CGLFramebuffer>();
    const auto   drmFormat = monitor->m_output && monitor->m_output->state ? monitor->m_output->state->state().drmFormat : DRM_FORMAT_ABGR8888;
    if (!framebuffer->alloc(framebufferWidth, framebufferHeight, DRM_FORMAT_ABGR8888) && !framebuffer->alloc(framebufferWidth, framebufferHeight, drmFormat))
        return false;

    const bool previousBlockFeedback = g_pHyprRenderer->m_bBlockSurfaceFeedback;
    const bool previousBlockShader = g_pHyprRenderer->m_renderData.blockScreenShader;
    const bool previousRenderingSnapshot = g_pHyprRenderer->m_bRenderingSnapshot;
    CRegion    fakeDamage{0, 0, framebufferWidth, framebufferHeight};

    g_pHyprOpenGL->makeEGLCurrent();
    g_pHyprRenderer->m_bBlockSurfaceFeedback = true;
    if (!g_pHyprRenderer->beginRender(monitor, fakeDamage, Render::RENDER_MODE_FULL_FAKE, nullptr, framebuffer)) {
        g_pHyprRenderer->m_bBlockSurfaceFeedback = previousBlockFeedback;
        return false;
    }

    g_pHyprRenderer->m_bRenderingSnapshot = true;
    {
        FullSurfaceVisibleRegionOverride fullVisibleRegion(window);
        glClearColor(0.F, 0.F, 0.F, 0.F);
        glClear(GL_COLOR_BUFFER_BIT);
        g_pHyprRenderer->renderWindow(window, monitor, frozenTime, false, Render::RENDER_PASS_ALL, false, false);
    }
    g_pHyprRenderer->m_bRenderingSnapshot = previousRenderingSnapshot;

    g_pHyprRenderer->m_renderData.blockScreenShader = true;
    g_pHyprRenderer->endRender();
    g_pHyprRenderer->m_renderData.blockScreenShader = previousBlockShader;
    g_pHyprRenderer->m_bBlockSurfaceFeedback = previousBlockFeedback;

    const int cropX = clampedIntFromDouble(renderCropBox.x);
    const int cropY = clampedIntFromDouble(renderCropBox.y);
    auto      readback = readRgbaFramebufferRegion(*framebuffer, cropX, cropY, width, height);
    if (readback.pixels.empty())
        return false;

    width = readback.width;
    height = readback.height;
    artifactBox = CBox{mainBox.x + (readback.cropX - cropX) / scale, mainBox.y + (readback.cropTopY - cropY) / scale, width / scale, height / scale};

    unpremultiplyAlpha(readback);
    return writeFileExclusive(path, readback.pixels);
}

Json rectJson(const CBox& box) {
    return Json{{"x", box.x}, {"y", box.y}, {"width", box.w}, {"height", box.h}};
}

Json monitorRectJson(const PHLMONITOR& monitor) {
    return Json{{"x", monitor->m_position.x}, {"y", monitor->m_position.y}, {"width", monitor->m_size.x}, {"height", monitor->m_size.y}};
}

bool isWindowVisible(const PHLWINDOW& window) {
    if (!window || !window->m_isMapped || window->isHidden() || !window->m_workspace)
        return false;
    if (g_pHyprRenderer)
        return g_pHyprRenderer->shouldRenderWindow(window);
    return window->m_pinned || window->m_workspace->isVisible();
}

Json windowJson(const PHLWINDOW& window) {
    CBox visible = window->geometricBox(Desktop::View::IGeometric::GEOMETRIC_GOAL);
    const auto full = window->getFullWindowBoundingBox();
    const auto transientFor = window->m_isX11 ? window->x11Parent() : PHLWINDOW{};

    return Json{
        {"address", "0x" + pointerId(window.get())},
        {"title", boundedString(window->m_title, 4096)},
        {"class", boundedString(window->m_class, 4096)},
        {"initialClass", boundedString(window->m_initialClass, 4096)},
        {"pid", window->getPID()},
        {"transientFor", transientFor ? Json("0x" + pointerId(transientFor.get())) : Json(nullptr)},
        {"visible", isWindowVisible(window)},
        {"xwayland", window->m_isX11},
        {"geometry", rectJson(visible)},
        {"fullGeometry", rectJson(full)},
    };
}

std::string sessionId() {
    std::array<unsigned char, 16> randomBytes {};
    std::size_t                   offset = 0;
    while (offset < randomBytes.size()) {
        const auto count = getrandom(randomBytes.data() + offset, randomBytes.size() - offset, 0);
        if (count > 0) {
            offset += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR)
            continue;
        break;
    }

    static std::atomic_uint64_t fallbackCounter = 0;
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    if (offset == randomBytes.size()) {
        for (const auto byte : randomBytes)
            out << std::setw(2) << static_cast<unsigned int>(byte);
    } else {
        out << Time::millis(Time::steadyNow()) << '-' << getpid() << '-' << fallbackCounter.fetch_add(1, std::memory_order_relaxed);
    }
    return out.str();
}

int openPrivateArtifactParent(const std::filesystem::path& path, std::string& error) {
    struct stat before {};
    if (lstat(path.c_str(), &before) != 0) {
        error = "screenshot output directory is unavailable: " + std::string(strerror(errno));
        return -1;
    }
    if (S_ISLNK(before.st_mode) || !S_ISDIR(before.st_mode) || before.st_uid != geteuid() || (before.st_mode & 0777) != 0700) {
        error = "screenshot output directory must be a non-symlink directory owned by the compositor uid with mode 0700";
        return -1;
    }
    const int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        error = "failed to securely open screenshot output directory: " + std::string(strerror(errno));
        return -1;
    }
    struct stat opened {};
    if (fstat(fd, &opened) != 0 || !S_ISDIR(opened.st_mode) || opened.st_uid != geteuid() || (opened.st_mode & 0777) != 0700 ||
        opened.st_dev != before.st_dev || opened.st_ino != before.st_ino) {
        close(fd);
        error = "screenshot output directory changed during validation";
        return -1;
    }
    return fd;
}

bool removeEmptyArtifactDirectoryIfSame(const std::filesystem::path& path, dev_t device, ino_t inode) {
    struct stat current {};
    if (lstat(path.c_str(), &current) != 0)
        return errno == ENOENT;
    if (!S_ISDIR(current.st_mode) || S_ISLNK(current.st_mode) || current.st_uid != geteuid() || current.st_dev != device || current.st_ino != inode)
        return false;
    return rmdir(path.c_str()) == 0;
}

class ArtifactCleanup {
  public:
    ArtifactCleanup(std::filesystem::path root, dev_t device, ino_t inode) : m_root(std::move(root)), m_device(device), m_inode(inode) {}
    ~ArtifactCleanup() {
        if (!m_active)
            return;
        for (const auto& file : m_files)
            unlinkIfSameFile(file.path, file.device, file.inode);
        removeEmptyArtifactDirectoryIfSame(m_root, m_device, m_inode);
    }
    void track(const std::filesystem::path& path) {
        struct stat info {};
        if (lstat(path.c_str(), &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == geteuid())
            m_files.push_back({path, info.st_dev, info.st_ino});
    }
    void release() { m_active = false; }

  private:
    struct TrackedFile {
        std::filesystem::path path;
        dev_t                 device = 0;
        ino_t                 inode = 0;
    };
    std::filesystem::path    m_root;
    dev_t                    m_device = 0;
    ino_t                    m_inode = 0;
    std::vector<TrackedFile> m_files;
    bool                     m_active = true;
};

} // namespace

ScreenshotResult captureScreenshotSession(const std::filesystem::path& outputJsonPath, const PHLWINDOW& targetWindow) {
    if (!g_pCompositor || !g_pHyprRenderer || !g_pHyprOpenGL)
        return {.success = false, .error = "Hyprland renderer is not ready"};
    if (outputJsonPath.empty())
        return {.success = false, .error = "missing output json path"};

    const auto parent = outputJsonPath.parent_path();
    if (parent.empty() || outputJsonPath.filename().empty() || outputJsonPath.filename() == "." || outputJsonPath.filename() == "..")
        return {.success = false, .error = "screenshot output path must name a file inside a private directory"};

    std::string parentError;
    const int   parentFd = openPrivateArtifactParent(parent, parentError);
    if (parentFd < 0)
        return {.success = false, .error = parentError};

    std::string           id;
    std::filesystem::path artifactRoot;
    int                   artifactFd = -1;
    for (int attempt = 0; attempt < 32; ++attempt) {
        id = sessionId();
        if (mkdirat(parentFd, id.c_str(), 0700) != 0) {
            if (errno == EEXIST)
                continue;
            const auto message = std::string(strerror(errno));
            close(parentFd);
            return {.success = false, .error = "failed to create artifact directory: " + message};
        }
        artifactRoot = parent / id;
        artifactFd = openat(parentFd, id.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        break;
    }
    if (artifactFd < 0) {
        close(parentFd);
        return {.success = false, .error = "failed to create a unique private artifact directory"};
    }
    struct stat artifactInfo {};
    if (fstat(artifactFd, &artifactInfo) != 0 || !S_ISDIR(artifactInfo.st_mode) || artifactInfo.st_uid != geteuid() ||
        (artifactInfo.st_mode & 0777) != 0700) {
        close(artifactFd);
        unlinkat(parentFd, id.c_str(), AT_REMOVEDIR);
        close(parentFd);
        return {.success = false, .error = "new screenshot artifact directory failed ownership or permission validation"};
    }
    close(artifactFd);
    close(parentFd);
    ArtifactCleanup artifactCleanup(artifactRoot, artifactInfo.st_dev, artifactInfo.st_ino);

    Json root;
    root["id"] = id;
    root["mode"] = targetWindow ? "window" : "monitors";
    root["monitors"] = Json::array();
    root["windows"] = Json::array();

    if (g_pInputManager) {
        const auto cursor = g_pInputManager->getMouseCoordsInternal();
        root["cursorPosition"] = Json{{"x", cursor.x}, {"y", cursor.y}};
    }

    const auto frozenTime = Time::steadyNow();
    if (targetWindow) {
        const auto window = targetWindow;
        if (!window || !window->m_isMapped)
            return {.success = false, .error = "target window not found"};

        const auto monitor = window->m_monitor.lock();
        if (!monitor)
            return {.success = false, .error = "target window has no monitor"};

        int        width = 0;
        int        height = 0;
        CBox       artifactBox;
        const auto artifactPath = artifactRoot / ("window-" + pointerId(window.get()) + ".rgba");
        if (!renderWindowArtifact(window, monitor, frozenTime, artifactPath, width, height, artifactBox))
            return {.success = false, .error = "failed to render target window"};
        artifactCleanup.track(artifactPath);

        const double scale = monitor->m_scale <= 0.0 ? 1.0 : monitor->m_scale;
        root["target"] = windowJson(window);
        root["target"]["artifactPath"] = artifactPath.string();
        root["target"]["artifactWidth"] = width;
        root["target"]["artifactHeight"] = height;
        root["target"]["artifactTopDown"] = true;
        const auto inputBox = inputWindowBox(window, artifactBox);
        root["target"]["artifactGeometry"] = rectJson(artifactBox);
        root["target"]["inputGeometry"] = rectJson(inputBox);
        root["monitors"].push_back(Json{
            {"name", "window:" + boundedString(window->m_title, 4096)},
            {"geometry", rectJson(inputBox)},
            {"scale", scale},
            {"transform", 0},
            {"artifactPath", artifactPath.string()},
            {"artifactWidth", width},
            {"artifactHeight", height},
            {"artifactTopDown", true},
        });
        root["windows"].push_back(windowJson(window));

        const auto serialized = root.dump(2, ' ', false, Json::error_handler_t::replace);
        std::vector<unsigned char> bytes(serialized.begin(), serialized.end());
        if (!writeFileExclusive(outputJsonPath, bytes))
            return {.success = false, .error = "failed to write output json"};

        artifactCleanup.release();
        return {.success = true};
    }

    int        monitorIndex = 0;
    for (const auto& monitor : State::monitorState()->monitors()) {
        if (!monitor)
            continue;

        int        width = 0;
        int        height = 0;
        const auto artifactPath = artifactRoot / ("monitor-" + std::to_string(monitorIndex) + ".rgba");
        const bool rendered = renderMonitorArtifact(monitor, frozenTime, artifactPath, width, height);
        if (rendered)
            artifactCleanup.track(artifactPath);

        root["monitors"].push_back(Json{
            {"name", boundedString(monitor->m_name, 4096)},
            {"geometry", monitorRectJson(monitor)},
            {"scale", monitor->m_scale},
            {"transform", static_cast<int>(monitor->m_transform)},
            {"artifactPath", rendered ? artifactPath.string() : ""},
            {"artifactWidth", rendered ? width : 0},
            {"artifactHeight", rendered ? height : 0},
            {"artifactTopDown", true},
        });
        ++monitorIndex;
    }

    for (const auto& window : Desktop::windowState()->windows()) {
        if (!window || !window->m_isMapped)
            continue;
        root["windows"].push_back(windowJson(window));
    }

    const auto serialized = root.dump(2, ' ', false, Json::error_handler_t::replace);
    std::vector<unsigned char> bytes(serialized.begin(), serialized.end());
    if (!writeFileExclusive(outputJsonPath, bytes))
        return {.success = false, .error = "failed to write output json"};

    artifactCleanup.release();
    return {.success = true};
}

} // namespace hypr_agent_portal
