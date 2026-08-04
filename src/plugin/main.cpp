#include "plugin/screenshot_capture.hpp"

#include <hyprland/src/config/ConfigManager.hpp>
#include <hyprland/src/config/lua/bindings/LuaBindingsInternal.hpp>
#include <hyprland/src/plugins/PluginAPI.hpp>
#include <hyprland/src/config/values/ConfigValues.hpp>

#define private public
#include <hyprland/src/Compositor.hpp>
#include <hyprland/src/desktop/Workspace.hpp>
#include <hyprland/src/desktop/state/GlobalWindowController.hpp>
#include <hyprland/src/desktop/state/ViewState.hpp>
#include <hyprland/src/desktop/state/WindowState.hpp>
#include <hyprland/src/desktop/view/Window.hpp>
#include <hyprland/src/event/EventBus.hpp>
#include <hyprland/src/helpers/time/Time.hpp>
#include <hyprland/src/managers/input/InputManager.hpp>
#include <hyprland/src/managers/SeatManager.hpp>
#include <hyprland/src/managers/eventLoop/EventLoopManager.hpp>
#include <hyprland/src/managers/eventLoop/EventLoopTimer.hpp>
#include <hyprland/src/protocols/core/DataDevice.hpp>
#include <hyprland/src/protocols/core/Seat.hpp>
#include <hyprland/src/render/Renderer.hpp>
#include <hyprland/src/render/Texture.hpp>
#include <hyprland/src/render/gl/GLTexture.hpp>
#include <hyprland/src/render/pass/TexPassElement.hpp>
#include <hyprland/src/state/MonitorState.hpp>
#include <hyprland/src/xwayland/XSurface.hpp>
#include <hyprland/src/xwayland/XWayland.hpp>
#undef private

extern "C" {
#include <lauxlib.h>
#include <lua.h>
}
#include <hyprutils/signal/Listener.hpp>

#include <algorithm>
#include <any>
#include <array>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cmath>
#include <drm_fourcc.h>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <linux/input-event-codes.h>
#include <memory>
#include <numbers>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <wayland-server-protocol.h>

inline HANDLE g_pluginHandle = nullptr;

namespace {

using Render::GL::g_pHyprOpenGL;

std::vector<SP<CEventLoopTimer>> g_pointerRestoreTimers;
std::vector<SP<CEventLoopTimer>> g_workspaceRestackTimers;
SP<CEventLoopTimer>              g_indicatorHideTimer;
SP<CEventLoopTimer>              g_indicatorAnimationTimer;
SP<CEventLoopTimer>              g_xwaylandKeyboardRestoreTimer;
CHyprSignalListener              g_windowOpenListener;
CHyprSignalListener              g_windowOpenEarlyListener;
CHyprSignalListener              g_renderStageListener;
CHyprSignalListener              g_keyboardInputListener;
CHyprSignalListener              g_pointerButtonInputListener;
CHyprSignalListener              g_pointerMotionInputListener;
PHLWINDOWREF                     g_agentPointerWindow;
std::optional<Vector2D>          g_agentPointerPosition;
std::optional<Vector2D>          g_agentPointerStartPosition;
std::optional<Vector2D>          g_agentPointerDisplayPosition;
std::optional<Vector2D>          g_agentPointerRelativePosition;
std::optional<Vector2D>          g_agentPointerRelativeStartPosition;
std::optional<Vector2D>          g_agentPointerRelativeDisplayPosition;
std::optional<Time::steady_tp>   g_agentPointerUpdated;
std::optional<Time::steady_tp>   g_agentPointerMotionStarted;
std::string                      g_agentPointerAction;
SP<Render::ITexture>             g_codexCursorTexture;
Vector2D                         g_codexCursorTextureSize;
double                           g_codexCursorHotspotX = 0.0;
double                           g_codexCursorHotspotY = 0.0;

struct SPluginConfig {
    SP<Config::Values::CBoolValue>   allowPointer;
    SP<Config::Values::CBoolValue>   allowKeyboard;
    SP<Config::Values::CBoolValue>   allowScreenshot;
    SP<Config::Values::CBoolValue>   allowSession;
    SP<Config::Values::CBoolValue>   showIndicator;
    SP<Config::Values::CIntValue>    indicatorTimeoutMs;
    SP<Config::Values::CIntValue>    keyboardRestoreDelayMs;
    SP<Config::Values::CStringValue> cursorTexturePath;
};

SPluginConfig g_config;

constexpr const char* LUA_CONFIG_ALLOW_POINTER             = "plugin.hypr_agent_protal.allow_pointer";
constexpr const char* LUA_CONFIG_ALLOW_KEYBOARD            = "plugin.hypr_agent_protal.allow_keyboard";
constexpr const char* LUA_CONFIG_ALLOW_SCREENSHOT          = "plugin.hypr_agent_protal.allow_screenshot";
constexpr const char* LUA_CONFIG_ALLOW_SESSION             = "plugin.hypr_agent_protal.allow_session";
constexpr const char* LUA_CONFIG_SHOW_INDICATOR            = "plugin.hypr_agent_protal.show_indicator";
constexpr const char* LUA_CONFIG_INDICATOR_TIMEOUT_MS      = "plugin.hypr_agent_protal.indicator_timeout_ms";
constexpr const char* LUA_CONFIG_KEYBOARD_RESTORE_DELAY_MS = "plugin.hypr_agent_protal.keyboard_restore_delay_ms";
constexpr const char* LUA_CONFIG_CURSOR_TEXTURE_PATH       = "plugin.hypr_agent_protal.cursor_texture_path";
constexpr const char* LUA_PLUGIN_NAMESPACE                 = "hypr_agent_protal";

constexpr int    CODEX_CURSOR_TEXTURE_SIZE = 160;
constexpr int    CODEX_OFFICIAL_CURSOR_TEXTURE_SIZE = 252;
constexpr double CODEX_CURSOR_HOTSPOT_X = 76.6;
constexpr double CODEX_CURSOR_HOTSPOT_Y = 89.3;
constexpr double CODEX_OFFICIAL_CURSOR_HOTSPOT_X = 120.7;
constexpr double CODEX_OFFICIAL_CURSOR_HOTSPOT_Y = 140.6;
constexpr double CODEX_CURSOR_LOGICAL_SIZE = 128.0;
constexpr double CODEX_CURSOR_MOTION_MS = 1429.1667;
constexpr double CODEX_CURSOR_ANIMATION_MS = 1680.0;

bool registerConfigValue(SP<Config::Values::IValue> value) {
    if (!value)
        return false;

    return HyprlandAPI::addConfigValueV2(g_pluginHandle, std::move(value));
}

bool usingLegacyConfig() {
    return Config::mgr() && Config::mgr()->type() == Config::CONFIG_LEGACY;
}

template <typename T>
T legacyConfigValue(const std::string& name, T fallback) {
    const auto value = HyprlandAPI::getConfigValue(g_pluginHandle, name);
    if (!value)
        return fallback;

    try {
        return std::any_cast<T>(value->getValue());
    } catch (const std::bad_any_cast&) {
        return fallback;
    }
}

bool configBool(const std::string& suffix, bool fallback) {
    if (usingLegacyConfig())
        return legacyConfigValue<Hyprlang::INT>("plugin:hypr-agent-protal:" + suffix, fallback ? 1 : 0) != 0;

    if (suffix == "allow_pointer" && g_config.allowPointer)
        return g_config.allowPointer->value();
    if (suffix == "allow_keyboard" && g_config.allowKeyboard)
        return g_config.allowKeyboard->value();
    if (suffix == "allow_screenshot" && g_config.allowScreenshot)
        return g_config.allowScreenshot->value();
    if (suffix == "allow_session" && g_config.allowSession)
        return g_config.allowSession->value();
    if (suffix == "show_indicator" && g_config.showIndicator)
        return g_config.showIndicator->value();

    return fallback;
}

int configInt(const std::string& suffix, int fallback) {
    if (usingLegacyConfig())
        return static_cast<int>(legacyConfigValue<Hyprlang::INT>("plugin:hypr-agent-protal:" + suffix, fallback));

    if (suffix == "indicator_timeout_ms" && g_config.indicatorTimeoutMs)
        return static_cast<int>(g_config.indicatorTimeoutMs->value());
    if (suffix == "keyboard_restore_delay_ms" && g_config.keyboardRestoreDelayMs)
        return static_cast<int>(g_config.keyboardRestoreDelayMs->value());

    return fallback;
}

std::string configString(const std::string& suffix, const std::string& fallback) {
    if (usingLegacyConfig()) {
        const auto value = HyprlandAPI::getConfigValue(g_pluginHandle, "plugin:hypr-agent-protal:" + suffix);
        if (!value)
            return fallback;

        try {
            return std::string{std::any_cast<Hyprlang::STRING>(value->getValue())};
        } catch (const std::bad_any_cast&) {
            return fallback;
        }
    }

    if (suffix == "cursor_texture_path" && g_config.cursorTexturePath)
        return g_config.cursorTexturePath->value();

    return fallback;
}

void registerPluginConfig() {
    if (usingLegacyConfig()) {
        HyprlandAPI::addConfigValue(g_pluginHandle, "plugin:hypr-agent-protal:allow_pointer", Hyprlang::INT{1});
        HyprlandAPI::addConfigValue(g_pluginHandle, "plugin:hypr-agent-protal:allow_keyboard", Hyprlang::INT{1});
        HyprlandAPI::addConfigValue(g_pluginHandle, "plugin:hypr-agent-protal:allow_screenshot", Hyprlang::INT{1});
        HyprlandAPI::addConfigValue(g_pluginHandle, "plugin:hypr-agent-protal:allow_session", Hyprlang::INT{1});
        HyprlandAPI::addConfigValue(g_pluginHandle, "plugin:hypr-agent-protal:show_indicator", Hyprlang::INT{1});
        HyprlandAPI::addConfigValue(g_pluginHandle, "plugin:hypr-agent-protal:indicator_timeout_ms", Hyprlang::INT{30000});
        HyprlandAPI::addConfigValue(g_pluginHandle, "plugin:hypr-agent-protal:keyboard_restore_delay_ms", Hyprlang::INT{700});
        HyprlandAPI::addConfigValue(g_pluginHandle, "plugin:hypr-agent-protal:cursor_texture_path", Hyprlang::STRING{""});
        return;
    }

    using namespace Config::Values;

    g_config.allowPointer          = makeShared<CBoolValue>(LUA_CONFIG_ALLOW_POINTER, "allow background pointer dispatchers", true);
    g_config.allowKeyboard         = makeShared<CBoolValue>(LUA_CONFIG_ALLOW_KEYBOARD, "allow background keyboard dispatchers", true);
    g_config.allowScreenshot       = makeShared<CBoolValue>(LUA_CONFIG_ALLOW_SCREENSHOT, "allow compositor screenshot dispatchers", true);
    g_config.allowSession          = makeShared<CBoolValue>(LUA_CONFIG_ALLOW_SESSION, "allow workspace session dispatchers", true);
    g_config.showIndicator         = makeShared<CBoolValue>(LUA_CONFIG_SHOW_INDICATOR, "show the visible agent cursor indicator", true);
    g_config.indicatorTimeoutMs    = makeShared<CIntValue>(LUA_CONFIG_INDICATOR_TIMEOUT_MS, "visible agent cursor timeout in milliseconds", Config::INTEGER{30000});
    g_config.keyboardRestoreDelayMs = makeShared<CIntValue>(LUA_CONFIG_KEYBOARD_RESTORE_DELAY_MS,
                                                            "maximum XWayland keyboard lease after modified shortcuts", Config::INTEGER{700});
    g_config.cursorTexturePath =
        makeShared<CStringValue>(LUA_CONFIG_CURSOR_TEXTURE_PATH, "raw ABGR cursor texture path", Config::STRING{""});

    const auto registerOrReset = [](auto& value) {
        if (!registerConfigValue(value))
            value.reset();
    };

    registerOrReset(g_config.allowPointer);
    registerOrReset(g_config.allowKeyboard);
    registerOrReset(g_config.allowScreenshot);
    registerOrReset(g_config.allowSession);
    registerOrReset(g_config.showIndicator);
    registerOrReset(g_config.indicatorTimeoutMs);
    registerOrReset(g_config.keyboardRestoreDelayMs);
    registerOrReset(g_config.cursorTexturePath);
}

std::filesystem::path defaultCursorTexturePath() {
    if (const char* xdgConfig = std::getenv("XDG_CONFIG_HOME"); xdgConfig && *xdgConfig)
        return std::filesystem::path{xdgConfig} / "hypr-agent-protal" / "codex-cursor-252.abgr";
    if (const char* home = std::getenv("HOME"); home && *home)
        return std::filesystem::path{home} / ".config" / "hypr-agent-protal" / "codex-cursor-252.abgr";
    return {};
}

std::filesystem::path expandUserPath(std::string path) {
    if (path.empty())
        return {};
    if (path[0] == '~') {
        if (const char* home = std::getenv("HOME"); home && *home) {
            if (path.size() == 1)
                return std::filesystem::path{home};
            if (path[1] == '/')
                return std::filesystem::path{home} / path.substr(2);
        }
    }
    return std::filesystem::path{path};
}

CBox agentIndicatorBounds(const Vector2D& globalPos) {
    return CBox{globalPos.x - 44.0, globalPos.y - 50.0, 88.0, 88.0};
}

Vector2D agentIndicatorWindowAnchor(const PHLWINDOW& window) {
    if (!window)
        return {};
    return window->getFullWindowBoundingBox().pos();
}

CBox agentIndicatorRenderedWindowBox(const PHLWINDOW& window) {
    if (!window)
        return {};

    auto box = window->getFullWindowBoundingBox();
    if (window->m_workspace && !window->m_pinned)
        box.translate(window->m_workspace->m_renderOffset->value());
    box.translate(window->m_floatingOffset);
    return box;
}

Vector2D agentIndicatorRenderedWindowAnchor(const PHLWINDOW& window) {
    return agentIndicatorRenderedWindowBox(window).pos();
}

Vector2D agentIndicatorRenderedGlobalFromRelative(const PHLWINDOW& window, const Vector2D& relative) {
    const auto anchor = agentIndicatorRenderedWindowAnchor(window);
    return Vector2D{anchor.x + relative.x, anchor.y + relative.y};
}

void damageAgentIndicator() {
    if (!g_pHyprRenderer)
        return;

    if (const auto window = g_agentPointerWindow.lock()) {
        g_pHyprRenderer->damageWindow(window, true);
        if (g_agentPointerRelativePosition)
            g_pHyprRenderer->damageBox(agentIndicatorBounds(agentIndicatorRenderedGlobalFromRelative(window, *g_agentPointerRelativePosition)));
        if (g_agentPointerRelativeStartPosition)
            g_pHyprRenderer->damageBox(agentIndicatorBounds(agentIndicatorRenderedGlobalFromRelative(window, *g_agentPointerRelativeStartPosition)));
        if (g_agentPointerRelativeDisplayPosition)
            g_pHyprRenderer->damageBox(agentIndicatorBounds(agentIndicatorRenderedGlobalFromRelative(window, *g_agentPointerRelativeDisplayPosition)));
    }

    if (g_agentPointerPosition)
        g_pHyprRenderer->damageBox(agentIndicatorBounds(*g_agentPointerPosition));
    if (g_agentPointerStartPosition)
        g_pHyprRenderer->damageBox(agentIndicatorBounds(*g_agentPointerStartPosition));
    if (g_agentPointerDisplayPosition)
        g_pHyprRenderer->damageBox(agentIndicatorBounds(*g_agentPointerDisplayPosition));
}

int indicatorTimeoutMs() {
    return std::clamp(configInt("indicator_timeout_ms", 30000), 0, 60000);
}

Time::steady_dur indicatorTimeout() {
    return std::chrono::milliseconds(indicatorTimeoutMs());
}

int xwaylandKeyboardRestoreDelayMs() {
    return std::clamp(configInt("keyboard_restore_delay_ms", 700), 0, 5000);
}

struct Rgba {
    double r = 0.0;
    double g = 0.0;
    double b = 0.0;
    double a = 0.0;
};

void blendTexturePixel(std::vector<uint8_t>& pixels, int x, int y, const Rgba& color, double coverage = 1.0) {
    if (x < 0 || y < 0 || x >= CODEX_CURSOR_TEXTURE_SIZE || y >= CODEX_CURSOR_TEXTURE_SIZE)
        return;

    const double srcA = std::clamp(color.a * coverage, 0.0, 1.0);
    if (srcA <= 0.0)
        return;

    const auto   index = static_cast<size_t>((y * CODEX_CURSOR_TEXTURE_SIZE + x) * 4);
    const double dstR = pixels[index] / 255.0;
    const double dstG = pixels[index + 1] / 255.0;
    const double dstB = pixels[index + 2] / 255.0;
    const double dstA = pixels[index + 3] / 255.0;
    const double outA = srcA + dstA * (1.0 - srcA);

    if (outA <= 0.0) {
        pixels[index] = pixels[index + 1] = pixels[index + 2] = pixels[index + 3] = 0;
        return;
    }

    // Hyprland renders textures with premultiplied-alpha blending.
    const auto toByte = [](double value) { return static_cast<uint8_t>(std::lround(std::clamp(value, 0.0, 1.0) * 255.0)); };
    pixels[index] = toByte(color.r * srcA + dstR * (1.0 - srcA));
    pixels[index + 1] = toByte(color.g * srcA + dstG * (1.0 - srcA));
    pixels[index + 2] = toByte(color.b * srcA + dstB * (1.0 - srcA));
    pixels[index + 3] = toByte(outA);
}

double circleCoverage(int x, int y, const Vector2D& center, double radius) {
    constexpr int SAMPLES = 4;
    int           inside = 0;
    for (int sy = 0; sy < SAMPLES; ++sy) {
        for (int sx = 0; sx < SAMPLES; ++sx) {
            const double px = x + (sx + 0.5) / SAMPLES;
            const double py = y + (sy + 0.5) / SAMPLES;
            const double dx = px - center.x;
            const double dy = py - center.y;
            if (dx * dx + dy * dy <= radius * radius)
                ++inside;
        }
    }
    return static_cast<double>(inside) / (SAMPLES * SAMPLES);
}

void drawTextureCircle(std::vector<uint8_t>& pixels, const Vector2D& center, double radius, const Rgba& color) {
    const int minX = std::max(0, static_cast<int>(std::floor(center.x - radius - 1.0)));
    const int maxX = std::min(CODEX_CURSOR_TEXTURE_SIZE - 1, static_cast<int>(std::ceil(center.x + radius + 1.0)));
    const int minY = std::max(0, static_cast<int>(std::floor(center.y - radius - 1.0)));
    const int maxY = std::min(CODEX_CURSOR_TEXTURE_SIZE - 1, static_cast<int>(std::ceil(center.y + radius + 1.0)));

    for (int y = minY; y <= maxY; ++y)
        for (int x = minX; x <= maxX; ++x)
            blendTexturePixel(pixels, x, y, color, circleCoverage(x, y, center, radius));
}

void drawTextureFog(std::vector<uint8_t>& pixels, const Vector2D& center) {
    for (int y = 0; y < CODEX_CURSOR_TEXTURE_SIZE; ++y) {
        for (int x = 0; x < CODEX_CURSOR_TEXTURE_SIZE; ++x) {
            const double dx = (static_cast<double>(x) + 0.5) - center.x;
            const double dy = (static_cast<double>(y) + 0.5) - center.y;
            const double r2 = dx * dx + dy * dy;
            const double core = std::exp(-r2 / (2.0 * 16.0 * 16.0));
            const double body = std::exp(-r2 / (2.0 * 31.0 * 31.0));
            const double aura = std::exp(-r2 / (2.0 * 48.0 * 48.0));
            const double alpha = std::min(0.24, core * 0.045 + body * 0.14 + aura * 0.038);
            const double warmth = core * 0.08 + body * 0.03;

            blendTexturePixel(pixels, x, y, Rgba{0.73 + warmth, 0.76 + warmth, 1.0, alpha});
        }
    }
}

double distanceToSegment(const Vector2D& point, const Vector2D& start, const Vector2D& end) {
    const double vx = end.x - start.x;
    const double vy = end.y - start.y;
    const double lengthSquared = vx * vx + vy * vy;
    if (lengthSquared <= 0.0001)
        return std::hypot(point.x - start.x, point.y - start.y);

    const double t = std::clamp(((point.x - start.x) * vx + (point.y - start.y) * vy) / lengthSquared, 0.0, 1.0);
    const double px = start.x + vx * t;
    const double py = start.y + vy * t;
    return std::hypot(point.x - px, point.y - py);
}

template <size_t N>
double polylineCoverage(int x, int y, const std::array<Vector2D, N>& points, double lineWidth, bool closed) {
    constexpr int SAMPLES = 4;
    int           covered = 0;
    const double  radius = lineWidth * 0.5;

    for (int sy = 0; sy < SAMPLES; ++sy) {
        for (int sx = 0; sx < SAMPLES; ++sx) {
            const Vector2D point{x + (sx + 0.5) / SAMPLES, y + (sy + 0.5) / SAMPLES};
            double         distance = std::numeric_limits<double>::infinity();

            for (size_t index = 1; index < points.size(); ++index)
                distance = std::min(distance, distanceToSegment(point, points[index - 1], points[index]));
            if (closed)
                distance = std::min(distance, distanceToSegment(point, points.back(), points.front()));

            if (distance <= radius)
                ++covered;
        }
    }

    return static_cast<double>(covered) / (SAMPLES * SAMPLES);
}

template <size_t N>
void drawTexturePolyline(std::vector<uint8_t>& pixels, const std::array<Vector2D, N>& points, double lineWidth, const Rgba& color, bool closed = false) {
    double minX = points[0].x, maxX = points[0].x;
    double minY = points[0].y, maxY = points[0].y;
    for (const auto& point : points) {
        minX = std::min(minX, point.x);
        maxX = std::max(maxX, point.x);
        minY = std::min(minY, point.y);
        maxY = std::max(maxY, point.y);
    }

    const double expand = lineWidth + 2.0;
    const int    startX = std::max(0, static_cast<int>(std::floor(minX - expand)));
    const int    endX = std::min(CODEX_CURSOR_TEXTURE_SIZE - 1, static_cast<int>(std::ceil(maxX + expand)));
    const int    startY = std::max(0, static_cast<int>(std::floor(minY - expand)));
    const int    endY = std::min(CODEX_CURSOR_TEXTURE_SIZE - 1, static_cast<int>(std::ceil(maxY + expand)));

    for (int y = startY; y <= endY; ++y)
        for (int x = startX; x <= endX; ++x)
            blendTexturePixel(pixels, x, y, color, polylineCoverage(x, y, points, lineWidth, closed));
}

template <size_t N>
bool pointInPolygon(const std::array<Vector2D, N>& polygon, double x, double y) {
    bool inside = false;
    for (size_t i = 0, j = polygon.size() - 1; i < polygon.size(); j = i++) {
        const auto& pi = polygon[i];
        const auto& pj = polygon[j];
        if (((pi.y > y) != (pj.y > y)) && (x < (pj.x - pi.x) * (y - pi.y) / (pj.y - pi.y) + pi.x))
            inside = !inside;
    }
    return inside;
}

template <size_t N>
double polygonCoverage(int x, int y, const std::array<Vector2D, N>& polygon) {
    constexpr int SAMPLES = 4;
    int           inside = 0;
    for (int sy = 0; sy < SAMPLES; ++sy) {
        for (int sx = 0; sx < SAMPLES; ++sx) {
            const double px = x + (sx + 0.5) / SAMPLES;
            const double py = y + (sy + 0.5) / SAMPLES;
            if (pointInPolygon(polygon, px, py))
                ++inside;
        }
    }
    return static_cast<double>(inside) / (SAMPLES * SAMPLES);
}

template <size_t N>
void drawTexturePolygon(std::vector<uint8_t>& pixels, const std::array<Vector2D, N>& polygon, const Rgba& color) {
    double minX = polygon[0].x, maxX = polygon[0].x;
    double minY = polygon[0].y, maxY = polygon[0].y;
    for (const auto& point : polygon) {
        minX = std::min(minX, point.x);
        maxX = std::max(maxX, point.x);
        minY = std::min(minY, point.y);
        maxY = std::max(maxY, point.y);
    }

    const int startX = std::max(0, static_cast<int>(std::floor(minX - 1.0)));
    const int endX = std::min(CODEX_CURSOR_TEXTURE_SIZE - 1, static_cast<int>(std::ceil(maxX + 1.0)));
    const int startY = std::max(0, static_cast<int>(std::floor(minY - 1.0)));
    const int endY = std::min(CODEX_CURSOR_TEXTURE_SIZE - 1, static_cast<int>(std::ceil(maxY + 1.0)));

    for (int y = startY; y <= endY; ++y)
        for (int x = startX; x <= endX; ++x)
            blendTexturePixel(pixels, x, y, color, polygonCoverage(x, y, polygon));
}

SP<Render::ITexture> loadOfficialCodexCursorTexture() {
    const auto configuredPath = configString("cursor_texture_path", "");
    const auto texturePath = configuredPath.empty() ? defaultCursorTexturePath() : expandUserPath(configuredPath);
    if (texturePath.empty() || !std::filesystem::exists(texturePath))
        return {};

    std::ifstream file{texturePath, std::ios::binary};
    if (!file)
        return {};

    std::vector<uint8_t> pixels(std::istreambuf_iterator<char>{file}, {});
    constexpr size_t     EXPECTED_SIZE = CODEX_OFFICIAL_CURSOR_TEXTURE_SIZE * CODEX_OFFICIAL_CURSOR_TEXTURE_SIZE * 4;
    if (pixels.size() != EXPECTED_SIZE)
        return {};

    g_codexCursorTextureSize = Vector2D{CODEX_OFFICIAL_CURSOR_TEXTURE_SIZE, CODEX_OFFICIAL_CURSOR_TEXTURE_SIZE};
    g_codexCursorHotspotX = CODEX_OFFICIAL_CURSOR_HOTSPOT_X;
    g_codexCursorHotspotY = CODEX_OFFICIAL_CURSOR_HOTSPOT_Y;
    return makeShared<Render::GL::CGLTexture>(DRM_FORMAT_ABGR8888, pixels.data(), CODEX_OFFICIAL_CURSOR_TEXTURE_SIZE * 4, g_codexCursorTextureSize, true);
}

SP<Render::ITexture> codexCursorTexture() {
    if (g_codexCursorTexture)
        return g_codexCursorTexture;

    g_codexCursorTexture = loadOfficialCodexCursorTexture();
    if (g_codexCursorTexture)
        return g_codexCursorTexture;

    std::vector<uint8_t> pixels(CODEX_CURSOR_TEXTURE_SIZE * CODEX_CURSOR_TEXTURE_SIZE * 4, 0);

    drawTextureFog(pixels, Vector2D{80.0, 79.0});
    drawTextureCircle(pixels, Vector2D{80.0, 79.0}, 38.0, Rgba{0.92, 0.93, 1.0, 0.010});

    const std::array<Vector2D, 7> pointer = {Vector2D{65.5, 47.0}, Vector2D{65.5, 104.0}, Vector2D{78.0, 91.0}, Vector2D{88.5, 116.0},
                                             Vector2D{102.5, 110.0}, Vector2D{92.0, 86.0}, Vector2D{115.0, 86.0}};
    const std::array<Vector2D, 7> pointerShadow = {Vector2D{67.2, 49.2}, Vector2D{67.2, 106.2}, Vector2D{79.7, 93.2}, Vector2D{90.2, 118.2},
                                                   Vector2D{104.2, 112.2}, Vector2D{93.7, 88.2}, Vector2D{116.7, 88.2}};

    drawTexturePolyline(pixels, pointerShadow, 9.0, Rgba{0.08, 0.08, 0.14, 0.105}, true);
    drawTexturePolygon(pixels, pointer, Rgba{0.86, 0.88, 1.0, 0.12});
    drawTexturePolyline(pixels, pointer, 8.0, Rgba{0.88, 0.90, 1.0, 0.26}, true);
    drawTexturePolyline(pixels, pointer, 4.8, Rgba{1.0, 1.0, 1.0, 0.94}, true);
    drawTexturePolyline(pixels, pointer, 1.35, Rgba{0.68, 0.70, 0.92, 0.26}, true);

    g_codexCursorTextureSize = Vector2D{CODEX_CURSOR_TEXTURE_SIZE, CODEX_CURSOR_TEXTURE_SIZE};
    g_codexCursorHotspotX = CODEX_CURSOR_HOTSPOT_X;
    g_codexCursorHotspotY = CODEX_CURSOR_HOTSPOT_Y;
    g_codexCursorTexture = makeShared<Render::GL::CGLTexture>(DRM_FORMAT_ABGR8888, pixels.data(), CODEX_CURSOR_TEXTURE_SIZE * 4,
                                                              g_codexCursorTextureSize, true);
    return g_codexCursorTexture;
}

double vectorLength(const Vector2D& value) {
    return std::hypot(value.x, value.y);
}

bool pointInsideBox(const Vector2D& point, const CBox& box, double padding = 0.0) {
    return point.x >= box.x + padding && point.y >= box.y + padding && point.x <= box.x + box.w - padding && point.y <= box.y + box.h - padding;
}

CBox intersectBoxes(const CBox& a, const CBox& b) {
    const double left = std::max(a.x, b.x);
    const double top = std::max(a.y, b.y);
    const double right = std::min(a.x + a.w, b.x + b.w);
    const double bottom = std::min(a.y + a.h, b.y + b.h);
    if (right <= left || bottom <= top)
        return {};
    return CBox{left, top, right - left, bottom - top};
}

Vector2D clampPointToBox(const Vector2D& point, const CBox& box, double padding) {
    if (box.empty())
        return point;
    const double padX = std::min(std::max(0.0, padding), std::max(0.0, box.w * 0.5 - 1.0));
    const double padY = std::min(std::max(0.0, padding), std::max(0.0, box.h * 0.5 - 1.0));
    return Vector2D{
        std::clamp(point.x, box.x + padX, box.x + box.w - padX),
        std::clamp(point.y, box.y + padY, box.y + box.h - padY),
    };
}

bool indicatorActionShouldSnap(std::string_view action) {
    return action == "click" || action == "doubleclick" || action == "double-click" || action == "press" || action == "down" || action == "release" ||
        action == "up" || action == "scroll" || action == "key" || action == "type" || action == "set_value";
}

Vector2D cubicPoint(const Vector2D& start, const Vector2D& control1, const Vector2D& control2, const Vector2D& end, double progress) {
    const double t = std::clamp(progress, 0.0, 1.0);
    const double omt = 1.0 - t;
    const double a = omt * omt * omt;
    const double b = 3.0 * omt * omt * t;
    const double c = 3.0 * omt * t * t;
    const double d = t * t * t;
    return Vector2D{
        start.x * a + control1.x * b + control2.x * c + end.x * d,
        start.y * a + control1.y * b + control2.y * c + end.y * d,
    };
}

struct CursorBezier {
    Vector2D control1;
    Vector2D control2;
};

CursorBezier makeCursorBezier(const Vector2D& start, const Vector2D& end, double curveScale, double side) {
    const Vector2D delta{end.x - start.x, end.y - start.y};
    const double   distance = std::max(vectorLength(delta), 1.0);
    const Vector2D normal{-delta.y / distance, delta.x / distance};
    const double   curveAmount = std::clamp(distance * 0.22, 28.0, 110.0) * curveScale;
    return CursorBezier{
        Vector2D{start.x + delta.x * 0.18 + normal.x * curveAmount * side, start.y + delta.y * 0.18 + normal.y * curveAmount * side},
        Vector2D{start.x + delta.x * 0.82 + normal.x * curveAmount * 0.48 * side, start.y + delta.y * 0.82 + normal.y * curveAmount * 0.48 * side},
    };
}

bool cursorBezierStaysInside(const Vector2D& start, const Vector2D& end, const CursorBezier& bezier, const CBox& bounds) {
    for (int i = 1; i < 10; ++i) {
        const auto point = cubicPoint(start, bezier.control1, bezier.control2, end, i / 10.0);
        if (!pointInsideBox(point, bounds, 1.0))
            return false;
    }
    return true;
}

CursorBezier chooseCursorBezier(const Vector2D& start, const Vector2D& end, const CBox& bounds) {
    const Vector2D delta{end.x - start.x, end.y - start.y};
    const double   distance = vectorLength(delta);
    if (distance < 2.0)
        return makeCursorBezier(start, end, 0.0, 1.0);

    const double baseSide = delta.x >= 0.0 ? 1.0 : -1.0;
    for (const double curveScale : {1.0, 0.65, 0.35}) {
        for (const double side : {baseSide, -baseSide}) {
            const auto bezier = makeCursorBezier(start, end, curveScale, side);
            if (cursorBezierStaysInside(start, end, bezier, bounds))
                return bezier;
        }
    }

    return makeCursorBezier(start, end, 0.0, 1.0);
}

double officialSpringProgress(double elapsedMs) {
    // Same progress spring constants as the bundled Codex Computer Use cursor.
    const double targetTime = std::clamp(elapsedMs / 1000.0, 0.0, CODEX_CURSOR_MOTION_MS / 1000.0);
    constexpr double RESPONSE = 1.4;
    constexpr double DAMPING_FRACTION = 0.9;
    constexpr double DT = 1.0 / 240.0;
    constexpr double IDLE_VELOCITY_THRESHOLD = 28800.0;
    const double     stiffness = std::min(std::pow((2.0 * std::numbers::pi) / RESPONSE, 2.0), IDLE_VELOCITY_THRESHOLD);
    const double     drag = 2.0 * DAMPING_FRACTION * std::sqrt(stiffness);

    double current = 0.0;
    double velocity = 0.0;
    double force = 0.0;
    double time = 0.0;

    while (time < targetTime) {
        const double dt = std::min(DT, targetTime - time);
        const double halfDt = dt * 0.5;
        const double velocityHalf = velocity + force * halfDt;
        current += velocityHalf * dt;
        force = stiffness * (1.0 - current) - drag * velocityHalf;
        velocity = velocityHalf + force * halfDt;
        time += dt;
    }

    return std::clamp(current, 0.0, 1.0);
}

Vector2D animatedAgentPosition(const Time::steady_tp& now, const PHLWINDOW& window, const CBox& bounds) {
    if (!g_agentPointerPosition && !g_agentPointerRelativePosition)
        return {};

    const Vector2D target = g_agentPointerRelativePosition ? agentIndicatorRenderedGlobalFromRelative(window, *g_agentPointerRelativePosition) : *g_agentPointerPosition;
    const Vector2D start = g_agentPointerRelativeStartPosition ? agentIndicatorRenderedGlobalFromRelative(window, *g_agentPointerRelativeStartPosition) :
                                                        g_agentPointerStartPosition.value_or(target);
    if (!g_agentPointerMotionStarted || vectorLength(Vector2D{target.x - start.x, target.y - start.y}) < 2.0)
        return target;

    const double elapsedMs = static_cast<double>(std::chrono::duration_cast<std::chrono::milliseconds>(now - *g_agentPointerMotionStarted).count());
    const double progress = officialSpringProgress(elapsedMs);
    const auto   bezier = chooseCursorBezier(start, target, bounds);
    return cubicPoint(start, bezier.control1, bezier.control2, target, progress);
}

void renderAgentIndicator(eRenderStage stage) {
    if (stage != RENDER_POST_WINDOW || !configBool("show_indicator", true) || (!g_agentPointerPosition && !g_agentPointerRelativePosition) || !g_agentPointerUpdated ||
        !g_pHyprOpenGL || !g_pHyprRenderer)
        return;

    const auto targetWindow = g_agentPointerWindow.lock();
    const auto currentWindow = g_pHyprRenderer->m_renderData.currentWindow.lock();
    if (!targetWindow || currentWindow != targetWindow)
        return;

    const auto monitor = g_pHyprRenderer->m_renderData.pMonitor.lock();
    if (!monitor)
        return;

    const auto windowBox = agentIndicatorRenderedWindowBox(targetWindow);
    const auto   now = Time::steadyNow();
    const double ageMs = static_cast<double>(std::chrono::duration_cast<std::chrono::milliseconds>(now - *g_agentPointerUpdated).count());
    const int    timeoutMs = indicatorTimeoutMs();
    if (timeoutMs > 0 && ageMs > timeoutMs + 50.0)
        return;

    const double fade = timeoutMs <= 0 ? 1.0 : std::clamp((static_cast<double>(timeoutMs) - ageMs) / 900.0, 0.0, 1.0);
    if (fade <= 0.0)
        return;

    const auto global = animatedAgentPosition(now, targetWindow, windowBox);
    const auto monitorBox = CBox{monitor->m_position.x, monitor->m_position.y, monitor->m_size.x, monitor->m_size.y};
    const auto visibleWindowBox = intersectBoxes(windowBox, monitorBox);
    const auto displayGlobal = visibleWindowBox.empty() ? global : clampPointToBox(global, visibleWindowBox, 18.0);
    g_agentPointerDisplayPosition = displayGlobal;
    const auto anchor = agentIndicatorRenderedWindowAnchor(targetWindow);
    g_agentPointerRelativeDisplayPosition = Vector2D{displayGlobal.x - anchor.x, displayGlobal.y - anchor.y};

    const bool   clickLike = g_agentPointerAction == "click" || g_agentPointerAction == "doubleclick" || g_agentPointerAction == "double-click" ||
        g_agentPointerAction == "press" || g_agentPointerAction == "down" || g_agentPointerAction == "release" || g_agentPointerAction == "up";
    const double pulse = clickLike ? std::clamp(1.0 - ageMs / 420.0, 0.0, 1.0) : 0.0;
    const double renderScale = std::max(1.0, static_cast<double>(monitor->m_scale));
    const Vector2D tip{
        (displayGlobal.x - monitor->m_position.x) * renderScale,
        (displayGlobal.y - monitor->m_position.y) * renderScale,
    };
    const double renderSize = (CODEX_CURSOR_LOGICAL_SIZE + 2.0 * pulse) * renderScale;
    const auto   texture = codexCursorTexture();
    if (!texture || g_codexCursorTextureSize.x <= 0.0 || g_codexCursorTextureSize.y <= 0.0)
        return;

    const double x = tip.x - (g_codexCursorHotspotX / g_codexCursorTextureSize.x) * renderSize;
    const double y = tip.y - (g_codexCursorHotspotY / g_codexCursorTextureSize.y) * renderSize;

    CTexPassElement::SRenderData data;
    data.tex = texture;
    data.box = CBox{x, y, renderSize, renderSize};
    data.a = static_cast<float>(fade);
    g_pHyprRenderer->m_renderPass.add(makeUnique<CTexPassElement>(std::move(data)));
}

void stopIndicatorTimer(SP<CEventLoopTimer>& timer) {
    if (timer && g_pEventLoopManager)
        g_pEventLoopManager->removeTimer(timer);
    timer.reset();
}

void scheduleIndicatorAnimation() {
    if (!g_pEventLoopManager || g_indicatorAnimationTimer)
        return;

    g_indicatorAnimationTimer = makeShared<CEventLoopTimer>(
        std::chrono::milliseconds(16),
        [](SP<CEventLoopTimer> self, void*) {
            const auto now = Time::steadyNow();
            const bool animationDone = g_agentPointerUpdated &&
                std::chrono::duration_cast<std::chrono::milliseconds>(now - *g_agentPointerUpdated).count() > CODEX_CURSOR_ANIMATION_MS;
            const int  timeoutMs = indicatorTimeoutMs();
            const bool expired = g_agentPointerUpdated && timeoutMs > 0 &&
                std::chrono::duration_cast<std::chrono::milliseconds>(now - *g_agentPointerUpdated).count() > timeoutMs + 50;
            if ((!g_agentPointerPosition && !g_agentPointerRelativePosition) || !g_pEventLoopManager || expired) {
                if (g_pEventLoopManager)
                    g_pEventLoopManager->removeTimer(self);
                if (g_indicatorAnimationTimer.get() == self.get())
                    g_indicatorAnimationTimer.reset();
                return;
            }

            damageAgentIndicator();
            self->updateTimeout(animationDone ? std::chrono::milliseconds(33) : std::chrono::milliseconds(16));
        },
        nullptr);
    g_pEventLoopManager->addTimer(g_indicatorAnimationTimer);
}

void scheduleIndicatorHide() {
    if (!g_pEventLoopManager)
        return;

    stopIndicatorTimer(g_indicatorHideTimer);
    if (indicatorTimeoutMs() <= 0)
        return;

    g_indicatorHideTimer = makeShared<CEventLoopTimer>(
        indicatorTimeout(),
        [](SP<CEventLoopTimer> self, void*) {
            damageAgentIndicator();
            g_agentPointerWindow.reset();
            g_agentPointerPosition.reset();
            g_agentPointerStartPosition.reset();
            g_agentPointerDisplayPosition.reset();
            g_agentPointerRelativePosition.reset();
            g_agentPointerRelativeStartPosition.reset();
            g_agentPointerRelativeDisplayPosition.reset();
            g_agentPointerUpdated.reset();
            g_agentPointerMotionStarted.reset();
            g_agentPointerAction.clear();

            if (g_pEventLoopManager)
                g_pEventLoopManager->removeTimer(self);
            if (g_indicatorHideTimer.get() == self.get())
                g_indicatorHideTimer.reset();
            stopIndicatorTimer(g_indicatorAnimationTimer);
        },
        nullptr);
    g_pEventLoopManager->addTimer(g_indicatorHideTimer);
}

void showAgentIndicator(const PHLWINDOW& targetWindow, const Vector2D& globalPos, std::string_view action) {
    if (!configBool("show_indicator", true))
        return;

    const auto oldWindow = g_agentPointerWindow.lock();
    const auto previousDisplay = g_agentPointerDisplayPosition;
    const auto previousRelativeDisplay = g_agentPointerRelativeDisplayPosition;
    const auto previousTarget = g_agentPointerPosition;
    const auto previousRelativeTarget = g_agentPointerRelativePosition;
    const auto now = Time::steadyNow();
    Vector2D   motionStart = globalPos;
    const auto anchor = agentIndicatorWindowAnchor(targetWindow);
    const auto relative = Vector2D{globalPos.x - anchor.x, globalPos.y - anchor.y};
    Vector2D   relativeMotionStart = relative;

    if (!indicatorActionShouldSnap(action) && oldWindow && oldWindow == targetWindow) {
        if (previousRelativeDisplay) {
            relativeMotionStart = *previousRelativeDisplay;
            motionStart = agentIndicatorRenderedGlobalFromRelative(targetWindow, relativeMotionStart);
        } else if (previousDisplay && pointInsideBox(*previousDisplay, agentIndicatorRenderedWindowBox(targetWindow))) {
            motionStart = *previousDisplay;
            const auto renderedAnchor = agentIndicatorRenderedWindowAnchor(targetWindow);
            relativeMotionStart = Vector2D{motionStart.x - renderedAnchor.x, motionStart.y - renderedAnchor.y};
        } else if (previousRelativeTarget) {
            relativeMotionStart = *previousRelativeTarget;
            motionStart = agentIndicatorRenderedGlobalFromRelative(targetWindow, relativeMotionStart);
        } else if (previousTarget && pointInsideBox(*previousTarget, targetWindow->getFullWindowBoundingBox())) {
            motionStart = *previousTarget;
            relativeMotionStart = Vector2D{motionStart.x - anchor.x, motionStart.y - anchor.y};
        }
    }

    damageAgentIndicator();
    g_agentPointerWindow = PHLWINDOWREF{targetWindow};
    g_agentPointerPosition = globalPos;
    g_agentPointerStartPosition = motionStart;
    g_agentPointerDisplayPosition = motionStart;
    g_agentPointerRelativePosition = relative;
    g_agentPointerRelativeStartPosition = relativeMotionStart;
    g_agentPointerRelativeDisplayPosition = relativeMotionStart;
    g_agentPointerUpdated = now;
    g_agentPointerMotionStarted = now;
    g_agentPointerAction = std::string(action);
    damageAgentIndicator();

    scheduleIndicatorHide();
    scheduleIndicatorAnimation();
}

std::string trim(std::string_view value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
        value.remove_prefix(1);
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
        value.remove_suffix(1);
    return std::string(value);
}

std::vector<std::string> splitCsv(std::string_view input) {
    std::vector<std::string> parts;
    std::string             current;
    bool                    escaped = false;
    bool                    quoted = false;

    for (const char ch : input) {
        if (escaped) {
            current.push_back(ch);
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '"') {
            quoted = !quoted;
            continue;
        }
        if (ch == ',' && !quoted) {
            parts.push_back(trim(current));
            current.clear();
            continue;
        }
        current.push_back(ch);
    }
    parts.push_back(trim(current));
    return parts;
}

std::optional<double> parseDouble(const std::string& raw) {
    double value = 0.0;
    const auto begin = raw.data();
    const auto end = raw.data() + raw.size();
    const auto [ptr, ec] = std::from_chars(begin, end, value);
    if (ec != std::errc{} || ptr != end || !std::isfinite(value))
        return std::nullopt;
    return value;
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::vector<std::string> splitCombo(std::string_view input) {
    std::vector<std::string> parts;
    std::string             current;

    for (const char ch : input) {
        if (ch == '+' || ch == '-' || ch == ' ') {
            const auto part = trim(current);
            if (!part.empty())
                parts.push_back(lower(part));
            current.clear();
            continue;
        }
        current.push_back(ch);
    }

    const auto part = trim(current);
    if (!part.empty())
        parts.push_back(lower(part));
    return parts;
}

std::optional<uint32_t> pointerButton(std::string raw) {
    raw = lower(trim(raw));
    if (raw.empty() || raw == "left")
        return BTN_LEFT;
    if (raw == "right")
        return BTN_RIGHT;
    if (raw == "middle")
        return BTN_MIDDLE;
    if (raw == "side")
        return BTN_SIDE;
    if (raw == "extra")
        return BTN_EXTRA;

    uint32_t value = 0;
    const auto [ptr, ec] = std::from_chars(raw.data(), raw.data() + raw.size(), value);
    if (ec == std::errc{} && ptr == raw.data() + raw.size())
        return value;
    return std::nullopt;
}

std::optional<uint32_t> keyboardKey(std::string raw) {
    raw = lower(trim(raw));
    if (raw.empty())
        return std::nullopt;

    static const std::unordered_map<std::string, uint32_t> keys = {
        {"a", KEY_A},
        {"b", KEY_B},
        {"c", KEY_C},
        {"d", KEY_D},
        {"e", KEY_E},
        {"f", KEY_F},
        {"g", KEY_G},
        {"h", KEY_H},
        {"i", KEY_I},
        {"j", KEY_J},
        {"k", KEY_K},
        {"l", KEY_L},
        {"m", KEY_M},
        {"n", KEY_N},
        {"o", KEY_O},
        {"p", KEY_P},
        {"q", KEY_Q},
        {"r", KEY_R},
        {"s", KEY_S},
        {"t", KEY_T},
        {"u", KEY_U},
        {"v", KEY_V},
        {"w", KEY_W},
        {"x", KEY_X},
        {"y", KEY_Y},
        {"z", KEY_Z},
        {"esc", KEY_ESC},
        {"escape", KEY_ESC},
        {"enter", KEY_ENTER},
        {"return", KEY_ENTER},
        {"tab", KEY_TAB},
        {"backspace", KEY_BACKSPACE},
        {"delete", KEY_DELETE},
        {"del", KEY_DELETE},
        {"insert", KEY_INSERT},
        {"ins", KEY_INSERT},
        {"space", KEY_SPACE},
        {"minus", KEY_MINUS},
        {"-", KEY_MINUS},
        {"equal", KEY_EQUAL},
        {"=", KEY_EQUAL},
        {"leftbrace", KEY_LEFTBRACE},
        {"[", KEY_LEFTBRACE},
        {"rightbrace", KEY_RIGHTBRACE},
        {"]", KEY_RIGHTBRACE},
        {"backslash", KEY_BACKSLASH},
        {"\\", KEY_BACKSLASH},
        {"semicolon", KEY_SEMICOLON},
        {";", KEY_SEMICOLON},
        {"apostrophe", KEY_APOSTROPHE},
        {"quote", KEY_APOSTROPHE},
        {"'", KEY_APOSTROPHE},
        {"grave", KEY_GRAVE},
        {"`", KEY_GRAVE},
        {"comma", KEY_COMMA},
        {",", KEY_COMMA},
        {"dot", KEY_DOT},
        {"period", KEY_DOT},
        {".", KEY_DOT},
        {"slash", KEY_SLASH},
        {"/", KEY_SLASH},
        {"up", KEY_UP},
        {"down", KEY_DOWN},
        {"left", KEY_LEFT},
        {"right", KEY_RIGHT},
        {"home", KEY_HOME},
        {"end", KEY_END},
        {"pageup", KEY_PAGEUP},
        {"pgup", KEY_PAGEUP},
        {"pagedown", KEY_PAGEDOWN},
        {"pgdn", KEY_PAGEDOWN},
        {"capslock", KEY_CAPSLOCK},
        {"leftctrl", KEY_LEFTCTRL},
        {"ctrl", KEY_LEFTCTRL},
        {"control", KEY_LEFTCTRL},
        {"leftshift", KEY_LEFTSHIFT},
        {"shift", KEY_LEFTSHIFT},
        {"leftalt", KEY_LEFTALT},
        {"alt", KEY_LEFTALT},
        {"option", KEY_LEFTALT},
        {"leftmeta", KEY_LEFTMETA},
        {"meta", KEY_LEFTMETA},
        {"super", KEY_LEFTMETA},
        {"win", KEY_LEFTMETA},
        {"cmd", KEY_LEFTMETA},
        {"command", KEY_LEFTMETA},
        {"rightctrl", KEY_RIGHTCTRL},
        {"rightshift", KEY_RIGHTSHIFT},
        {"rightalt", KEY_RIGHTALT},
        {"rightmeta", KEY_RIGHTMETA},
    };

    if (raw.size() == 1) {
        const char ch = raw.front();
        if (ch >= '1' && ch <= '9')
            return KEY_1 + static_cast<uint32_t>(ch - '1');
        if (ch == '0')
            return KEY_0;
    }

    if (raw.size() > 1 && raw.front() == 'f') {
        uint32_t n = 0;
        const auto [ptr, ec] = std::from_chars(raw.data() + 1, raw.data() + raw.size(), n);
        if (ec == std::errc{} && ptr == raw.data() + raw.size() && n >= 1 && n <= 12)
            return KEY_F1 + n - 1;
    }

    if (const auto it = keys.find(raw); it != keys.end())
        return it->second;

    uint32_t value = 0;
    const auto [ptr, ec] = std::from_chars(raw.data(), raw.data() + raw.size(), value);
    if (ec == std::errc{} && ptr == raw.data() + raw.size() && value <= KEY_MAX)
        return value;
    return std::nullopt;
}

struct KeyboardModifier {
    uint32_t key;
    uint32_t mask;
};

std::optional<KeyboardModifier> keyboardModifier(std::string raw) {
    raw = lower(trim(raw));
    if (raw == "ctrl" || raw == "control")
        return KeyboardModifier{.key = KEY_LEFTCTRL, .mask = 1U << 2};
    if (raw == "shift")
        return KeyboardModifier{.key = KEY_LEFTSHIFT, .mask = 1U << 0};
    if (raw == "alt" || raw == "option")
        return KeyboardModifier{.key = KEY_LEFTALT, .mask = 1U << 3};
    if (raw == "meta" || raw == "super" || raw == "win" || raw == "cmd" || raw == "command")
        return KeyboardModifier{.key = KEY_LEFTMETA, .mask = 1U << 6};
    return std::nullopt;
}

uint32_t nowMs() {
    return static_cast<uint32_t>(Time::millis(Time::steadyNow()) & 0xFFFFFFFFU);
}

void removePointerTimer(const SP<CEventLoopTimer>& self) {
    if (g_pEventLoopManager)
        g_pEventLoopManager->removeTimer(self);

    g_pointerRestoreTimers.erase(
        std::remove_if(g_pointerRestoreTimers.begin(), g_pointerRestoreTimers.end(), [&self](const auto& item) { return item.get() == self.get(); }),
        g_pointerRestoreTimers.end());
}

struct TargetSurface {
    PHLWINDOW              window;
    SP<CWLSurfaceResource> surface;
    Vector2D               local;
};

struct WorkspaceSession {
    PHLWINDOWREF root;
    pid_t        pid = -1;
    PHLWORKSPACE targetWorkspace;
};

std::vector<WorkspaceSession> g_workspaceSessions;

CBox windowMainSurfaceGoalBox(const PHLWINDOW& window) {
    if (!window)
        return {};

    return window->geometricBox(Desktop::View::IGeometric::GEOMETRIC_GOAL);
}

bool sameXWaylandClientFamily(const PHLWINDOW& root, const PHLWINDOW& candidate) {
    if (!root || !candidate || root == candidate || !root->m_isX11 || !candidate->m_isX11)
        return false;

    const auto transientFor = candidate->x11Parent();
    if (transientFor && transientFor == root)
        return true;

    const auto rootPid = root->getPID();
    const auto candidatePid = candidate->getPID();
    if (rootPid <= 0 || candidatePid != rootPid)
        return false;

    if (!root->m_class.empty() && root->m_class == candidate->m_class)
        return true;
    return !root->m_initialClass.empty() && root->m_initialClass == candidate->m_initialClass;
}

bool sameClientFamily(const PHLWINDOW& root, const PHLWINDOW& candidate) {
    if (!root || !candidate || root == candidate)
        return false;
    if (sameXWaylandClientFamily(root, candidate))
        return true;

    const auto rootPid = root->getPID();
    const auto candidatePid = candidate->getPID();
    return rootPid > 0 && candidatePid == rootPid;
}

PHLWINDOW xwaylandRelatedWindowAt(const PHLWINDOW& root, const Vector2D& globalPos) {
    if (!g_pCompositor || !root || !root->m_isX11)
        return root;

    PHLWINDOW best = root;
    double    bestArea = std::numeric_limits<double>::infinity();

    for (const auto& candidate : Desktop::windowState()->windows()) {
        if (!candidate || !candidate->m_isMapped || candidate->isHidden() || !sameXWaylandClientFamily(root, candidate))
            continue;

        const auto box = windowMainSurfaceGoalBox(candidate);
        if (!box.containsPoint(globalPos))
            continue;

        const double area = std::max(1.0, box.w) * std::max(1.0, box.h);
        if (area < bestArea) {
            best = candidate;
            bestArea = area;
        }
    }

    return best;
}

PHLWORKSPACE workspaceSessionTarget(const WorkspaceSession& session) {
    const auto root = session.root.lock();
    if (root && root->m_workspace)
        return root->m_workspace;
    return session.targetWorkspace;
}

bool workspaceSessionMatchesWindow(const WorkspaceSession& session, const PHLWINDOW& window, bool requireMapped = true) {
    if (!window || (requireMapped && !window->m_isMapped))
        return false;

    const auto root = session.root.lock();
    if (root && window == root)
        return true;
    if (root && sameClientFamily(root, window))
        return true;
    return session.pid > 0 && window->getPID() == session.pid;
}

void constrainRelatedWindowFocusAndLayer(const PHLWINDOW& window) {
    if (!window)
        return;

    window->m_noInitialFocus = true;
    window->m_suppressedEvents |= Desktop::View::SUPPRESS_ACTIVATE | Desktop::View::SUPPRESS_ACTIVATE_FOCUSONLY;
}

void restackRelatedWindowWithRoot(const PHLWINDOW& root, const PHLWINDOW& window) {
    if (!g_pCompositor || !root || !window || root == window)
        return;

    constrainRelatedWindowFocusAndLayer(window);

    Desktop::windowState()->raise(window);

    if (g_pHyprRenderer) {
        g_pHyprRenderer->damageWindow(root);
        g_pHyprRenderer->damageWindow(window);
    }
}

void placeRelatedWindowOnRootWorkspaceEarly(WorkspaceSession& session, const PHLWINDOW& window) {
    if (!window)
        return;

    const auto root = session.root.lock();
    if (!root || root == window)
        return;

    constrainRelatedWindowFocusAndLayer(window);
    if (!window->m_isMapped)
        return;

    const auto targetWorkspace = workspaceSessionTarget(session);
    if (!targetWorkspace || targetWorkspace->inert() || window->m_workspace == targetWorkspace)
        return;

    window->moveToWorkspace(targetWorkspace);
    window->m_monitor = targetWorkspace->m_monitor;
}

void scheduleRelatedWindowRestack(const PHLWINDOW& root, const PHLWINDOW& window, std::chrono::milliseconds delay) {
    if (!g_pEventLoopManager || !root || !window || root == window)
        return;

    PHLWINDOWREF rootRef{root};
    PHLWINDOWREF windowRef{window};
    auto         timer = makeShared<CEventLoopTimer>(
        delay,
        [rootRef, windowRef](SP<CEventLoopTimer> self, void*) mutable {
            restackRelatedWindowWithRoot(rootRef.lock(), windowRef.lock());

            if (g_pEventLoopManager)
                g_pEventLoopManager->removeTimer(self);

            g_workspaceRestackTimers.erase(
                std::remove_if(g_workspaceRestackTimers.begin(), g_workspaceRestackTimers.end(), [&self](const auto& item) { return item.get() == self.get(); }),
                g_workspaceRestackTimers.end());
        },
        nullptr);

    g_workspaceRestackTimers.push_back(timer);
    g_pEventLoopManager->addTimer(timer);
}

void scheduleRelatedWindowRestacks(const PHLWINDOW& root, const PHLWINDOW& window) {
    scheduleRelatedWindowRestack(root, window, std::chrono::milliseconds(50));
    scheduleRelatedWindowRestack(root, window, std::chrono::milliseconds(200));
    scheduleRelatedWindowRestack(root, window, std::chrono::milliseconds(500));
}

void moveRelatedWindowToSessionWorkspace(WorkspaceSession& session, const PHLWINDOW& window) {
    if (!g_pCompositor || !window || !window->m_isMapped)
        return;

    const auto root = session.root.lock();
    if (root && window == root)
        return;

    const auto targetWorkspace = workspaceSessionTarget(session);
    if (!targetWorkspace || targetWorkspace->inert())
        return;

    if (window->m_workspace != targetWorkspace)
        Desktop::globalWindowController()->moveWindowToWorkspace(window, targetWorkspace);

    if (root) {
        restackRelatedWindowWithRoot(root, window);
        scheduleRelatedWindowRestacks(root, window);
    }
}

void syncWorkspaceSession(WorkspaceSession& session) {
    if (!g_pCompositor)
        return;

    for (const auto& window : Desktop::windowState()->windows()) {
        if (workspaceSessionMatchesWindow(session, window))
            moveRelatedWindowToSessionWorkspace(session, window);
    }
}

void handleWorkspaceSessionWindowOpen(const PHLWINDOW& window) {
    if (!window || g_workspaceSessions.empty())
        return;

    for (auto& session : g_workspaceSessions) {
        if (workspaceSessionMatchesWindow(session, window))
            moveRelatedWindowToSessionWorkspace(session, window);
    }
}

void handleWorkspaceSessionWindowOpenEarly(const PHLWINDOW& window) {
    if (!window || g_workspaceSessions.empty())
        return;

    for (auto& session : g_workspaceSessions) {
        if (workspaceSessionMatchesWindow(session, window, false))
            placeRelatedWindowOnRootWorkspaceEarly(session, window);
    }
}

std::optional<TargetSurface> resolveTargetSurface(const std::string& targetRegex, const Vector2D& globalPos) {
    if (!g_pCompositor)
        return std::nullopt;

    auto window = Desktop::viewState()->query().selector(targetRegex).mappedOnly().runWindow();
    if (!window || !window->m_isMapped)
        return std::nullopt;

    window = xwaylandRelatedWindowAt(window, globalPos);

    if (window->m_isX11) {
        if (!window->wlSurface() || !window->wlSurface()->resource())
            return std::nullopt;

        const auto mainBox = windowMainSurfaceGoalBox(window);
        Vector2D   local = globalPos - mainBox.pos();
        const auto scale = window->m_X11SurfaceScaledBy <= 0.0F ? 1.0F : window->m_X11SurfaceScaledBy;
        local = local * scale;
        return TargetSurface{.window = window, .surface = window->wlSurface()->resource(), .local = local};
    }

    Vector2D local;
    const auto mainBox = windowMainSurfaceGoalBox(window);
    auto [surface, surfaceLocal] = window->wlSurface()->resource()->at(globalPos - mainBox.pos(), true);
    local = surfaceLocal;
    if (!surface && window->wlSurface() && window->wlSurface()->resource()) {
        local = globalPos - mainBox.pos();
        surface = window->wlSurface()->resource();
    }

    if (!surface)
        return std::nullopt;
    return TargetSurface{.window = window, .surface = surface, .local = local};
}

std::optional<Vector2D> targetPointToGlobal(const std::string& targetRegex, const Vector2D& point, bool windowRelative) {
    if (!windowRelative)
        return point;
    if (!g_pCompositor)
        return std::nullopt;

    const auto window = Desktop::viewState()->query().selector(targetRegex).mappedOnly().runWindow();
    if (!window || !window->m_isMapped)
        return std::nullopt;

    const auto box = windowMainSurfaceGoalBox(window);
    return Vector2D(box.x + point.x, box.y + point.y);
}

std::optional<TargetSurface> resolveTargetSurfaceForPoint(const std::string& targetRegex, const Vector2D& point, bool windowRelative) {
    const auto global = targetPointToGlobal(targetRegex, point, windowRelative);
    if (!global)
        return std::nullopt;
    return resolveTargetSurface(targetRegex, *global);
}

std::optional<TargetSurface> resolveTargetMainSurface(const std::string& targetRegex) {
    if (!g_pCompositor)
        return std::nullopt;

    const auto window = Desktop::viewState()->query().selector(targetRegex).mappedOnly().runWindow();
    if (!window || !window->m_isMapped || !window->wlSurface() || !window->wlSurface()->resource())
        return std::nullopt;

    const auto mainBox = windowMainSurfaceGoalBox(window);
    return TargetSurface{.window = window, .surface = window->wlSurface()->resource(), .local = mainBox.middle()};
}

struct PointerFocusRestore {
    SP<CWLSurfaceResource> previousSurface;
    Vector2D               previousLocal;
    bool                   restored = false;

    PointerFocusRestore() {
        if (!g_pSeatManager)
            return;
        previousSurface = g_pSeatManager->m_state.pointerFocus.lock();
        previousLocal = g_pSeatManager->m_lastLocalCoords;
    }

    ~PointerFocusRestore() {
        restoreNow(false);
    }

    void restoreNow(bool resetCurrentXWaylandFocus) {
        if (restored || !g_pSeatManager)
            return;

        if (resetCurrentXWaylandFocus) {
            g_pSeatManager->m_state.pointerFocus.reset();
            g_pSeatManager->m_state.pointerFocusResource.reset();
        }

        restored = true;
        g_pSeatManager->setPointerFocus(previousSurface, previousLocal);
        g_pSeatManager->sendPointerFrame();
    }

    void restoreLater(Time::steady_dur delay, bool resetCurrentXWaylandFocus) {
        if (restored || !g_pEventLoopManager)
            return;

        auto previous = previousSurface;
        auto local = previousLocal;
        auto timer = makeShared<CEventLoopTimer>(
            delay,
            [previous, local, resetCurrentXWaylandFocus](SP<CEventLoopTimer> self, void*) {
                if (g_pSeatManager) {
                    if (resetCurrentXWaylandFocus) {
                        g_pSeatManager->m_state.pointerFocus.reset();
                        g_pSeatManager->m_state.pointerFocusResource.reset();
                    }
                    g_pSeatManager->setPointerFocus(previous, local);
                    g_pSeatManager->sendPointerFrame();
                }

                if (g_pEventLoopManager)
                    g_pEventLoopManager->removeTimer(self);

                g_pointerRestoreTimers.erase(
                    std::remove_if(g_pointerRestoreTimers.begin(), g_pointerRestoreTimers.end(), [&self](const auto& item) { return item.get() == self.get(); }),
                    g_pointerRestoreTimers.end());
            },
            nullptr);

        restored = true;
        g_pointerRestoreTimers.push_back(timer);
        g_pEventLoopManager->addTimer(timer);
    }

    void restoreForTarget(const TargetSurface& target) {
        if (!g_pSeatManager)
            return;

        if (target.window && target.window->m_isX11) {
            restoreLater(std::chrono::milliseconds(75), true);
            return;
        }

        restoreNow(false);
    }

    PointerFocusRestore(const PointerFocusRestore&) = delete;
    PointerFocusRestore& operator=(const PointerFocusRestore&) = delete;
};

struct KeyboardStateSnapshot {
    std::vector<uint32_t> pressedKeys;
    uint32_t              depressed = 0;
    uint32_t              latched   = 0;
    uint32_t              locked    = 0;
    uint32_t              group     = 0;
};

KeyboardStateSnapshot physicalKeyboardState() {
    KeyboardStateSnapshot state;
    if (g_pInputManager)
        state.pressedKeys = g_pInputManager->getKeysFromAllKBs();

    const auto activeKeyboard = g_pSeatManager ? g_pSeatManager->m_keyboard.lock() : nullptr;
    if (!activeKeyboard)
        return state;

    state.depressed = activeKeyboard->m_modifiersState.depressed;
    state.latched   = activeKeyboard->m_modifiersState.latched;
    state.locked    = activeKeyboard->m_modifiersState.locked;
    state.group     = activeKeyboard->m_modifiersState.group;

    if (!g_pInputManager)
        return state;

    for (const auto& keyboard : g_pInputManager->m_keyboards) {
        if (!keyboard || !keyboard->m_enabled || !keyboard->shareStates() ||
            (keyboard->isVirtual() && g_pInputManager->shouldIgnoreVirtualKeyboard(keyboard)))
            continue;
        state.depressed |= keyboard->m_modifiersState.depressed;
        state.latched |= keyboard->m_modifiersState.latched;
        state.locked |= keyboard->m_modifiersState.locked;
    }
    return state;
}

void fillPressedKeysArray(wl_array& keys, const std::vector<uint32_t>& pressedKeys) {
    wl_array_init(&keys);
    if (pressedKeys.empty())
        return;

    const auto byteCount = pressedKeys.size() * sizeof(uint32_t);
    if (auto* storage = static_cast<uint32_t*>(wl_array_add(&keys, byteCount)); storage)
        std::copy(pressedKeys.begin(), pressedKeys.end(), storage);
}

// A target client may temporarily see a keyboard enter/key/leave sequence, but the
// compositor's global keyboard focus and every other Wayland client remain untouched.
class KeyboardResourceTransaction {
  public:
    explicit KeyboardResourceTransaction(SP<CWLSurfaceResource> target) : m_target(std::move(target)), m_physicalState(physicalKeyboardState()) {
        if (!m_target || !PROTO::seat)
            return;

        wl_array emptyKeys;
        wl_array_init(&emptyKeys);
        for (const auto& keyboard : PROTO::seat->m_keyboards) {
            if (!keyboard)
                continue;
            const auto owner = keyboard->m_owner.lock();
            if (!owner || owner->client() != m_target->client())
                continue;

            const auto previousSurface = keyboard->m_currentSurface.lock();
            if (previousSurface != m_target)
                keyboard->sendEnter(m_target, &emptyKeys);
            if (keyboard->m_currentSurface.lock() == m_target)
                m_endpoints.push_back({.keyboard = keyboard, .previousSurface = previousSurface});
        }
        wl_array_release(&emptyKeys);
    }

    ~KeyboardResourceTransaction() {
        restore();
    }

    bool ready() const {
        return !m_endpoints.empty();
    }

    void sendKey(uint32_t key, wl_keyboard_key_state state) {
        const auto timestamp = nowMs();
        for (const auto& endpoint : m_endpoints)
            endpoint.keyboard->sendKey(timestamp, key, state);
    }

    void sendModifierKey(uint32_t key, wl_keyboard_key_state state) {
        const auto timestamp = nowMs();
        for (const auto& endpoint : m_endpoints) {
            if (endpoint.previousSurface == m_target && physicalKeyHeld(key))
                continue;
            endpoint.keyboard->sendKey(timestamp, key, state);
        }
    }

    bool targetKeyConflictsWithPhysicalInput(uint32_t key) const {
        if (!physicalKeyHeld(key))
            return false;
        return std::any_of(m_endpoints.begin(), m_endpoints.end(), [this](const auto& endpoint) { return endpoint.previousSurface == m_target; });
    }

    void sendMods(uint32_t depressed, uint32_t latched = 0, uint32_t locked = 0, uint32_t group = 0) {
        for (const auto& endpoint : m_endpoints)
            endpoint.keyboard->sendMods(depressed, latched, locked, group);
    }

    void flushTargetClient() const {
        if (m_target && m_target->client())
            wl_client_flush(m_target->client());
    }

    KeyboardResourceTransaction(const KeyboardResourceTransaction&) = delete;
    KeyboardResourceTransaction& operator=(const KeyboardResourceTransaction&) = delete;

  private:
    struct Endpoint {
        SP<CWLKeyboardResource> keyboard;
        SP<CWLSurfaceResource>  previousSurface;
    };

    bool physicalKeyHeld(uint32_t key) const {
        return std::find(m_physicalState.pressedKeys.begin(), m_physicalState.pressedKeys.end(), key) != m_physicalState.pressedKeys.end();
    }

    void restore() {
        if (m_restored)
            return;
        m_restored = true;

        wl_array pressedKeys;
        fillPressedKeysArray(pressedKeys, m_physicalState.pressedKeys);
        for (const auto& endpoint : m_endpoints) {
            if (endpoint.previousSurface != m_target) {
                if (endpoint.keyboard->m_currentSurface.lock() == m_target)
                    endpoint.keyboard->sendLeave();
                if (endpoint.previousSurface) {
                    endpoint.keyboard->sendEnter(endpoint.previousSurface, &pressedKeys);
                    endpoint.keyboard->sendMods(m_physicalState.depressed, m_physicalState.latched, m_physicalState.locked, m_physicalState.group);
                }
            } else {
                endpoint.keyboard->sendMods(m_physicalState.depressed, m_physicalState.latched, m_physicalState.locked, m_physicalState.group);
            }
        }
        wl_array_release(&pressedKeys);
        flushTargetClient();
    }

    SP<CWLSurfaceResource> m_target;
    KeyboardStateSnapshot  m_physicalState;
    std::vector<Endpoint>  m_endpoints;
    bool                   m_restored = false;
};

struct XWaylandKeyboardLease {
    WP<CXWaylandSurface> previous;
    WP<CXWaylandSurface> target;
    bool                 active = false;
};

XWaylandKeyboardLease g_xwaylandKeyboardLease;

void cancelXWaylandKeyboardRestoreTimer() {
    if (g_xwaylandKeyboardRestoreTimer && g_pEventLoopManager)
        g_pEventLoopManager->removeTimer(g_xwaylandKeyboardRestoreTimer);
    g_xwaylandKeyboardRestoreTimer.reset();
}

void syncXWaylandFocus() {
    if (!g_pXWayland || !g_pXWayland->m_wm)
        return;
    auto* connection = g_pXWayland->m_wm->getConnection();
    if (!connection)
        return;

    xcb_generic_error_t* error = nullptr;
    auto* reply = xcb_get_input_focus_reply(connection, xcb_get_input_focus(connection), &error);
    std::free(reply);
    std::free(error);
}

void restoreXWaylandKeyboardFocus() {
    cancelXWaylandKeyboardRestoreTimer();
    if (!g_xwaylandKeyboardLease.active)
        return;

    const auto previous = g_xwaylandKeyboardLease.previous.lock();
    const auto target   = g_xwaylandKeyboardLease.target.lock();
    g_xwaylandKeyboardLease = {};

    if (!g_pXWayland || !g_pXWayland->m_wm || !target)
        return;
    if (previous)
        previous->activate(true);
    else
        target->activate(false);
    syncXWaylandFocus();
}

bool activateXWaylandKeyboardTarget(const TargetSurface& target) {
    if (!target.window || !target.window->m_isX11 || !target.window->m_xwaylandSurface || !g_pXWayland || !g_pXWayland->m_wm)
        return false;

    const auto xTarget = target.window->m_xwaylandSurface;
    if (g_xwaylandKeyboardLease.active) {
        cancelXWaylandKeyboardRestoreTimer();
        if (g_pXWayland->m_wm->m_focusedSurface.lock() != xTarget) {
            xTarget->activate(true);
            syncXWaylandFocus();
            if (g_pXWayland->m_wm->m_focusedSurface.lock() != xTarget) {
                restoreXWaylandKeyboardFocus();
                return false;
            }
            g_xwaylandKeyboardLease.target = xTarget;
        }
        return true;
    }

    const auto previous = g_pXWayland->m_wm->m_focusedSurface.lock();
    if (previous == xTarget)
        return false;

    xTarget->activate(true);
    syncXWaylandFocus();
    if (g_pXWayland->m_wm->m_focusedSurface.lock() != xTarget)
        return false;

    g_xwaylandKeyboardLease = {.previous = previous, .target = xTarget, .active = true};
    return true;
}

void restoreXWaylandKeyboardFocusLater(std::chrono::milliseconds delay) {
    if (!g_xwaylandKeyboardLease.active)
        return;
    if (!g_pEventLoopManager || delay.count() <= 0) {
        restoreXWaylandKeyboardFocus();
        return;
    }

    cancelXWaylandKeyboardRestoreTimer();
    g_xwaylandKeyboardRestoreTimer = makeShared<CEventLoopTimer>(
        delay,
        [](SP<CEventLoopTimer>, void*) { restoreXWaylandKeyboardFocus(); },
        nullptr);
    g_pEventLoopManager->addTimer(g_xwaylandKeyboardRestoreTimer);
}

void sendClipboardSelectionToNativeTarget(const TargetSurface& target) {
    if (!target.surface || (target.window && target.window->m_isX11) || !PROTO::data || !g_pSeatManager)
        return;

    const auto selection = g_pSeatManager->m_selection.currentSelection.lock();
    const auto device    = PROTO::data->dataDeviceForClient(target.surface->client());
    if (selection && device)
        PROTO::data->sendSelectionToDevice(device, selection);
}

void activateXWaylandTarget(const TargetSurface& target) {
    if (activateXWaylandKeyboardTarget(target))
        restoreXWaylandKeyboardFocusLater(std::chrono::milliseconds(1000));
}

void sendPointerScroll(double dx, double dy) {
    const auto sendAxis = [](wl_pointer_axis axis, double ticks) {
        if (std::abs(ticks) < 0.001)
            return;
        const auto discrete = static_cast<int32_t>(ticks > 0 ? std::ceil(ticks) : std::floor(ticks));
        const auto value120 = static_cast<int32_t>(std::round(ticks * 120.0));
        g_pSeatManager->sendPointerAxis(nowMs(), axis, ticks * 15.0, discrete, value120, WL_POINTER_AXIS_SOURCE_WHEEL, WL_POINTER_AXIS_RELATIVE_DIRECTION_IDENTICAL);
    };

    sendAxis(WL_POINTER_AXIS_HORIZONTAL_SCROLL, dx);
    sendAxis(WL_POINTER_AXIS_VERTICAL_SCROLL, dy);
    g_pSeatManager->sendPointerFrame();
}

SDispatchResult dispatchPointerWithMode(const std::string& args, bool windowRelative) {
    if (!configBool("allow_pointer", true))
        return {.success = false, .error = "hypr-agent-protal pointer dispatch is disabled"};
    if (!g_pSeatManager)
        return {.success = false, .error = "seat manager is not ready"};

    const auto parts = splitCsv(args);
    if (parts.size() < 4)
        return {.success = false,
                .error = "usage: hypr-agent-protal:pointer <window-regex>,<x>,<y>,<move|click|press|release|drag>[,<button>][,<drag-x>,<drag-y>,<duration-sec>]"};

    const auto x = parseDouble(parts[1]);
    const auto y = parseDouble(parts[2]);
    if (!x || !y)
        return {.success = false, .error = "pointer coordinates must be finite numbers"};

    const Vector2D inputPoint{*x, *y};
    const auto     globalPoint = targetPointToGlobal(parts[0], inputPoint, windowRelative);
    if (!globalPoint)
        return {.success = false, .error = "target window not found"};

    const auto target = resolveTargetSurface(parts[0], *globalPoint);
    if (!target)
        return {.success = false, .error = "target window/surface not found"};

    const auto action = lower(parts[3]);
    const auto button = pointerButton(parts.size() >= 5 ? parts[4] : "left");
    if (!button && action != "move" && action != "motion" && action != "scroll")
        return {.success = false, .error = "unknown pointer button"};

    PointerFocusRestore restore;
    activateXWaylandTarget(*target);
    g_pSeatManager->setPointerFocus(target->surface, target->local);
    g_pSeatManager->sendPointerMotion(nowMs(), target->local);

    if (action == "move" || action == "motion") {
        g_pSeatManager->sendPointerFrame();
        showAgentIndicator(target->window, *globalPoint, action);
        restore.restoreForTarget(*target);
        return {.success = true};
    }

    if (action == "scroll") {
        const auto dy = parts.size() >= 5 ? parseDouble(parts[4]) : std::optional<double>{1.0};
        const auto dx = parts.size() >= 6 ? parseDouble(parts[5]) : std::optional<double>{0.0};
        if (!dx || !dy)
            return {.success = false, .error = "scroll dx/dy must be finite numbers"};
        showAgentIndicator(target->window, *globalPoint, action);
        sendPointerScroll(*dx, *dy);
        restore.restoreLater(std::chrono::milliseconds(90), false);
        return {.success = true};
    }

    if (action == "drag") {
        if (parts.size() < 7)
            return {.success = false, .error = "drag requires destination x and y"};
        const auto x2 = parseDouble(parts[5]);
        const auto y2 = parseDouble(parts[6]);
        const auto duration = parts.size() >= 8 ? parseDouble(parts[7]) : std::optional<double>{0.2};
        if (!x2 || !y2 || !duration)
            return {.success = false, .error = "drag destination and duration must be finite numbers"};

        g_pSeatManager->sendPointerButton(nowMs(), *button, WL_POINTER_BUTTON_STATE_PRESSED);
        g_pSeatManager->sendPointerFrame();

        const double durationSec = std::clamp(*duration, 0.0, 3.0);
        const int    steps       = std::clamp(static_cast<int>(std::round(std::max(0.05, durationSec) * 60.0)), 4, 60);

        if (g_pEventLoopManager && durationSec > 0.0) {
            struct DragState {
                std::string                  selector;
                Vector2D                     start;
                Vector2D                     end;
                bool                         windowRelative = false;
                uint32_t                     button = 0;
                SP<CWLSurfaceResource>       previousSurface;
                Vector2D                     previousLocal;
                std::optional<TargetSurface> lastTarget;
                Vector2D                     lastGlobal;
            };

            auto state = std::make_shared<DragState>();
            state->selector = parts[0];
            state->start = inputPoint;
            state->end = Vector2D{*x2, *y2};
            state->windowRelative = windowRelative;
            state->button = *button;
            state->previousSurface = restore.previousSurface;
            state->previousLocal = restore.previousLocal;
            state->lastTarget = *target;
            state->lastGlobal = *globalPoint;
            restore.restored = true;

            const int durationMs = std::max(1, static_cast<int>(std::round(durationSec * 1000.0)));
            for (int step = 1; step <= steps; ++step) {
                const double   t = static_cast<double>(step) / static_cast<double>(steps);
                const Vector2D point{state->start.x + ((state->end.x - state->start.x) * t), state->start.y + ((state->end.y - state->start.y) * t)};
                const int      delayMs = std::max(1, static_cast<int>(std::round(durationMs * t)));
                auto           timer = makeShared<CEventLoopTimer>(
                    std::chrono::milliseconds(delayMs),
                    [state, point](SP<CEventLoopTimer> self, void*) {
                        if (g_pSeatManager) {
                            const auto global = targetPointToGlobal(state->selector, point, state->windowRelative);
                            const auto stepTarget = global ? resolveTargetSurface(state->selector, *global) : std::optional<TargetSurface>{};
                            if (stepTarget) {
                                state->lastTarget = *stepTarget;
                                state->lastGlobal = *global;
                                g_pSeatManager->setPointerFocus(stepTarget->surface, stepTarget->local);
                                g_pSeatManager->sendPointerMotion(nowMs(), stepTarget->local);
                                g_pSeatManager->sendPointerFrame();
                            }
                        }
                        removePointerTimer(self);
                    },
                    nullptr);
                g_pointerRestoreTimers.push_back(timer);
                g_pEventLoopManager->addTimer(timer);
            }

            auto releaseTimer = makeShared<CEventLoopTimer>(
                std::chrono::milliseconds(durationMs + 1),
                [state](SP<CEventLoopTimer> self, void*) {
                    if (g_pSeatManager && state->lastTarget) {
                        if (const auto finalGlobal = targetPointToGlobal(state->selector, state->end, state->windowRelative)) {
                            state->lastGlobal = *finalGlobal;
                            if (const auto finalTarget = resolveTargetSurface(state->selector, *finalGlobal))
                                state->lastTarget = *finalTarget;
                        }
                        const auto target = *state->lastTarget;
                        g_pSeatManager->setPointerFocus(target.surface, target.local);
                        g_pSeatManager->sendPointerMotion(nowMs(), target.local);
                        g_pSeatManager->sendPointerButton(nowMs(), state->button, WL_POINTER_BUTTON_STATE_RELEASED);
                        g_pSeatManager->sendPointerFrame();
                        showAgentIndicator(target.window, state->lastGlobal, "drag");

                        if (target.window && target.window->m_isX11) {
                            g_pSeatManager->m_state.pointerFocus.reset();
                            g_pSeatManager->m_state.pointerFocusResource.reset();
                        }
                        g_pSeatManager->setPointerFocus(state->previousSurface, state->previousLocal);
                        g_pSeatManager->sendPointerFrame();
                    }
                    removePointerTimer(self);
                },
                nullptr);
            g_pointerRestoreTimers.push_back(releaseTimer);
            g_pEventLoopManager->addTimer(releaseTimer);
            return {.success = true};
        }

        TargetSurface lastTarget = *target;
        Vector2D      lastGlobal = *globalPoint;
        for (int step = 1; step <= steps; ++step) {
            const double   t = static_cast<double>(step) / static_cast<double>(steps);
            const Vector2D point{inputPoint.x + ((*x2 - inputPoint.x) * t), inputPoint.y + ((*y2 - inputPoint.y) * t)};
            const auto     global = targetPointToGlobal(parts[0], point, windowRelative);
            const auto     stepTarget = global ? resolveTargetSurface(parts[0], *global) : std::optional<TargetSurface>{};
            if (!stepTarget)
                continue;
            lastTarget = *stepTarget;
            lastGlobal = *global;
            g_pSeatManager->setPointerFocus(lastTarget.surface, lastTarget.local);
            g_pSeatManager->sendPointerMotion(nowMs(), lastTarget.local);
            g_pSeatManager->sendPointerFrame();
        }
        g_pSeatManager->sendPointerButton(nowMs(), *button, WL_POINTER_BUTTON_STATE_RELEASED);
        g_pSeatManager->sendPointerFrame();
        showAgentIndicator(lastTarget.window, lastGlobal, action);
        restore.restoreForTarget(lastTarget);
        return {.success = true};
    }

    if (action == "click") {
        showAgentIndicator(target->window, *globalPoint, action);
        g_pSeatManager->sendPointerButton(nowMs(), *button, WL_POINTER_BUTTON_STATE_PRESSED);
        g_pSeatManager->sendPointerButton(nowMs(), *button, WL_POINTER_BUTTON_STATE_RELEASED);
        g_pSeatManager->sendPointerFrame();
        restore.restoreLater(std::chrono::milliseconds(120), target->window && target->window->m_isX11);
        return {.success = true};
    }

    if (action == "doubleclick" || action == "double-click") {
        showAgentIndicator(target->window, *globalPoint, action);
        g_pSeatManager->sendPointerButton(nowMs(), *button, WL_POINTER_BUTTON_STATE_PRESSED);
        g_pSeatManager->sendPointerButton(nowMs(), *button, WL_POINTER_BUTTON_STATE_RELEASED);
        g_pSeatManager->sendPointerFrame();

        if (!g_pEventLoopManager) {
            restore.restoreForTarget(*target);
            return {.success = true};
        }

        const auto previousSurface = restore.previousSurface;
        const auto previousLocal = restore.previousLocal;
        const auto targetSelector = parts[0];
        const auto targetInput = inputPoint;
        const bool targetWindowRelative = windowRelative;
        const auto targetButton = *button;
        restore.restored = true;

        auto timer = makeShared<CEventLoopTimer>(
            std::chrono::milliseconds(180),
            [previousSurface, previousLocal, targetSelector, targetInput, targetWindowRelative, targetButton](SP<CEventLoopTimer> self, void*) mutable {
                const auto target = resolveTargetSurfaceForPoint(targetSelector, targetInput, targetWindowRelative);
                if (g_pSeatManager && target) {
                    g_pSeatManager->setPointerFocus(target->surface, target->local);
                    g_pSeatManager->sendPointerMotion(nowMs(), target->local);
                    g_pSeatManager->sendPointerButton(nowMs(), targetButton, WL_POINTER_BUTTON_STATE_PRESSED);
                    g_pSeatManager->sendPointerButton(nowMs(), targetButton, WL_POINTER_BUTTON_STATE_RELEASED);
                    g_pSeatManager->sendPointerFrame();
                }

                if (target) {
                    const auto targetGlobal = targetPointToGlobal(targetSelector, targetInput, targetWindowRelative);
                    showAgentIndicator(target->window, targetGlobal.value_or(target->window->getFullWindowBoundingBox().middle()), "doubleclick");
                }

                if (g_pSeatManager) {
                    if (target && target->window && target->window->m_isX11) {
                        g_pSeatManager->m_state.pointerFocus.reset();
                        g_pSeatManager->m_state.pointerFocusResource.reset();
                    }
                    g_pSeatManager->setPointerFocus(previousSurface, previousLocal);
                    g_pSeatManager->sendPointerFrame();
                }

                if (g_pEventLoopManager)
                    g_pEventLoopManager->removeTimer(self);

                g_pointerRestoreTimers.erase(
                    std::remove_if(g_pointerRestoreTimers.begin(), g_pointerRestoreTimers.end(), [&self](const auto& item) { return item.get() == self.get(); }),
                    g_pointerRestoreTimers.end());
            },
            nullptr);

        g_pointerRestoreTimers.push_back(timer);
        g_pEventLoopManager->addTimer(timer);
        return {.success = true};
    }

    if (action == "press" || action == "down") {
        showAgentIndicator(target->window, *globalPoint, action);
        g_pSeatManager->sendPointerButton(nowMs(), *button, WL_POINTER_BUTTON_STATE_PRESSED);
        g_pSeatManager->sendPointerFrame();
        restore.restoreForTarget(*target);
        return {.success = true};
    }

    if (action == "release" || action == "up") {
        showAgentIndicator(target->window, *globalPoint, action);
        g_pSeatManager->sendPointerButton(nowMs(), *button, WL_POINTER_BUTTON_STATE_RELEASED);
        g_pSeatManager->sendPointerFrame();
        restore.restoreForTarget(*target);
        return {.success = true};
    }

    return {.success = false, .error = "unknown pointer action"};
}

SDispatchResult dispatchPointer(const std::string& args) {
    return dispatchPointerWithMode(args, false);
}

SDispatchResult dispatchPointerRelative(const std::string& args) {
    return dispatchPointerWithMode(args, true);
}

SDispatchResult dispatchIndicator(const std::string& args) {
    if (!g_pCompositor)
        return {.success = false, .error = "compositor is not ready"};

    const auto parts = splitCsv(args);
    if (parts.size() < 3)
        return {.success = false, .error = "usage: hypr-agent-protal:indicator <window-regex>,<global-x>,<global-y>[,<action>]"};

    const auto x = parseDouble(parts[1]);
    const auto y = parseDouble(parts[2]);
    if (!x || !y)
        return {.success = false, .error = "indicator coordinates must be finite numbers"};

    auto window = Desktop::viewState()->query().selector(parts[0]).mappedOnly().runWindow();
    if (!window || !window->m_isMapped)
        return {.success = false, .error = "target window not found"};

    const Vector2D global{*x, *y};
    window = xwaylandRelatedWindowAt(window, global);
    const auto action = parts.size() >= 4 ? lower(parts[3]) : std::string{"move"};
    showAgentIndicator(window, global, action);
    return {.success = true};
}

SDispatchResult dispatchKeyboard(const std::string& args) {
    if (!configBool("allow_keyboard", true))
        return {.success = false, .error = "hypr-agent-protal keyboard dispatch is disabled"};
    if (!g_pSeatManager)
        return {.success = false, .error = "seat manager is not ready"};

    const auto parts = splitCsv(args);
    if (parts.size() < 3)
        return {.success = false, .error = "usage: hypr-agent-protal:keyboard <window-regex>,<tap|press|release>,<key>[,<modifiers>][,<global-x>,<global-y>]"};

    std::optional<TargetSurface> target;
    std::optional<Vector2D>      indicatorGlobal;
    if (parts.size() >= 6) {
        const auto x = parseDouble(parts[4]);
        const auto y = parseDouble(parts[5]);
        if (!x || !y)
            return {.success = false, .error = "keyboard focus coordinates must be finite numbers"};
        indicatorGlobal = Vector2D{*x, *y};
        target = resolveTargetSurface(parts[0], Vector2D{*x, *y});
    } else {
        target = resolveTargetMainSurface(parts[0]);
    }
    if (!target)
        return {.success = false, .error = "target window/surface not found"};

    const auto action = lower(parts[1]);
    const auto key = keyboardKey(parts[2]);
    if (!key)
        return {.success = false, .error = "unknown keyboard key"};

    std::vector<KeyboardModifier> modifiers;
    uint32_t                      modifierMask = 0;
    if (parts.size() >= 4) {
        for (const auto& name : splitCombo(parts[3])) {
            auto mod = keyboardModifier(name);
            if (!mod)
                return {.success = false, .error = "unknown keyboard modifier"};
            modifierMask |= mod->mask;
            modifiers.push_back(*mod);
        }
    }

    const bool xwaylandLease = activateXWaylandKeyboardTarget(*target);
    showAgentIndicator(target->window, indicatorGlobal.value_or(windowMainSurfaceGoalBox(target->window).middle()), "key");

    KeyboardResourceTransaction transaction(target->surface);
    if (!transaction.ready()) {
        if (xwaylandLease)
            restoreXWaylandKeyboardFocus();
        return {.success = false, .error = "target client has no keyboard resource"};
    }
    if (transaction.targetKeyConflictsWithPhysicalInput(*key)) {
        if (xwaylandLease)
            restoreXWaylandKeyboardFocus();
        return {.success = false, .error = "target key is currently held by the physical keyboard"};
    }

    if (*key == KEY_V && (modifierMask & (1U << 2)) != 0)
        sendClipboardSelectionToNativeTarget(*target);

    const auto pressModifiers = [&] {
        for (const auto& mod : modifiers)
            transaction.sendModifierKey(mod.key, WL_KEYBOARD_KEY_STATE_PRESSED);
        transaction.sendMods(modifierMask, 0, 0, 0);
    };

    const auto releaseModifiers = [&] {
        transaction.sendMods(0, 0, 0, 0);
        for (auto it = modifiers.rbegin(); it != modifiers.rend(); ++it)
            transaction.sendModifierKey(it->key, WL_KEYBOARD_KEY_STATE_RELEASED);
    };

    if (action == "tap" || action == "press-release") {
        pressModifiers();
        transaction.sendKey(*key, WL_KEYBOARD_KEY_STATE_PRESSED);
        transaction.sendKey(*key, WL_KEYBOARD_KEY_STATE_RELEASED);
        releaseModifiers();
        transaction.flushTargetClient();
        if (xwaylandLease)
            restoreXWaylandKeyboardFocusLater(std::chrono::milliseconds(modifierMask != 0 ? xwaylandKeyboardRestoreDelayMs() : 90));
        return {.success = true};
    }

    if (action == "press" || action == "down") {
        pressModifiers();
        transaction.sendKey(*key, WL_KEYBOARD_KEY_STATE_PRESSED);
        transaction.flushTargetClient();
        if (xwaylandLease)
            restoreXWaylandKeyboardFocusLater(std::chrono::milliseconds(90));
        return {.success = true};
    }

    if (action == "release" || action == "up") {
        transaction.sendKey(*key, WL_KEYBOARD_KEY_STATE_RELEASED);
        releaseModifiers();
        transaction.flushTargetClient();
        if (xwaylandLease)
            restoreXWaylandKeyboardFocusLater(std::chrono::milliseconds(90));
        return {.success = true};
    }

    if (xwaylandLease)
        restoreXWaylandKeyboardFocus();
    return {.success = false, .error = "unknown keyboard action"};
}

SDispatchResult dispatchScreenshot(const std::string& args) {
    if (!configBool("allow_screenshot", true))
        return {.success = false, .error = "hypr-agent-protal screenshot dispatch is disabled"};

    const auto parts = splitCsv(args);
    const auto path = parts.empty() ? std::string{} : trim(parts[0]);
    if (path.empty())
        return {.success = false, .error = "usage: hypr-agent-protal:screenshot <output-session-json-path>[,<window-regex>]"};

    const auto target = parts.size() >= 2 ? trim(parts[1]) : std::string{};
    const auto result = hypr_agent_protal::captureScreenshotSession(std::filesystem::path(path), target);
    if (!result.success)
        return {.success = false, .error = result.error};
    return {.success = true};
}

SDispatchResult dispatchSession(const std::string& args) {
    if (!configBool("allow_session", true))
        return {.success = false, .error = "hypr-agent-protal session dispatch is disabled"};
    if (!g_pCompositor)
        return {.success = false, .error = "compositor is not ready"};

    const auto parts = splitCsv(args);
    if (parts.empty())
        return {.success = false, .error = "usage: hypr-agent-protal:session <begin|sync|end>[,<window-regex>]"};

    const auto action = lower(parts[0]);
    if (action == "begin") {
        if (parts.size() < 2)
            return {.success = false, .error = "session begin requires a target window selector"};

        const auto root = Desktop::viewState()->query().selector(parts[1]).mappedOnly().runWindow();
        if (!root || !root->m_isMapped)
            return {.success = false, .error = "target window not found"};

        auto existing = std::find_if(g_workspaceSessions.begin(), g_workspaceSessions.end(), [&root](const auto& session) { return session.root.lock() == root; });
        if (existing == g_workspaceSessions.end()) {
            g_workspaceSessions.push_back({
                .root = PHLWINDOWREF{root},
                .pid = root->getPID(),
                .targetWorkspace = root->m_workspace,
            });
            existing = std::prev(g_workspaceSessions.end());
        } else {
            existing->targetWorkspace = root->m_workspace;
        }

        syncWorkspaceSession(*existing);
        return {.success = true};
    }

    if (action == "sync") {
        if (parts.size() >= 2) {
            const auto root = Desktop::viewState()->query().selector(parts[1]).mappedOnly().runWindow();
            if (!root)
                return {.success = false, .error = "target window not found"};
            auto existing = std::find_if(g_workspaceSessions.begin(), g_workspaceSessions.end(), [&root](const auto& session) { return session.root.lock() == root; });
            if (existing == g_workspaceSessions.end())
                return {.success = false, .error = "target session not found"};
            syncWorkspaceSession(*existing);
        } else {
            for (auto& session : g_workspaceSessions)
                syncWorkspaceSession(session);
        }
        return {.success = true};
    }

    if (action == "end") {
        if (parts.size() >= 2) {
            const auto root = Desktop::viewState()->query().selector(parts[1]).mappedOnly().runWindow();
            if (!root)
                return {.success = false, .error = "target window not found"};

            const auto oldSize = g_workspaceSessions.size();
            g_workspaceSessions.erase(std::remove_if(g_workspaceSessions.begin(), g_workspaceSessions.end(), [&root](auto& session) { return session.root.lock() == root; }),
                                      g_workspaceSessions.end());
            if (g_workspaceSessions.size() == oldSize)
                return {.success = false, .error = "target session not found"};
        } else {
            g_workspaceSessions.clear();
        }
        return {.success = true};
    }

    return {.success = false, .error = "unknown session action"};
}

enum class eLuaDispatcher : int {
    POINTER,
    POINTER_RELATIVE,
    INDICATOR,
    KEYBOARD,
    SCREENSHOT,
    SESSION,
};

SDispatchResult dispatchLuaPayload(eLuaDispatcher dispatcher, const std::string& payload) {
    switch (dispatcher) {
        case eLuaDispatcher::POINTER: return dispatchPointer(payload);
        case eLuaDispatcher::POINTER_RELATIVE: return dispatchPointerRelative(payload);
        case eLuaDispatcher::INDICATOR: return dispatchIndicator(payload);
        case eLuaDispatcher::KEYBOARD: return dispatchKeyboard(payload);
        case eLuaDispatcher::SCREENSHOT: return dispatchScreenshot(payload);
        case eLuaDispatcher::SESSION: return dispatchSession(payload);
    }

    return {.success = false, .error = "unknown hypr-agent-protal lua dispatcher"};
}

int pushLuaDispatchResult(lua_State* L, const SDispatchResult& result) {
    lua_newtable(L);
    lua_pushboolean(L, result.success);
    lua_setfield(L, -2, "ok");
    lua_pushboolean(L, result.passEvent);
    lua_setfield(L, -2, "pass_event");
    if (!result.success) {
        lua_pushstring(L, result.error.c_str());
        lua_setfield(L, -2, "error");
    }
    return 1;
}

int luaDispatchClosure(lua_State* L) {
    const auto dispatcher = static_cast<eLuaDispatcher>(lua_tointeger(L, lua_upvalueindex(1)));
    const auto payloadArg = lua_tostring(L, lua_upvalueindex(2));
    const auto payload    = std::string{payloadArg ? payloadArg : ""};
    return pushLuaDispatchResult(L, dispatchLuaPayload(dispatcher, payload));
}

int makeLuaDispatcher(lua_State* L, eLuaDispatcher dispatcher) {
    const auto* payload = luaL_checkstring(L, 1);
    lua_pushinteger(L, static_cast<lua_Integer>(dispatcher));
    lua_pushstring(L, payload ? payload : "");
    lua_pushcclosure(L, luaDispatchClosure, 2);
    return Config::Lua::Bindings::Internal::wrapDispatcher(L);
}

int luaPointer(lua_State* L) {
    return makeLuaDispatcher(L, eLuaDispatcher::POINTER);
}

int luaPointerRelative(lua_State* L) {
    return makeLuaDispatcher(L, eLuaDispatcher::POINTER_RELATIVE);
}

int luaIndicator(lua_State* L) {
    return makeLuaDispatcher(L, eLuaDispatcher::INDICATOR);
}

int luaKeyboard(lua_State* L) {
    return makeLuaDispatcher(L, eLuaDispatcher::KEYBOARD);
}

int luaScreenshot(lua_State* L) {
    return makeLuaDispatcher(L, eLuaDispatcher::SCREENSHOT);
}

int luaSession(lua_State* L) {
    return makeLuaDispatcher(L, eLuaDispatcher::SESSION);
}

void registerLuaDispatchers() {
    if (!Config::mgr() || Config::mgr()->type() != Config::CONFIG_LUA)
        return;

    HyprlandAPI::addLuaFunction(g_pluginHandle, LUA_PLUGIN_NAMESPACE, "pointer", luaPointer);
    HyprlandAPI::addLuaFunction(g_pluginHandle, LUA_PLUGIN_NAMESPACE, "pointer_relative", luaPointerRelative);
    HyprlandAPI::addLuaFunction(g_pluginHandle, LUA_PLUGIN_NAMESPACE, "indicator", luaIndicator);
    HyprlandAPI::addLuaFunction(g_pluginHandle, LUA_PLUGIN_NAMESPACE, "keyboard", luaKeyboard);
    HyprlandAPI::addLuaFunction(g_pluginHandle, LUA_PLUGIN_NAMESPACE, "screenshot", luaScreenshot);
    HyprlandAPI::addLuaFunction(g_pluginHandle, LUA_PLUGIN_NAMESPACE, "session", luaSession);
}

} // namespace

APICALL EXPORT std::string PLUGIN_API_VERSION() {
    return HYPRLAND_API_VERSION;
}

APICALL EXPORT PLUGIN_DESCRIPTION_INFO PLUGIN_INIT(HANDLE handle) {
    g_pluginHandle = handle;

    registerPluginConfig();
    registerLuaDispatchers();

    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:pointer", dispatchPointer);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:pointer-relative", dispatchPointerRelative);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:indicator", dispatchIndicator);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:keyboard", dispatchKeyboard);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:screenshot", dispatchScreenshot);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:session", dispatchSession);
    g_windowOpenEarlyListener = Event::bus()->m_events.window.openEarly.listen([](PHLWINDOW window) { handleWorkspaceSessionWindowOpenEarly(window); });
    g_windowOpenListener = Event::bus()->m_events.window.open.listen([](PHLWINDOW window) { handleWorkspaceSessionWindowOpen(window); });
    g_renderStageListener = Event::bus()->m_events.render.stage.listen([](eRenderStage stage) { renderAgentIndicator(stage); });
    g_keyboardInputListener = Event::bus()->m_events.input.keyboard.key.listen(
        [](const IKeyboard::SKeyEvent&, Event::SCallbackInfo&) { restoreXWaylandKeyboardFocus(); });
    g_pointerButtonInputListener = Event::bus()->m_events.input.mouse.button.listen(
        [](const IPointer::SButtonEvent&, Event::SCallbackInfo&) { restoreXWaylandKeyboardFocus(); });
    g_pointerMotionInputListener = Event::bus()->m_events.input.mouse.move.listen(
        [](const Vector2D&, Event::SCallbackInfo&) { restoreXWaylandKeyboardFocus(); });
    HyprlandAPI::reloadConfig();

    return {
        .name = "hypr-agent-protal",
        .description = "Background screenshot, pointer, keyboard, workspace guard, and backend-independent visible agent cursor primitives for Hyprland agents",
        .author = "wilf",
        .version = "0.3.46",
    };
}

APICALL EXPORT void PLUGIN_EXIT() {
    g_workspaceSessions.clear();
    g_windowOpenEarlyListener.reset();
    g_windowOpenListener.reset();
    g_renderStageListener.reset();
    g_keyboardInputListener.reset();
    g_pointerButtonInputListener.reset();
    g_pointerMotionInputListener.reset();
    restoreXWaylandKeyboardFocus();

    if (g_pEventLoopManager) {
        for (const auto& timer : g_pointerRestoreTimers)
            g_pEventLoopManager->removeTimer(timer);
        for (const auto& timer : g_workspaceRestackTimers)
            g_pEventLoopManager->removeTimer(timer);
        if (g_indicatorHideTimer)
            g_pEventLoopManager->removeTimer(g_indicatorHideTimer);
        if (g_indicatorAnimationTimer)
            g_pEventLoopManager->removeTimer(g_indicatorAnimationTimer);
    }
    g_pointerRestoreTimers.clear();
    g_workspaceRestackTimers.clear();
    g_indicatorHideTimer.reset();
    g_indicatorAnimationTimer.reset();
    g_agentPointerWindow.reset();
    g_agentPointerPosition.reset();
    g_agentPointerStartPosition.reset();
    g_agentPointerDisplayPosition.reset();
    g_agentPointerRelativePosition.reset();
    g_agentPointerRelativeStartPosition.reset();
    g_agentPointerRelativeDisplayPosition.reset();
    g_agentPointerUpdated.reset();
    g_agentPointerMotionStarted.reset();
    g_agentPointerAction.clear();
    g_config = {};
    g_pluginHandle = nullptr;
}
