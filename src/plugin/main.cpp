#include "plugin/screenshot_capture.hpp"

#include <hyprland/src/config/ConfigManager.hpp>
#include <hyprland/src/config/lua/bindings/LuaBindingsInternal.hpp>
#include <hyprland/src/config/shared/actions/ConfigActions.hpp>
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
#include <hyprland/src/managers/KeybindManager.hpp>
#include <hyprland/src/managers/SeatManager.hpp>
#include <hyprland/src/managers/eventLoop/EventLoopManager.hpp>
#include <hyprland/src/managers/eventLoop/EventLoopTimer.hpp>
#include <hyprland/src/protocols/core/DataDevice.hpp>
#include <hyprland/src/protocols/core/Seat.hpp>
#include <hyprland/src/protocols/SessionLock.hpp>
#include <hyprland/src/render/Renderer.hpp>
#include <hyprland/src/render/Texture.hpp>
#include <hyprland/src/render/gl/GLTexture.hpp>
#include <hyprland/src/render/pass/TexPassElement.hpp>
#include <hyprland/src/state/MonitorState.hpp>
#include <hyprland/src/state/WorkspaceState.hpp>
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
#include <fnmatch.h>
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
CHyprSignalListener              g_pointerAxisInputListener;
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
    SP<Config::Values::CBoolValue>   cancelOnHumanInput;
    SP<Config::Values::CStringValue> cursorTexturePath;
    SP<Config::Values::CStringValue> privacyClassDenylist;
    SP<Config::Values::CBoolValue>   compatAllowPointer;
    SP<Config::Values::CBoolValue>   compatAllowKeyboard;
    SP<Config::Values::CBoolValue>   compatAllowScreenshot;
    SP<Config::Values::CBoolValue>   compatAllowSession;
    SP<Config::Values::CBoolValue>   compatShowIndicator;
    SP<Config::Values::CIntValue>    compatIndicatorTimeoutMs;
    SP<Config::Values::CIntValue>    compatKeyboardRestoreDelayMs;
    SP<Config::Values::CBoolValue>   compatCancelOnHumanInput;
    SP<Config::Values::CStringValue> compatCursorTexturePath;
    SP<Config::Values::CStringValue> compatPrivacyClassDenylist;
};

SPluginConfig g_config;

constexpr const char* LUA_CONFIG_ALLOW_POINTER             = "plugin.hypr_agent_portal.allow_pointer";
constexpr const char* LUA_CONFIG_ALLOW_KEYBOARD            = "plugin.hypr_agent_portal.allow_keyboard";
constexpr const char* LUA_CONFIG_ALLOW_SCREENSHOT          = "plugin.hypr_agent_portal.allow_screenshot";
constexpr const char* LUA_CONFIG_ALLOW_SESSION             = "plugin.hypr_agent_portal.allow_session";
constexpr const char* LUA_CONFIG_SHOW_INDICATOR            = "plugin.hypr_agent_portal.show_indicator";
constexpr const char* LUA_CONFIG_INDICATOR_TIMEOUT_MS      = "plugin.hypr_agent_portal.indicator_timeout_ms";
constexpr const char* LUA_CONFIG_KEYBOARD_RESTORE_DELAY_MS = "plugin.hypr_agent_portal.keyboard_restore_delay_ms";
constexpr const char* LUA_CONFIG_CANCEL_ON_HUMAN_INPUT     = "plugin.hypr_agent_portal.cancel_on_human_input";
constexpr const char* LUA_CONFIG_CURSOR_TEXTURE_PATH       = "plugin.hypr_agent_portal.cursor_texture_path";
constexpr const char* LUA_CONFIG_PRIVACY_CLASS_DENYLIST    = "plugin.hypr_agent_portal.privacy_class_denylist";
constexpr const char* LUA_PLUGIN_NAMESPACE                 = "hypr_agent_portal";
constexpr const char* LUA_PLUGIN_NAMESPACE_COMPAT          = "hypr_agent_protal";
constexpr const char* LUA_COMPAT_ALLOW_POINTER             = "plugin.hypr_agent_protal.allow_pointer";
constexpr const char* LUA_COMPAT_ALLOW_KEYBOARD            = "plugin.hypr_agent_protal.allow_keyboard";
constexpr const char* LUA_COMPAT_ALLOW_SCREENSHOT          = "plugin.hypr_agent_protal.allow_screenshot";
constexpr const char* LUA_COMPAT_ALLOW_SESSION             = "plugin.hypr_agent_protal.allow_session";
constexpr const char* LUA_COMPAT_SHOW_INDICATOR            = "plugin.hypr_agent_protal.show_indicator";
constexpr const char* LUA_COMPAT_INDICATOR_TIMEOUT_MS      = "plugin.hypr_agent_protal.indicator_timeout_ms";
constexpr const char* LUA_COMPAT_KEYBOARD_RESTORE_DELAY_MS = "plugin.hypr_agent_protal.keyboard_restore_delay_ms";
constexpr const char* LUA_COMPAT_CANCEL_ON_HUMAN_INPUT     = "plugin.hypr_agent_protal.cancel_on_human_input";
constexpr const char* LUA_COMPAT_CURSOR_TEXTURE_PATH       = "plugin.hypr_agent_protal.cursor_texture_path";
constexpr const char* LUA_COMPAT_PRIVACY_CLASS_DENYLIST    = "plugin.hypr_agent_protal.privacy_class_denylist";

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

template <typename T>
T legacyCompatConfigValue(const std::string& suffix, T fallback) {
    const auto current = legacyConfigValue<T>("plugin:hypr-agent-portal:" + suffix, fallback);
    const auto compat = legacyConfigValue<T>("plugin:hypr-agent-protal:" + suffix, fallback);
    return current != fallback ? current : compat;
}

bool configBool(const std::string& suffix, bool fallback) {
    if (usingLegacyConfig())
        return legacyCompatConfigValue<Hyprlang::INT>(suffix, fallback ? 1 : 0) != 0;

    const auto aliased = [fallback](const auto& current, const auto& compat) {
        const bool currentValue = current ? current->value() : fallback;
        const bool compatValue = compat ? static_cast<bool>(compat->value()) : fallback;
        return currentValue && compatValue;
    };
    if (suffix == "allow_pointer")
        return aliased(g_config.allowPointer, g_config.compatAllowPointer);
    if (suffix == "allow_keyboard")
        return aliased(g_config.allowKeyboard, g_config.compatAllowKeyboard);
    if (suffix == "allow_screenshot")
        return aliased(g_config.allowScreenshot, g_config.compatAllowScreenshot);
    if (suffix == "allow_session")
        return aliased(g_config.allowSession, g_config.compatAllowSession);
    if (suffix == "show_indicator")
        return aliased(g_config.showIndicator, g_config.compatShowIndicator);
    if (suffix == "cancel_on_human_input")
        return aliased(g_config.cancelOnHumanInput, g_config.compatCancelOnHumanInput);

    return fallback;
}

int configInt(const std::string& suffix, int fallback) {
    if (usingLegacyConfig())
        return static_cast<int>(legacyCompatConfigValue<Hyprlang::INT>(suffix, fallback));

    const auto aliased = [fallback](const auto& current, const auto& compat) {
        const int currentValue = current ? static_cast<int>(current->value()) : fallback;
        return currentValue != fallback ? currentValue : (compat ? static_cast<int>(compat->value()) : currentValue);
    };
    if (suffix == "indicator_timeout_ms")
        return aliased(g_config.indicatorTimeoutMs, g_config.compatIndicatorTimeoutMs);
    if (suffix == "keyboard_restore_delay_ms")
        return aliased(g_config.keyboardRestoreDelayMs, g_config.compatKeyboardRestoreDelayMs);

    return fallback;
}

std::string configString(const std::string& suffix, const std::string& fallback) {
    if (usingLegacyConfig()) {
        const auto read = [&suffix](const std::string& prefix) -> std::string {
            const auto value = HyprlandAPI::getConfigValue(g_pluginHandle, prefix + suffix);
            if (!value)
                return {};
            try {
                return std::string{std::any_cast<Hyprlang::STRING>(value->getValue())};
            } catch (const std::bad_any_cast&) {
                return {};
            }
        };
        const auto current = read("plugin:hypr-agent-portal:");
        const auto compat = read("plugin:hypr-agent-protal:");
        if (suffix == "privacy_class_denylist" && !current.empty() && !compat.empty())
            return current + "," + compat;
        return !current.empty() ? current : (!compat.empty() ? compat : fallback);
    }

    if (suffix == "cursor_texture_path" && g_config.cursorTexturePath) {
        const std::string current = g_config.cursorTexturePath->value();
        if (current != fallback || !g_config.compatCursorTexturePath)
            return current;
        return g_config.compatCursorTexturePath->value();
    }
    if (suffix == "privacy_class_denylist") {
        const std::string current = g_config.privacyClassDenylist ? std::string{g_config.privacyClassDenylist->value()} : std::string{};
        const std::string compat = g_config.compatPrivacyClassDenylist ? std::string{g_config.compatPrivacyClassDenylist->value()} : std::string{};
        if (current.empty())
            return compat.empty() ? fallback : compat;
        return compat.empty() ? current : current + "," + compat;
    }

    return fallback;
}

void registerPluginConfig() {
    if (usingLegacyConfig()) {
        const auto addBoth = [](const std::string& suffix, const auto& value) {
            HyprlandAPI::addConfigValue(g_pluginHandle, "plugin:hypr-agent-portal:" + suffix, value);
            HyprlandAPI::addConfigValue(g_pluginHandle, "plugin:hypr-agent-protal:" + suffix, value);
        };
        addBoth("allow_pointer", Hyprlang::INT{1});
        addBoth("allow_keyboard", Hyprlang::INT{1});
        addBoth("allow_screenshot", Hyprlang::INT{1});
        addBoth("allow_session", Hyprlang::INT{1});
        addBoth("show_indicator", Hyprlang::INT{1});
        addBoth("indicator_timeout_ms", Hyprlang::INT{30000});
        addBoth("keyboard_restore_delay_ms", Hyprlang::INT{700});
        addBoth("cancel_on_human_input", Hyprlang::INT{1});
        addBoth("cursor_texture_path", Hyprlang::STRING{""});
        addBoth("privacy_class_denylist", Hyprlang::STRING{""});
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
    g_config.cancelOnHumanInput =
        makeShared<CBoolValue>(LUA_CONFIG_CANCEL_ON_HUMAN_INPUT, "cancel active agent sequences and keyboard leases on desktop input", true);
    g_config.cursorTexturePath =
        makeShared<CStringValue>(LUA_CONFIG_CURSOR_TEXTURE_PATH, "raw ABGR cursor texture path", Config::STRING{""});
    g_config.privacyClassDenylist =
        makeShared<CStringValue>(LUA_CONFIG_PRIVACY_CLASS_DENYLIST, "comma-separated window classes excluded from screenshots", Config::STRING{""});
    g_config.compatAllowPointer = makeShared<CBoolValue>(LUA_COMPAT_ALLOW_POINTER, "compat: allow background pointer dispatchers", true);
    g_config.compatAllowKeyboard = makeShared<CBoolValue>(LUA_COMPAT_ALLOW_KEYBOARD, "compat: allow background keyboard dispatchers", true);
    g_config.compatAllowScreenshot = makeShared<CBoolValue>(LUA_COMPAT_ALLOW_SCREENSHOT, "compat: allow compositor screenshot dispatchers", true);
    g_config.compatAllowSession = makeShared<CBoolValue>(LUA_COMPAT_ALLOW_SESSION, "compat: allow workspace session dispatchers", true);
    g_config.compatShowIndicator = makeShared<CBoolValue>(LUA_COMPAT_SHOW_INDICATOR, "compat: show the visible agent cursor indicator", true);
    g_config.compatIndicatorTimeoutMs =
        makeShared<CIntValue>(LUA_COMPAT_INDICATOR_TIMEOUT_MS, "compat: visible agent cursor timeout", Config::INTEGER{30000});
    g_config.compatKeyboardRestoreDelayMs =
        makeShared<CIntValue>(LUA_COMPAT_KEYBOARD_RESTORE_DELAY_MS, "compat: maximum XWayland keyboard lease", Config::INTEGER{700});
    g_config.compatCancelOnHumanInput =
        makeShared<CBoolValue>(LUA_COMPAT_CANCEL_ON_HUMAN_INPUT, "compat: cancel active operations on desktop input", true);
    g_config.compatCursorTexturePath =
        makeShared<CStringValue>(LUA_COMPAT_CURSOR_TEXTURE_PATH, "compat: raw ABGR cursor texture path", Config::STRING{""});
    g_config.compatPrivacyClassDenylist =
        makeShared<CStringValue>(LUA_COMPAT_PRIVACY_CLASS_DENYLIST, "compat: screenshot privacy class denylist", Config::STRING{""});

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
    registerOrReset(g_config.cancelOnHumanInput);
    registerOrReset(g_config.cursorTexturePath);
    registerOrReset(g_config.privacyClassDenylist);
    registerOrReset(g_config.compatAllowPointer);
    registerOrReset(g_config.compatAllowKeyboard);
    registerOrReset(g_config.compatAllowScreenshot);
    registerOrReset(g_config.compatAllowSession);
    registerOrReset(g_config.compatShowIndicator);
    registerOrReset(g_config.compatIndicatorTimeoutMs);
    registerOrReset(g_config.compatKeyboardRestoreDelayMs);
    registerOrReset(g_config.compatCancelOnHumanInput);
    registerOrReset(g_config.compatCursorTexturePath);
    registerOrReset(g_config.compatPrivacyClassDenylist);
}

std::filesystem::path defaultCursorTexturePath() {
    if (const char* xdgConfig = std::getenv("XDG_CONFIG_HOME"); xdgConfig && *xdgConfig)
        return std::filesystem::path{xdgConfig} / "hypr-agent-portal" / "codex-cursor-252.abgr";
    if (const char* home = std::getenv("HOME"); home && *home)
        return std::filesystem::path{home} / ".config" / "hypr-agent-portal" / "codex-cursor-252.abgr";
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

struct AsyncPointerOperation {
    std::string                  selector;
    Vector2D                     start;
    Vector2D                     end;
    bool                         windowRelative = false;
    uint32_t                     button = 0;
    bool                         buttonPressed = false;
    SP<CWLSurfaceResource>       previousSurface;
    Vector2D                     previousLocal;
    std::optional<TargetSurface> lastTarget;
    Vector2D                     lastGlobal;
};

std::shared_ptr<AsyncPointerOperation> g_asyncPointerOperation;
bool                                   g_agentPanicActive = false;

struct PhysicalApprovalChallenge {
    std::string     id;
    Time::steady_tp expiresAt;
    bool            approved = false;
};

std::optional<PhysicalApprovalChallenge> g_physicalApprovalChallenge;

bool compositorSessionLocked() {
    return PROTO::sessionLock && PROTO::sessionLock->isLocked();
}

bool exclusiveLayerSurfaceActive() {
    return g_pInputManager && std::ranges::any_of(g_pInputManager->m_exclusiveLSes, [](const auto& layer) { return static_cast<bool>(layer.lock()); });
}

bool keyboardGrabActive() {
    return g_pSeatManager && static_cast<bool>(g_pSeatManager->m_seatGrab);
}

std::optional<std::string> inputSafetyError(const TargetSurface& target) {
    if (compositorSessionLocked())
        return "hypr-agent-portal input is blocked while the compositor session is locked";
    if (g_pSeatManager && g_pSeatManager->m_seatGrab && !g_pSeatManager->m_seatGrab->accepts(target.surface))
        return "hypr-agent-portal input is blocked by an active seat grab";
    if (exclusiveLayerSurfaceActive())
        return "hypr-agent-portal input is blocked by an exclusive layer surface";
    return std::nullopt;
}

bool screenshotPrivacyDenied(const PHLWINDOW& window) {
    if (!window)
        return false;

    const auto windowClass = lower(trim(window->m_class));
    const auto initialClass = lower(trim(window->m_initialClass));
    for (const auto& denied : splitCsv(configString("privacy_class_denylist", ""))) {
        const auto normalized = lower(trim(denied));
        if (!normalized.empty() &&
            (fnmatch(normalized.c_str(), windowClass.c_str(), 0) == 0 || fnmatch(normalized.c_str(), initialClass.c_str(), 0) == 0))
            return true;
    }
    return false;
}

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

struct TargetSelectorIdentity {
    std::string selector;
    bool        qualified = false;
    bool        valid = true;
    pid_t       pid = 0;
    std::string processStartTime;
};

TargetSelectorIdentity parseTargetSelectorIdentity(const std::string& raw) {
    TargetSelectorIdentity result{.selector = raw};
    if (!raw.starts_with("address:") || raw.find('@') == std::string::npos)
        return result;

    const auto pidMarker = raw.find("@pid=");
    const auto startMarker = raw.find("@start=", pidMarker == std::string::npos ? 0 : pidMarker + 5);
    if (pidMarker == std::string::npos || startMarker == std::string::npos || raw.find('@', startMarker + 7) != std::string::npos) {
        result.valid = false;
        return result;
    }

    result.selector = raw.substr(0, pidMarker);
    const auto pidText = raw.substr(pidMarker + 5, startMarker - (pidMarker + 5));
    result.processStartTime = raw.substr(startMarker + 7);
    const auto addressHex = result.selector.starts_with("address:0x") ? std::string_view{result.selector}.substr(10) : std::string_view{};
    if (addressHex.empty() || !std::ranges::all_of(addressHex, [](unsigned char c) { return std::isxdigit(c); }) || pidText.empty() || result.processStartTime.empty() ||
        !std::ranges::all_of(pidText, [](unsigned char c) { return std::isdigit(c); }) ||
        !std::ranges::all_of(result.processStartTime, [](unsigned char c) { return std::isdigit(c); })) {
        result.valid = false;
        return result;
    }

    long long parsedPid = 0;
    const auto [end, error] = std::from_chars(pidText.data(), pidText.data() + pidText.size(), parsedPid);
    if (error != std::errc{} || end != pidText.data() + pidText.size() || parsedPid <= 0 || parsedPid > std::numeric_limits<pid_t>::max()) {
        result.valid = false;
        return result;
    }
    result.pid = static_cast<pid_t>(parsedPid);
    result.qualified = true;
    return result;
}

std::optional<std::string> processStartTimeForPid(pid_t pid) {
    std::ifstream stat{"/proc/" + std::to_string(pid) + "/stat"};
    std::string line;
    if (!stat || !std::getline(stat, line))
        return std::nullopt;
    const auto close = line.rfind(')');
    if (close == std::string::npos || close + 2 >= line.size())
        return std::nullopt;
    std::istringstream fields{line.substr(close + 2)};
    std::string value;
    // The remainder starts at proc field 3. starttime is field 22.
    for (int field = 3; field <= 22; ++field) {
        if (!(fields >> value))
            return std::nullopt;
    }
    return value;
}

PHLWINDOW resolveTargetWindow(const std::string& rawSelector) {
    if (!g_pCompositor)
        return {};
    const auto identity = parseTargetSelectorIdentity(rawSelector);
    if (!identity.valid)
        return {};
    auto window = Desktop::viewState()->query().selector(identity.selector).mappedOnly().runWindow();
    // Keep the compositor-owned strong reference while validating the process
    // identity, so an address cannot be recycled between lookup and use.
    if (!window || !window->m_isMapped)
        return {};
    if (identity.qualified) {
        if (window->getPID() != identity.pid)
            return {};
        const auto actualStartTime = processStartTimeForPid(identity.pid);
        if (!actualStartTime || *actualStartTime != identity.processStartTime)
            return {};
    }
    return window;
}

std::optional<TargetSurface> resolveTargetSurface(const std::string& targetRegex, const Vector2D& globalPos) {
    if (!g_pCompositor)
        return std::nullopt;

    auto window = resolveTargetWindow(targetRegex);
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

    const auto window = resolveTargetWindow(targetRegex);
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

    const auto window = resolveTargetWindow(targetRegex);
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

void cancelPointerTimers() {
    if (g_pEventLoopManager) {
        for (const auto& timer : g_pointerRestoreTimers)
            g_pEventLoopManager->removeTimer(timer);
    }
    g_pointerRestoreTimers.clear();
}

void finishAsyncPointerOperation(const std::shared_ptr<AsyncPointerOperation>& operation, bool releaseButton) {
    if (!operation)
        return;

    if (g_pSeatManager) {
        if (operation->lastTarget) {
            const auto& target = *operation->lastTarget;
            g_pSeatManager->setPointerFocus(target.surface, target.local);
            g_pSeatManager->sendPointerMotion(nowMs(), target.local);
            if (releaseButton && operation->buttonPressed) {
                g_pSeatManager->sendPointerButton(nowMs(), operation->button, WL_POINTER_BUTTON_STATE_RELEASED);
                operation->buttonPressed = false;
            }
            g_pSeatManager->sendPointerFrame();

            if (target.window && target.window->m_isX11) {
                g_pSeatManager->m_state.pointerFocus.reset();
                g_pSeatManager->m_state.pointerFocusResource.reset();
            }
        } else if (releaseButton && operation->buttonPressed) {
            g_pSeatManager->sendPointerButton(nowMs(), operation->button, WL_POINTER_BUTTON_STATE_RELEASED);
            g_pSeatManager->sendPointerFrame();
            operation->buttonPressed = false;
        }

        g_pSeatManager->setPointerFocus(operation->previousSurface, operation->previousLocal);
        g_pSeatManager->sendPointerFrame();
    }

    if (g_asyncPointerOperation == operation)
        g_asyncPointerOperation.reset();
}

void cancelAsyncPointerOperation() {
    const auto operation = g_asyncPointerOperation;
    cancelPointerTimers();
    finishAsyncPointerOperation(operation, true);
}

void cancelWorkspaceSessionTimers() {
    if (g_pEventLoopManager) {
        for (const auto& timer : g_workspaceRestackTimers)
            g_pEventLoopManager->removeTimer(timer);
    }
    g_workspaceRestackTimers.clear();
}

void cancelAgentActivity(bool cancelSessions) {
    cancelAsyncPointerOperation();
    restoreXWaylandKeyboardFocus();

    if (cancelSessions) {
        cancelWorkspaceSessionTimers();
        g_workspaceSessions.clear();
    }
}

void handleHumanTakeover(bool pointerInput) {
    if (!configBool("cancel_on_human_input", true))
        return;

    const bool hadAsyncOperation = static_cast<bool>(g_asyncPointerOperation);
    const bool hadKeyboardLease = g_xwaylandKeyboardLease.active;
    if (!hadAsyncOperation && !hadKeyboardLease)
        return;

    if (pointerInput) {
        if (hadAsyncOperation)
            cancelAsyncPointerOperation();
        else
            cancelPointerTimers();
    }
    if (hadKeyboardLease)
        restoreXWaylandKeyboardFocus();
}

bool validApprovalChallengeId(std::string_view id) {
    return id.size() == 32 && std::ranges::all_of(id, [](unsigned char character) {
        return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
    });
}

void expirePhysicalApprovalChallenge() {
    if (g_physicalApprovalChallenge && Time::steadyNow() >= g_physicalApprovalChallenge->expiresAt)
        g_physicalApprovalChallenge.reset();
}

bool physicalApprovalKeyHeld() {
    if (!g_pInputManager)
        return false;

    return std::ranges::any_of(g_pInputManager->m_keyboards, [](const auto& keyboard) {
        return keyboard && keyboard->m_enabled && !keyboard->isVirtual() && keyboard->getPressed(KEY_F12);
    });
}

void handlePhysicalApprovalKey(const IKeyboard::SKeyEvent& event) {
    expirePhysicalApprovalChallenge();
    if (!g_physicalApprovalChallenge || event.state != WL_KEYBOARD_KEY_STATE_PRESSED || event.keycode != KEY_F12)
        return;

    // Agent keyboard injection writes directly to the target wl_keyboard
    // resource and never reaches this listener.  Also require the key to be
    // present on a non-virtual compositor keyboard so a virtual-keyboard
    // protocol client cannot forge physical presence.
    if (physicalApprovalKeyHeld())
        g_physicalApprovalChallenge->approved = true;
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
    if (g_agentPanicActive)
        return {.success = false, .error = "hypr-agent-portal panic is active"};
    if (!configBool("allow_pointer", true))
        return {.success = false, .error = "hypr-agent-portal pointer dispatch is disabled"};
    if (!g_pSeatManager)
        return {.success = false, .error = "seat manager is not ready"};

    const auto parts = splitCsv(args);
    if (parts.size() < 4)
        return {.success = false,
                .error = "usage: hypr-agent-portal:pointer <window-regex>,<x>,<y>,<move|click|press|release|drag>[,<button>][,<drag-x>,<drag-y>,<duration-sec>]"};

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
    if (const auto error = inputSafetyError(*target); error)
        return {.success = false, .error = *error};

    const auto action = lower(parts[3]);
    const auto button = pointerButton(parts.size() >= 5 ? parts[4] : "left");
    if (!button && action != "move" && action != "motion" && action != "scroll")
        return {.success = false, .error = "unknown pointer button"};
    if ((action == "drag" || action == "doubleclick" || action == "double-click") && g_asyncPointerOperation)
        cancelAsyncPointerOperation();

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
            auto state = std::make_shared<AsyncPointerOperation>();
            state->selector = parts[0];
            state->start = inputPoint;
            state->end = Vector2D{*x2, *y2};
            state->windowRelative = windowRelative;
            state->button = *button;
            state->buttonPressed = true;
            state->previousSurface = restore.previousSurface;
            state->previousLocal = restore.previousLocal;
            state->lastTarget = *target;
            state->lastGlobal = *globalPoint;
            g_asyncPointerOperation = state;
            restore.restored = true;

            const int durationMs = std::max(1, static_cast<int>(std::round(durationSec * 1000.0)));
            for (int step = 1; step <= steps; ++step) {
                const double   t = static_cast<double>(step) / static_cast<double>(steps);
                const Vector2D point{state->start.x + ((state->end.x - state->start.x) * t), state->start.y + ((state->end.y - state->start.y) * t)};
                const int      delayMs = std::max(1, static_cast<int>(std::round(durationMs * t)));
                auto           timer = makeShared<CEventLoopTimer>(
                    std::chrono::milliseconds(delayMs),
                    [state, point](SP<CEventLoopTimer> self, void*) {
                        if (g_pSeatManager && g_asyncPointerOperation == state) {
                            const auto global = targetPointToGlobal(state->selector, point, state->windowRelative);
                            const auto stepTarget = global ? resolveTargetSurface(state->selector, *global) : std::optional<TargetSurface>{};
                            if (stepTarget) {
                                if (inputSafetyError(*stepTarget)) {
                                    cancelAsyncPointerOperation();
                                    return;
                                }
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
                    if (g_pSeatManager && g_asyncPointerOperation == state && state->lastTarget) {
                        if (const auto finalGlobal = targetPointToGlobal(state->selector, state->end, state->windowRelative)) {
                            state->lastGlobal = *finalGlobal;
                            if (const auto finalTarget = resolveTargetSurface(state->selector, *finalGlobal))
                                state->lastTarget = *finalTarget;
                        }
                        const auto target = *state->lastTarget;
                        if (inputSafetyError(target)) {
                            cancelAsyncPointerOperation();
                            return;
                        }
                        g_pSeatManager->setPointerFocus(target.surface, target.local);
                        g_pSeatManager->sendPointerMotion(nowMs(), target.local);
                        g_pSeatManager->sendPointerButton(nowMs(), state->button, WL_POINTER_BUTTON_STATE_RELEASED);
                        state->buttonPressed = false;
                        g_pSeatManager->sendPointerFrame();
                        showAgentIndicator(target.window, state->lastGlobal, "drag");

                        if (target.window && target.window->m_isX11) {
                            g_pSeatManager->m_state.pointerFocus.reset();
                            g_pSeatManager->m_state.pointerFocusResource.reset();
                        }
                        g_pSeatManager->setPointerFocus(state->previousSurface, state->previousLocal);
                        g_pSeatManager->sendPointerFrame();
                    }
                    if (g_asyncPointerOperation == state)
                        g_asyncPointerOperation.reset();
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
        auto operation = std::make_shared<AsyncPointerOperation>();
        operation->selector = targetSelector;
        operation->start = targetInput;
        operation->end = targetInput;
        operation->windowRelative = targetWindowRelative;
        operation->button = targetButton;
        operation->previousSurface = previousSurface;
        operation->previousLocal = previousLocal;
        operation->lastTarget = *target;
        operation->lastGlobal = *globalPoint;
        g_asyncPointerOperation = operation;
        restore.restored = true;

        auto timer = makeShared<CEventLoopTimer>(
            std::chrono::milliseconds(180),
            [operation, previousSurface, previousLocal, targetSelector, targetInput, targetWindowRelative, targetButton](SP<CEventLoopTimer> self, void*) mutable {
                if (g_asyncPointerOperation != operation) {
                    removePointerTimer(self);
                    return;
                }
                const auto target = resolveTargetSurfaceForPoint(targetSelector, targetInput, targetWindowRelative);
                if (g_pSeatManager && target) {
                    if (inputSafetyError(*target)) {
                        cancelAsyncPointerOperation();
                        return;
                    }
                    operation->lastTarget = *target;
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
                if (g_asyncPointerOperation == operation)
                    g_asyncPointerOperation.reset();

                removePointerTimer(self);
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
        return {.success = false, .error = "usage: hypr-agent-portal:indicator <window-regex>,<global-x>,<global-y>[,<action>]"};

    const auto x = parseDouble(parts[1]);
    const auto y = parseDouble(parts[2]);
    if (!x || !y)
        return {.success = false, .error = "indicator coordinates must be finite numbers"};

    auto window = resolveTargetWindow(parts[0]);
    if (!window || !window->m_isMapped)
        return {.success = false, .error = "target window not found"};

    const Vector2D global{*x, *y};
    window = xwaylandRelatedWindowAt(window, global);
    const auto action = parts.size() >= 4 ? lower(parts[3]) : std::string{"move"};
    showAgentIndicator(window, global, action);
    return {.success = true};
}

SDispatchResult dispatchKeyboard(const std::string& args) {
    if (g_agentPanicActive)
        return {.success = false, .error = "hypr-agent-portal panic is active"};
    if (!configBool("allow_keyboard", true))
        return {.success = false, .error = "hypr-agent-portal keyboard dispatch is disabled"};
    if (!g_pSeatManager)
        return {.success = false, .error = "seat manager is not ready"};

    const auto parts = splitCsv(args);
    if (parts.size() < 3)
        return {.success = false, .error = "usage: hypr-agent-portal:keyboard <window-regex>,<tap|press|release>,<key>[,<modifiers>][,<global-x>,<global-y>]"};

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
    if (const auto error = inputSafetyError(*target); error)
        return {.success = false, .error = *error};

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
    if (compositorSessionLocked())
        return {.success = false, .error = "hypr-agent-portal screenshot is blocked while the compositor session is locked"};
    if (!configBool("allow_screenshot", true))
        return {.success = false, .error = "hypr-agent-portal screenshot dispatch is disabled"};

    const auto parts = splitCsv(args);
    const auto path = parts.empty() ? std::string{} : trim(parts[0]);
    if (path.empty())
        return {.success = false, .error = "usage: hypr-agent-portal:screenshot <output-session-json-path>[,<window-regex>]"};

    const auto target = parts.size() >= 2 ? trim(parts[1]) : std::string{};
    PHLWINDOW  targetWindow;
    if (!target.empty()) {
        const auto window = resolveTargetWindow(target);
        if (!window || !window->m_isMapped)
            return {.success = false, .error = "target window not found"};
        if (screenshotPrivacyDenied(window))
            return {.success = false, .error = "target window class is excluded by privacy_class_denylist"};
        targetWindow = window;
    } else {
        // Full capture serializes metadata for every mapped window, including
        // hidden windows and windows on inactive workspaces. Apply privacy to
        // that exact superset, not only to windows visible in monitor pixels.
        const bool privateMappedWindow = std::ranges::any_of(Desktop::windowState()->windows(), [](const auto& window) {
            return window && window->m_isMapped && screenshotPrivacyDenied(window);
        });
        if (privateMappedWindow)
            return {.success = false,
                    .error = "full-compositor screenshot is blocked while a mapped privacy_class_denylist window could enter capture metadata"};
    }
    const auto result = hypr_agent_portal::captureScreenshotSession(std::filesystem::path(path), targetWindow);
    if (!result.success)
        return {.success = false, .error = result.error};
    return {.success = true};
}

SDispatchResult dispatchSession(const std::string& args) {
    if (g_agentPanicActive)
        return {.success = false, .error = "hypr-agent-portal panic is active"};
    if (compositorSessionLocked())
        return {.success = false, .error = "hypr-agent-portal session dispatch is blocked while the compositor session is locked"};
    if (!configBool("allow_session", true))
        return {.success = false, .error = "hypr-agent-portal session dispatch is disabled"};
    if (!g_pCompositor)
        return {.success = false, .error = "compositor is not ready"};

    const auto parts = splitCsv(args);
    if (parts.empty())
        return {.success = false, .error = "usage: hypr-agent-portal:session <begin|sync|end>[,<window-regex>]"};

    const auto action = lower(parts[0]);
    if (action == "begin") {
        if (parts.size() < 2)
            return {.success = false, .error = "session begin requires a target window selector"};

        const auto root = resolveTargetWindow(parts[1]);
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
            const auto root = resolveTargetWindow(parts[1]);
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
            const auto root = resolveTargetWindow(parts[1]);
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

std::optional<int> parseManageInteger(const std::string& value, int minimum, int maximum) {
    if (value.empty())
        return std::nullopt;
    int parsed = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size() || parsed < minimum || parsed > maximum)
        return std::nullopt;
    return parsed;
}

bool validManageWorkspace(const std::string& selector) {
    if (selector.empty() || selector.size() > 128 || selector != trim(selector))
        return false;
    if (std::ranges::any_of(selector, [](unsigned char ch) { return ch < 0x20 || ch == 0x7f || ch == ',' || ch == ';' || ch == '\\' || ch == '"'; }))
        return false;
    if (selector == "special")
        return true;
    if (selector.starts_with("special:") || selector.starts_with("name:")) {
        const auto name = std::string_view{selector}.substr(selector.find(':') + 1);
        return !name.empty() && name.size() <= 96 && name.front() != ' ' && name.back() != ' ';
    }
    if (!std::ranges::all_of(selector, [](unsigned char ch) { return std::isdigit(ch); }))
        return false;
    const auto id = parseManageInteger(selector, 1, 100000);
    return id.has_value();
}

SDispatchResult runBuiltinDispatcher(const std::string_view name, const std::string& payload) {
    if (!g_pKeybindManager)
        return {.success = false, .error = "Hyprland keybind manager is unavailable"};
    const auto dispatcher = g_pKeybindManager->m_dispatchers.find(std::string{name});
    if (dispatcher == g_pKeybindManager->m_dispatchers.end())
        return {.success = false, .error = "required Hyprland dispatcher is unavailable"};
    return dispatcher->second(payload);
}

SDispatchResult manageActionResult(Config::Actions::ActionResult result) {
    if (!result)
        return {.success = false, .error = result.error().message};
    return {.passEvent = result->passEvent, .success = true};
}

PHLWORKSPACE resolveManageWorkspace(const std::string& selector) {
    if (!State::workspaceState())
        return {};
    return State::workspaceState()->query().string(selector).run();
}

bool validManageWorkspaceName(const std::string& name) {
    return !name.empty() && name.size() <= 96 && name == trim(name) && !name.starts_with("name:") && !name.starts_with("special:") &&
        !std::ranges::any_of(name, [](unsigned char ch) { return ch < 0x20 || ch == 0x7f || ch == ',' || ch == ';' || ch == '\\' || ch == '"'; });
}

SDispatchResult dispatchWorkspaceManage(const std::string& action, const std::vector<std::string>& parts) {
    if (action == "workspace_rename") {
        if (parts.size() != 3 || !validManageWorkspace(parts[1]) || parts[1].starts_with("special") || !validManageWorkspaceName(parts[2]))
            return {.success = false, .error = "workspace_rename requires an existing ordinary workspace and a safe new name"};
        const PHLWORKSPACE workspace = resolveManageWorkspace(parts[1]);
        if (!workspace || workspace->inert() || workspace->m_isSpecialWorkspace)
            return {.success = false, .error = "workspace_rename target is stale or not found"};
        return manageActionResult(Config::Actions::renameWorkspace(workspace, parts[2]));
    }

    if (action == "workspace_switch" || action == "workspace_create" || action == "workspace_activate") {
        if (parts.size() != 2 || !validManageWorkspace(parts[1]))
            return {.success = false, .error = "workspace action requires one safe workspace selector"};
        PHLWORKSPACE workspace = resolveManageWorkspace(parts[1]);
        if (action == "workspace_switch" && !workspace)
            return {.success = false, .error = "workspace_switch target was not found"};
        if (action == "workspace_create" && workspace)
            return {.success = false, .error = "workspace_create target already exists"};
        // Existing objects are held strongly and acted on directly.  For an
        // absent create/activate selector, changeWorkspace resolves, creates,
        // and activates synchronously on this compositor thread.
        return workspace ? manageActionResult(Config::Actions::changeWorkspace(workspace)) : manageActionResult(Config::Actions::changeWorkspace(parts[1]));
    }

    if (action == "special_show" || action == "special_hide" || action == "special_toggle") {
        if (parts.size() != 2 || !validManageWorkspace(parts[1]) || !(parts[1] == "special" || parts[1].starts_with("special:")))
            return {.success = false, .error = "special action requires special or special:NAME"};
        PHLWORKSPACE workspace = resolveManageWorkspace(parts[1]);
        if (!workspace) {
            if (action == "special_hide")
                return {.success = true};
            const auto created = Config::Actions::changeWorkspace(parts[1]);
            if (!created)
                return manageActionResult(created);
            workspace = resolveManageWorkspace(parts[1]);
            // changeWorkspace created and showed the absent special workspace;
            // a first toggle therefore means show, not an immediate hide.
            if (action == "special_show" || action == "special_toggle")
                return workspace ? SDispatchResult{.success = true} : SDispatchResult{.success = false, .error = "special workspace creation was not observable"};
        }
        if (!workspace || workspace->inert() || !workspace->m_isSpecialWorkspace)
            return {.success = false, .error = "special workspace target is stale or invalid"};

        std::vector<PHLMONITOR> visibleOn;
        for (const auto& monitor : State::monitorState()->monitors()) {
            if (monitor && monitor->activeSpecialWorkspaceID() == workspace->m_id)
                visibleOn.push_back(monitor);
        }
        const bool hide = action == "special_hide" || (action == "special_toggle" && !visibleOn.empty());
        if (hide) {
            for (const auto& monitor : visibleOn)
                monitor->setSpecialWorkspace(nullptr);
            return {.success = true};
        }
        if (!visibleOn.empty())
            return {.success = true};
        return manageActionResult(Config::Actions::changeWorkspace(workspace));
    }

    return {.success = false, .error = "unsupported workspace management action"};
}

// A deliberately narrow management gateway.  The caller cannot name a
// Hyprland dispatcher: every action below maps to a compile-time allowlist.
// resolveTargetWindow returns a compositor-owned strong reference and checks
// pid plus /proc starttime, so the address cannot be recycled between lookup
// and the synchronous built-in dispatcher call in this compositor stack frame.
SDispatchResult dispatchManage(const std::string& args) {
    if (g_agentPanicActive)
        return {.success = false, .error = "hypr-agent-portal panic is active"};
    if (compositorSessionLocked())
        return {.success = false, .error = "hypr-agent-portal management is blocked while the compositor session is locked"};
    if (args.find('"') != std::string::npos || args.find('\\') != std::string::npos)
        return {.success = false, .error = "manage payload quoting and escaping are not supported"};

    const auto parts = splitCsv(args);
    if (parts.size() < 2)
        return {.success = false, .error = "usage: hypr-agent-portal:manage ACTION,QUALIFIED_ADDRESS[,ARG...]"};

    const auto action = lower(parts[0]);
    static constexpr std::array<std::string_view, 7> WORKSPACE_ACTIONS = {
        "workspace_switch", "workspace_create", "workspace_activate", "workspace_rename", "special_show", "special_hide", "special_toggle",
    };
    if (std::ranges::contains(WORKSPACE_ACTIONS, action))
        return dispatchWorkspaceManage(action, parts);
    static constexpr std::array<std::string_view, 17> WINDOW_ACTIONS = {
        "focus", "close", "move", "resize", "minimize", "restore", "maximize", "unmaximize", "fullscreen", "unfullscreen", "floating", "tiled", "pin", "unpin",
        "move_to_workspace", "workspace_move_window", "move_window_to_workspace",
    };
    if (!std::ranges::contains(WINDOW_ACTIONS, action))
        return {.success = false, .error = "unsupported management action"};

    const auto identity = parseTargetSelectorIdentity(parts[1]);
    if (!identity.valid || !identity.qualified)
        return {.success = false, .error = "management target must be address:0x...@pid=...@start=..."};
    const PHLWINDOW window = resolveTargetWindow(parts[1]);
    if (!window)
        return {.success = false, .error = "qualified management target is stale or not found"};

    const auto requireCount = [&parts](size_t count) -> std::optional<SDispatchResult> {
        if (parts.size() == count)
            return std::nullopt;
        return SDispatchResult{.success = false, .error = "invalid argument count for management action"};
    };
    const auto runForWindow = [&window, &identity](std::string_view dispatcher, const std::string& payload) -> SDispatchResult {
        if (!window->m_isMapped)
            return {.success = false, .error = "qualified management target became unmapped"};
        return runBuiltinDispatcher(dispatcher, payload.empty() ? identity.selector : payload);
    };

    if (action == "focus" || action == "close" || action == "floating" || action == "tiled" || action == "pin" || action == "unpin") {
        if (const auto error = requireCount(2); error)
            return *error;
        if (action == "focus")
            return runForWindow("focuswindow", "");
        if (action == "close")
            return runForWindow("closewindow", "");
        if (action == "floating")
            return runForWindow("setfloating", "");
        if (action == "tiled")
            return runForWindow("settiled", "");
        const bool desired = action == "pin";
        if (window->m_pinned == desired)
            return {.success = true};
        return runForWindow("pin", "");
    }

    if (action == "move" || action == "resize") {
        if (const auto error = requireCount(4); error)
            return *error;
        const auto first = parseManageInteger(parts[2], action == "resize" ? 1 : -100000, 100000);
        const auto second = parseManageInteger(parts[3], action == "resize" ? 1 : -100000, 100000);
        if (!first || !second)
            return {.success = false, .error = "management coordinates or size are invalid"};
        const auto payload = "exact " + std::to_string(*first) + " " + std::to_string(*second) + "," + identity.selector;
        return runForWindow(action == "move" ? "movewindowpixel" : "resizewindowpixel", payload);
    }

    if (action == "maximize" || action == "unmaximize" || action == "fullscreen" || action == "unfullscreen") {
        if (const auto error = requireCount(2); error)
            return *error;
        auto focused = runForWindow("focuswindow", "");
        if (!focused.success)
            return focused;
        if (!window->m_isMapped || Desktop::focusState()->window() != window)
            return {.success = false, .error = "qualified management target did not retain focus"};
        const bool maximize = action == "maximize" || action == "unmaximize";
        const bool enable = action == "maximize" || action == "fullscreen";
        return runBuiltinDispatcher("fullscreen", std::string{maximize ? "1 " : "0 "} + (enable ? "set" : "unset"));
    }

    const bool workspaceMove = action == "move_to_workspace" || action == "workspace_move_window" || action == "move_window_to_workspace";
    const size_t expectedCount = workspaceMove ? 4 : 3;
    if (const auto error = requireCount(expectedCount); error)
        return *error;
    if (!validManageWorkspace(parts[2]))
        return {.success = false, .error = "management workspace selector is invalid"};
    bool follow = false;
    if (workspaceMove) {
        if (parts[3] == "follow")
            follow = true;
        else if (parts[3] != "silent")
            return {.success = false, .error = "move_to_workspace mode must be follow or silent"};
    }
    const auto payload = parts[2] + "," + identity.selector;
    return runForWindow(follow ? "movetoworkspace" : "movetoworkspacesilent", payload);
}

SDispatchResult dispatchPanic(const std::string& args) {
    const auto action = lower(trim(args));
    if (action.empty() || action == "panic" || action == "on") {
        g_agentPanicActive = true;
        cancelAgentActivity(true);
        return {.success = true};
    }
    if (action == "cancel") {
        cancelAgentActivity(true);
        return {.success = true};
    }
    if (action == "resume" || action == "reset" || action == "off") {
        cancelAgentActivity(true);
        g_agentPanicActive = false;
        return {.success = true};
    }
    if (action == "status")
        return g_agentPanicActive ? SDispatchResult{.success = false, .error = "hypr-agent-portal panic is active"} : SDispatchResult{.success = true};
    return {.success = false, .error = "usage: hypr-agent-portal:panic [panic|cancel|resume|status]"};
}

SDispatchResult dispatchApproval(const std::string& args) {
    std::istringstream stream(args);
    std::string        action;
    std::string        challengeId;
    std::string        ttlText;
    std::string        extra;
    stream >> action >> challengeId;
    action = lower(action);

    if (!validApprovalChallengeId(challengeId))
        return {.success = false, .error = "approval-invalid-challenge-id"};

    expirePhysicalApprovalChallenge();

    if (action == "arm") {
        stream >> ttlText >> extra;
        if (ttlText.empty() || !extra.empty())
            return {.success = false, .error = "usage: hypr-agent-portal:approval arm CHALLENGE_ID TTL_MS"};

        int64_t ttlMs = 0;
        const auto [end, error] = std::from_chars(ttlText.data(), ttlText.data() + ttlText.size(), ttlMs);
        if (error != std::errc{} || end != ttlText.data() + ttlText.size() || ttlMs < 1000 || ttlMs > 120000)
            return {.success = false, .error = "approval-invalid-ttl"};

        if (g_physicalApprovalChallenge) {
            if (g_physicalApprovalChallenge->id != challengeId)
                return {.success = false, .error = "approval-already-armed"};
            // Re-arming the same challenge is idempotent and never extends its
            // deadline, so callers cannot keep an old physical proof alive.
            return {.success = true};
        }

        g_physicalApprovalChallenge = PhysicalApprovalChallenge{
            .id        = challengeId,
            .expiresAt = Time::steadyNow() + std::chrono::milliseconds(ttlMs),
            .approved  = false,
        };
        return {.success = true};
    }

    if (action == "status") {
        stream >> extra;
        if (!extra.empty())
            return {.success = false, .error = "usage: hypr-agent-portal:approval status CHALLENGE_ID"};
        if (!g_physicalApprovalChallenge)
            return {.success = false, .error = "approval-expired-or-not-armed"};
        if (g_physicalApprovalChallenge->id != challengeId)
            return {.success = false, .error = "approval-id-mismatch"};
        if (!g_physicalApprovalChallenge->approved)
            return {.success = false, .error = "approval-pending-press-f12"};
        return {.success = true};
    }

    if (action == "cancel") {
        stream >> extra;
        if (!extra.empty())
            return {.success = false, .error = "usage: hypr-agent-portal:approval cancel CHALLENGE_ID"};
        if (g_physicalApprovalChallenge && g_physicalApprovalChallenge->id == challengeId)
            g_physicalApprovalChallenge.reset();
        return {.success = true};
    }

    return {.success = false, .error = "usage: hypr-agent-portal:approval [arm CHALLENGE_ID TTL_MS|status CHALLENGE_ID|cancel CHALLENGE_ID]"};
}

SDispatchResult dispatchGuard(const std::string& args) {
    const auto action = lower(trim(args));
    bool       active = false;
    if (action == "panic")
        active = g_agentPanicActive;
    else if (action == "locked")
        active = compositorSessionLocked();
    else if (action == "exclusive-layer")
        active = exclusiveLayerSurfaceActive();
    else if (action == "keyboard-grab")
        active = keyboardGrabActive();
    else
        return {.success = false, .error = "usage: hypr-agent-portal:guard [panic|locked|exclusive-layer|keyboard-grab]"};

    if (active)
        return {.success = false, .error = "guard-active:" + action};
    return {.success = true};
}

enum class eLuaDispatcher : int {
    POINTER,
    POINTER_RELATIVE,
    INDICATOR,
    KEYBOARD,
    SCREENSHOT,
    SESSION,
    MANAGE,
    PANIC,
    GUARD,
    APPROVAL,
};

SDispatchResult dispatchLuaPayload(eLuaDispatcher dispatcher, const std::string& payload) {
    switch (dispatcher) {
        case eLuaDispatcher::POINTER: return dispatchPointer(payload);
        case eLuaDispatcher::POINTER_RELATIVE: return dispatchPointerRelative(payload);
        case eLuaDispatcher::INDICATOR: return dispatchIndicator(payload);
        case eLuaDispatcher::KEYBOARD: return dispatchKeyboard(payload);
        case eLuaDispatcher::SCREENSHOT: return dispatchScreenshot(payload);
        case eLuaDispatcher::SESSION: return dispatchSession(payload);
        case eLuaDispatcher::MANAGE: return dispatchManage(payload);
        case eLuaDispatcher::PANIC: return dispatchPanic(payload);
        case eLuaDispatcher::GUARD: return dispatchGuard(payload);
        case eLuaDispatcher::APPROVAL: return dispatchApproval(payload);
    }

    return {.success = false, .error = "unknown hypr-agent-portal lua dispatcher"};
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

int luaManage(lua_State* L) {
    return makeLuaDispatcher(L, eLuaDispatcher::MANAGE);
}

int luaPanic(lua_State* L) {
    return makeLuaDispatcher(L, eLuaDispatcher::PANIC);
}

int luaGuard(lua_State* L) {
    return makeLuaDispatcher(L, eLuaDispatcher::GUARD);
}

int luaApproval(lua_State* L) {
    return makeLuaDispatcher(L, eLuaDispatcher::APPROVAL);
}

void registerLuaDispatchers() {
    if (!Config::mgr() || Config::mgr()->type() != Config::CONFIG_LUA)
        return;

    const auto addNamespace = [](const char* name) {
        HyprlandAPI::addLuaFunction(g_pluginHandle, name, "pointer", luaPointer);
        HyprlandAPI::addLuaFunction(g_pluginHandle, name, "pointer_relative", luaPointerRelative);
        HyprlandAPI::addLuaFunction(g_pluginHandle, name, "indicator", luaIndicator);
        HyprlandAPI::addLuaFunction(g_pluginHandle, name, "keyboard", luaKeyboard);
        HyprlandAPI::addLuaFunction(g_pluginHandle, name, "screenshot", luaScreenshot);
        HyprlandAPI::addLuaFunction(g_pluginHandle, name, "session", luaSession);
        HyprlandAPI::addLuaFunction(g_pluginHandle, name, "manage", luaManage);
        HyprlandAPI::addLuaFunction(g_pluginHandle, name, "panic", luaPanic);
        HyprlandAPI::addLuaFunction(g_pluginHandle, name, "guard", luaGuard);
        HyprlandAPI::addLuaFunction(g_pluginHandle, name, "approval", luaApproval);
    };
    addNamespace(LUA_PLUGIN_NAMESPACE);
    addNamespace(LUA_PLUGIN_NAMESPACE_COMPAT);
}

} // namespace

APICALL EXPORT std::string PLUGIN_API_VERSION() {
    return HYPRLAND_API_VERSION;
}

APICALL EXPORT PLUGIN_DESCRIPTION_INFO PLUGIN_INIT(HANDLE handle) {
    g_pluginHandle = handle;

    registerPluginConfig();
    registerLuaDispatchers();

    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-portal:pointer", dispatchPointer);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-portal:pointer-relative", dispatchPointerRelative);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-portal:indicator", dispatchIndicator);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-portal:keyboard", dispatchKeyboard);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-portal:screenshot", dispatchScreenshot);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-portal:session", dispatchSession);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-portal:manage", dispatchManage);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-portal:panic", dispatchPanic);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-portal:guard", dispatchGuard);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-portal:approval", dispatchApproval);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:pointer", dispatchPointer);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:pointer-relative", dispatchPointerRelative);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:indicator", dispatchIndicator);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:keyboard", dispatchKeyboard);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:screenshot", dispatchScreenshot);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:session", dispatchSession);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:manage", dispatchManage);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:panic", dispatchPanic);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:guard", dispatchGuard);
    HyprlandAPI::addDispatcherV2(g_pluginHandle, "hypr-agent-protal:approval", dispatchApproval);
    g_windowOpenEarlyListener = Event::bus()->m_events.window.openEarly.listen([](PHLWINDOW window) { handleWorkspaceSessionWindowOpenEarly(window); });
    g_windowOpenListener = Event::bus()->m_events.window.open.listen([](PHLWINDOW window) { handleWorkspaceSessionWindowOpen(window); });
    g_renderStageListener = Event::bus()->m_events.render.stage.listen([](eRenderStage stage) { renderAgentIndicator(stage); });
    g_keyboardInputListener = Event::bus()->m_events.input.keyboard.key.listen(
        [](const IKeyboard::SKeyEvent& event, Event::SCallbackInfo&) {
            handlePhysicalApprovalKey(event);
            handleHumanTakeover(false);
        });
    g_pointerButtonInputListener = Event::bus()->m_events.input.mouse.button.listen(
        [](const IPointer::SButtonEvent&, Event::SCallbackInfo&) { handleHumanTakeover(true); });
    g_pointerMotionInputListener = Event::bus()->m_events.input.mouse.move.listen(
        [](const Vector2D&, Event::SCallbackInfo&) { handleHumanTakeover(true); });
    g_pointerAxisInputListener = Event::bus()->m_events.input.mouse.axis.listen(
        [](const IPointer::SAxisEvent&, Event::SCallbackInfo&) { handleHumanTakeover(true); });
    HyprlandAPI::reloadConfig();

    return {
        .name = "hypr-agent-portal",
        .description = "Background screenshot, pointer, keyboard, workspace guard, and backend-independent visible agent cursor primitives for Hyprland agents",
        .author = "wilf",
        .version = "0.4.0",
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
    g_pointerAxisInputListener.reset();
    cancelAgentActivity(true);
    g_agentPanicActive = false;
    g_physicalApprovalChallenge.reset();

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
