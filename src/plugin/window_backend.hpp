#pragma once

#include <hyprland/src/desktop/state/WindowState.hpp>
#include <hyprland/src/desktop/view/window/Window.hpp>
#include <hyprland/src/xwayland/XSurface.hpp>
#include <hyprland/src/xwayland/XWayland.hpp>

namespace hypr_agent_portal {

// IWindowBackend::parent() filters unmapped parents. Keep the old x11Parent()
// semantics for related-window routing and screenshot transient metadata.
inline PHLWINDOW x11ParentWindow(const PHLWINDOW& window) {
    if (!window || !window->backend().isX11() || !g_pXWayland || !g_pXWayland->m_wm)
        return {};

    const auto surface = g_pXWayland->m_wm->windowForXID(window->backend().clientID().id);
    if (!surface || !surface->m_parent)
        return {};

    const Desktop::View::SBackendClientID parentID{.type = Desktop::View::eBackendType::WINDOW_BACKEND_X11, .id = surface->m_parent->m_xID};
    for (const auto& candidate : Desktop::windowState()->windows()) {
        if (candidate && candidate->backend().clientID() == parentID)
            return candidate;
    }
    return {};
}

} // namespace hypr_agent_portal
