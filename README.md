# hypr-agent-portal

hypr-agent-portal is an experimental Hyprland plugin plus MCP bridge for background agent control.

It exposes a set of compositor dispatchers. With the legacy hyprlang config provider
they can be called with the normal dispatcher syntax:

```ini
hyprctl dispatch hypr-agent-portal:screenshot /tmp/hypr-agent-portal-session.json
hyprctl dispatch hypr-agent-portal:screenshot '/tmp/hypr-agent-portal-session.json,address:0x1234'
hyprctl dispatch hypr-agent-portal:pointer 'address:0x1234,930,520,click,left'
hyprctl dispatch hypr-agent-portal:pointer 'address:0x1234,930,520,drag,left,1180,760,0.2'
hyprctl dispatch hypr-agent-portal:indicator 'address:0x1234,930,520,type'
hyprctl dispatch hypr-agent-portal:keyboard 'address:0x1234,tap,v,ctrl'
hyprctl dispatch hypr-agent-portal:session 'begin,address:0x1234'
hyprctl dispatch hypr-agent-portal:panic status
```

With the Lua config provider, `hyprctl dispatch` evaluates its argument as a Lua
dispatcher expression. Use the Lua plugin functions instead:

```sh
hyprctl dispatch 'hl.plugin.hypr_agent_portal.screenshot("/tmp/hypr-agent-portal-session.json")'
hyprctl dispatch 'hl.plugin.hypr_agent_portal.screenshot("/tmp/hypr-agent-portal-session.json,address:0x1234")'
hyprctl dispatch 'hl.plugin.hypr_agent_portal.pointer("address:0x1234,930,520,click,left")'
hyprctl dispatch 'hl.plugin.hypr_agent_portal.pointer("address:0x1234,930,520,drag,left,1180,760,0.2")'
hyprctl dispatch 'hl.plugin.hypr_agent_portal.indicator("address:0x1234,930,520,type")'
hyprctl dispatch 'hl.plugin.hypr_agent_portal.keyboard("address:0x1234,tap,v,ctrl")'
hyprctl dispatch 'hl.plugin.hypr_agent_portal.session("begin,address:0x1234")'
hyprctl dispatch 'hl.plugin.hypr_agent_portal.panic("status")'
hyprctl dispatch 'hl.plugin.hypr_agent_portal.approval("status 0123456789abcdef0123456789abcdef")'
```

`scripts/hypr-agent-portalctl` detects `configProvider: lua` and emits the Lua
dispatcher expression automatically.

The screenshot dispatcher renders active monitor workspaces into RGBA artifacts from inside Hyprland, then writes a JSON session file. When a window selector is supplied, it renders that window directly into an offscreen framebuffer, so the artifact is not occluded by other windows. On Hyprland v0.56, the pointer dispatcher resolves targets through `Desktop::viewState()->query()`, focuses the target surface only for the injected pointer events, sends motion/button/frame events through `g_pSeatManager`, then restores the previous pointer focus. Successful background pointer actions also render a non-interactive Codex-style cursor overlay with the target window's render pass, so it appears on the controlled app when that app is visible instead of being drawn as a global topmost layer.

For XWayland windows, the dispatcher sends to the `wlSurface()` resource and scales surface-local coordinates by `m_X11SurfaceScaledBy`. If the requested global coordinate lands on a same-process XWayland helper window, such as a search popup, pointer and keyboard dispatch are automatically routed to that related window. For native Wayland windows, it resolves subsurfaces through the root `CWLSurfaceResource::at()` traversal so they receive surface-local coordinates.

The keyboard dispatcher sends a transactional enter/key/leave sequence directly to the target client's `CWLKeyboardResource`; it does not change `g_pSeatManager`'s global keyboard focus. If the human and agent targets belong to the same Wayland client, the previous surface, held keys, and modifier state are restored synchronously before the dispatcher returns. Native clipboard paste also sends the current selection offer directly to the target data device before Ctrl+V.

XWayland applications share one X input focus, so they use a short compatibility lease instead of the fully isolated native path. Repeated agent keys extend that lease, while any real compositor keyboard event restores the previous X focus before the physical key is delivered. The MCP text path first uses AT-SPI when the target snapshot identifies a focused editable control, then falls back to the resource-level key or clipboard lanes.

For apps that spawn visible helper windows or dialogs during background control, `hypr-agent-portal:session begin,<target>` records the target window workspace. New same-process related windows opened during the session are moved back to that workspace instead of appearing on the agent's current workspace. Paste actions begin and sync this session automatically; if a paste opens a related dialog, the MCP result and the next `get_app_state` output include the dialog's `address:0x...` target so the agent can operate that dialog before returning to the root window.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

To build against the local Hyprland v0.56 checkout:

```sh
PKG_CONFIG_PATH="$HOME/data/Hyprland/build${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" cmake -S . -B build-v056 -DCMAKE_BUILD_TYPE=Debug -DHYPRLAND_SOURCE_DIR="$HOME/data/Hyprland"
cmake --build build-v056
```

Install or load `build/libhypr-agent-portal.so` as a Hyprland plugin. With hyprpm:

```sh
hyprpm add .
hyprpm enable hypr-agent-portal
hyprpm reload
```

## MCP

The repository includes a Codex plugin manifest and a stdio MCP server:

```sh
python3 mcp/hypr-agent-portal-mcp.py
```

The core bridge uses the Python standard library. Visual transforms and local
OCR are optional capabilities:

```sh
# Region crop/zoom, JPEG/WebP output, and Set-of-Marks overlays
python3 -m pip install Pillow

# OCR: install the local Tesseract executable and language data with the OS
# package manager. This adapter does not require a Python OCR package.
tesseract --version

# Optional alternate Python adapter (still requires Tesseract itself)
python3 -m pip install Pillow pytesseract
```

`ocr` reports structured backend diagnostics when neither `tesseract` nor the
optional `pytesseract` adapter is usable. PNG screenshot capture and the
non-visual MCP tools continue to work without Pillow; requests that require
crop, zoom, lossy encoding, or marks return a specific missing-backend error.

Example direct-tool arguments (opaque IDs come from the preceding response):

```json
{"app":"address:0x1234","region":{"x":40,"y":80,"width":900,"height":500},"coordinate_space":"screenshot","zoom":1.5,"format":"webp","quality":80,"max_dimension":1600}
{"app":"address:0x1234","backend":"auto","language":"eng"}
{"app":"address:0x1234","ocr_id":"OCR_ID","text":"Save","match":"exact","nth":1}
{"app":"address:0x1234","ocr_id":"OCR_ID","include_elements":true}
{"app":"address:0x1234","marks_id":"MARKS_ID","mark_id":7}
{"app":"address:0x1234","element_index":"12","text":"hello","method":"auto"}
{"steps":[{"id":"focus-search","action":"click","arguments":{"app":"address:0x1234","element_index":"12"}},{"id":"enter-query","action":"type_text","arguments":{"app":"address:0x1234","text":"Wayland"}}],"stop_on_error":true}
{"action":"minimize","app":"address:0x1234"}
{"action":"show_special","workspace":"special:scratch"}
```

These objects correspond respectively to `screenshot`, `ocr`, `click_text`,
`get_marks`, `click_mark`, `type_into`, `sequence`, `manage_window`, and
`manage_workspace`.

Recommended agent workflow:

1. If the user explicitly asks for `hypr-agent-portal`, do not use Browser MCP
   or the old `hyprcum` namespace.
2. Unless the user explicitly asks to open, launch, create, or use a new
   app/window/instance, call `list_apps` first and select an existing matching
   target.
3. If the user asks to open or launch an app, call `launch_app` or `open_app`.
   These tools reuse existing matching windows by default. Set
   `reuse_existing=false` or `new_window=true` only when the user explicitly
   asks for a new instance/window.
4. If the requested app is not in `list_apps`, call `launch_app` or `open_app`.
   Do not guess a shell command outside the MCP tool. The launcher dispatches
   `exec` through the active config provider, waits for the Hyprland window, and
   returns a `target` selector plus the next `get_app_state` hint.
5. Call `get_app_state` for semantic state, or `screenshot` with `app` for an
   image-only refresh.
6. If `get_app_state` reports `ACTIVE RELATED POPUP DETECTED`, operate the
   shown `target=address:0x...` popup/dialog before continuing with the root
   window. The popup screenshot is attached before the root-window screenshot.
   If an action closes that popup/dialog, the returned state may report
   `ACTION RESULT` with `targetClosed=true`; continue from the returned
   `continuedWithTarget` instead of retrying the closed popup target.
   When an action is expected to open or close a dialog/window, use
   `wait_for_window` or `wait_for_close` rather than acting on a stale snapshot.
   If an action result reports `ACTION WARNING` /
   `action-opened-unexpected-window`, stop the current assumed workflow,
   inspect the opened window and refreshed app state, then recover from the
   actual UI state.
7. Prefer `element_index` from `get_app_state`. Element-index clicks use the
   element's visible screenshot center and native pointer input by default, so
   they behave like real background clicks and show the visible agent cursor.
   Set `element_click_mode=auto` or
   `HYPR_AGENT_PORTAL_ELEMENT_CLICK_MODE=auto` only when you intentionally want
   to try AT-SPI action activation before the pointer fallback. When
   coordinates are needed, use `coordinate_space=screenshot` with screenshot pixels, or
   `coordinate_space=window` with target-window-relative logical coordinates.
8. Use `paste_text` for multiline, tabular, CSV/TSV, Unicode-heavy, or long
   text. Do not enter datasets with repeated `type_text`/`key` calls unless
   paste is unavailable. For grid-like targets, bulk paste first exits cell
   edit mode so TSV/CSV expands into cells instead of becoming one cell's text.
9. Read `uiHints` before acting on menus, tabs, or toolbars. `controlType=menu`
   is a toolkit role and may mean a classic menu, command label, or
   ribbon/notebookbar page selector. Verify the screenshot and refreshed app
   state instead of assuming the visual meaning.
10. If `get_app_state` exposes `globalMenu` actions, use `activate_menu_item`
   with the returned `menu_index` for app-menu commands. If no global menu item
   is exposed, use visible elements or screenshot/window-relative coordinates.
11. If using the compatibility `computer` tool, pass `app` when possible. When
   only `target` is available, `coordinate_space=screenshot` and
   `coordinate_space=window` still use target-relative coordinates; use
   `coordinate_space=global` only for deliberate low-level fallback.

Apps launched through `launch_app`/`open_app` automatically get accessibility
environment variables:

```sh
NO_AT_BRIDGE=0
QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1
GTK_MODULES=gail:atk-bridge
```

Chromium/Chrome/Electron-like launches also get
`--force-renderer-accessibility`; browser launches with `new_window=true` add
`--new-window` and open `about:blank` when no URL is supplied. To open a browser
directly, use for example:

```json
{"app": "chromium", "url": "https://example.com", "reuse_existing": false, "new_window": true}
```

For browser or app-control tasks, reuse an existing matching window unless the
user asked for a new one. The intended sequence is `list_apps` or `launch_app`,
`get_app_state`, then element-index actions where possible. Refresh
`get_app_state` after navigation or major UI changes, and use screenshot/window
coordinates only when the accessibility tree is missing or ambiguous.

The visible agent cursor is a compositor-side indicator, not a side effect of
moving the real pointer. Pointer actions update it through
`hypr-agent-portal:pointer`; semantic AT-SPI, keyboard, and text actions update
the same indicator through `hypr-agent-portal:indicator` before acting, so users
can see which app/region the agent is controlling regardless of the input
backend.

Avoid the obsolete `hyprcum` MCP server and namespace. Its tool schema lacks the
new app-state, screenshot-relative coordinates, related-window session handling,
cursor-position support, and Codex compatibility aliases.

The MCP server exposes the compatibility tool `computer` plus Codex-style app-state tools:

- `list_apps`: lists running Hyprland windows with stable selectors, classes, titles, pid, workspace, geometry, and XWayland status. MCP selectors bind the compositor address to the expected PID and Linux process start time (for example `address:0x123@pid=456@start=789`); treat the complete selector as opaque. Native dispatchers revalidate that identity while holding the compositor window reference, so a recycled address fails closed. Plain `address:0x...` remains available only for direct CLI compatibility.
- `launch_app` / `open_app`: starts apps through Hyprland, applies accessibility environment/flags, waits for a new window, and returns its selector.
- `get_app_state`: captures an unoccluded screenshot for a selected app/window and returns a semantic tree plus `uiHints` for menus, tabs, and toolbars. AT-SPI nodes are included when the target exposes accessibility; otherwise the result still includes screenshot metadata and synthetic window elements for coordinate fallback. AT-SPI frames are normalized to screenshot pixels, including target-window captures that contain compositor shadow/border margins. When the target process exposes DBusMenu or GMenu app-menu models, the result also includes `globalMenu` providers and `menu_index` actions.
- Active related popups/dialogs: when a same-process popup or floating dialog is open for the target, `get_app_state` adds an `ACTIVE RELATED POPUP DETECTED` notice, `activeRelatedTarget`, and an extra popup screenshot before the root-window screenshot. Agents should switch to that popup target first.
- Popup/dialog close handling: if an action such as OK, Finish, Cancel, Enter, or Escape closes the current popup target, semantic action tools return the surviving related/root app state with `lastAction.targetClosed=true` and an `ACTION RESULT` notice instead of surfacing the closed popup as `appNotFound`.
- Window lifecycle waits: `wait_for_window` and `wait_for_close` subscribe to
  Hyprland's `.socket2.sock` event stream, reconnect within the requested
  timeout, and return backend metadata. A compatibility poll is used only when
  the event socket is unavailable or times out, and is reported as a fallback
  in the result. The socket path is derived from the current Hyprland session,
  including the sandbox's short runtime path. `wait_for_window` returns the new
  or same-process related popup/dialog state; `wait_for_close` can return the
  surviving `related_to` root state.
- Action mismatch warnings: when an element click opens a related popup/dialog whose title does not match the clicked element text, the returned state includes `ACTION WARNING`, `attention.type=action-opened-unexpected-window`, and the clicked/opened details. Agents should refresh and recover from the actual UI state instead of continuing the assumed workflow.
- `get_cursor_position`: returns the current agent or compositor cursor in monitor-relative coordinates, and in screenshot/window-relative coordinates when `app` is supplied.
- `click`, `scroll`, `drag`, `type_text`, `paste_text`, `press_key`, `set_value`, `perform_secondary_action`, `activate_menu_item`: operate on the last app-state snapshot by `element_index` or `menu_index` where possible, and fall back to screenshot/window-relative coordinates plus the native background input dispatchers. For `click`, `element_index` is converted to the visible element center and sent through native pointer input by default. Use `element_click_mode=auto` or `HYPR_AGENT_PORTAL_ELEMENT_CLICK_MODE=auto` to try AT-SPI activation before pointer fallback, or `element_click_mode=atspi` to require AT-SPI activation. Use `paste_text` for bulk text and datasets; on grid/table targets it exits cell edit mode before pasting so tabular text can expand into cells. `type_text` is for short literal typing and accepts `method=auto`, `paste`, `keys`, or explicit `atspi`.
- Local visual targeting: `ocr` returns text, normalized confidence, and
  screenshot-coordinate boxes from `tesseract-cli` or `pytesseract` together
  with an opaque `ocr_id`. `click_text` selects an exact or substring match by
  one-based `nth`, then verifies that the OCR result still belongs to the same
  screenshot, process, and window geometry before clicking. AT-SPI name/text
  matching remains a separate semantic path and is not reported as OCR.
- Set-of-Marks: `get_marks` draws numbered labels over interactive AT-SPI
  elements and, when an `ocr_id` is supplied, OCR regions. It returns a
  `marks_id` plus each mark's element or screenshot-coordinate mapping;
  `click_mark` revalidates that binding before input. The overlay is encoded
  from a copy and never modifies the compositor capture. Privacy-excluded
  windows cannot be captured or marked, and full-compositor capture remains
  blocked while an excluded window is visible.
- Atomic text targeting: `type_into` resolves an editable control by
  `element_index`, accessible name/text, OCR, or mark, focuses/clicks it,
  refreshes state, and then uses `method=auto|atspi|paste|keys`. It rejects
  non-editable or stale targets and reports target closure or a newly opened
  related popup in the refreshed result.
- Ordered actions: `sequence` accepts up to 128 steps with per-step results,
  `stop_on_error`, and dry-run support. It is deliberately non-transactional:
  completed steps are not rolled back. Every step goes through the same policy,
  confirmation, confinement, cross-process lease, panic/cancel, and audit path
  as a standalone call; nested sequences are rejected.
- Window/workspace management: `manage_window` provides targeted, post-checked
  focus, close, move, resize, maximize, fullscreen, floating, pin, workspace
  move, and inverse operations. Hyprland has no portable minimize primitive, so
  minimize is simulated by moving the window to the private
  `special:hypr-agent-portal-minimized` workspace and recording its origin for
  restore. `list_workspaces` and `manage_workspace` list, switch,
  create-or-activate, rename, move a targeted window, and show/hide/toggle
  `special:` workspaces without treating a special workspace as an ordinary
  numbered workspace.
- Compatibility aliases: `read_app_state`, `list_windows`, `open_app`, `screenshot`, `get_screenshot`, `left_click`, `right_click`, `middle_click`, `double_click`, `triple_click`, `hover`, `move_mouse`, `left_click_drag`, `type`, `key`, `wait`, `wait_for_window`, and `wait_for_close`.
- The compatibility `computer` tool also exposes `ocr`, `click_text`,
  `get_marks`, `click_mark`, `type_into`, `sequence`, `manage_window`,
  `list_workspaces`, and `manage_workspace`; these aliases do not bypass the
  direct tools' validation or safety gates.
- Safety tools: `security_status` reports effective policy/readiness,
  `request_confirmation` creates an externally approved challenge for high-risk
  actions, `panic` cancels or latches off native mutations, and `audit_replay`
  performs plan-only replay preflight unless execution is explicitly enabled.

### Safety policy

Every direct mutating tool and every mutating `computer` action passes through
the same policy gate before any compositor or clipboard operation. Useful
launch profiles include:

```sh
# Observation only: mutating tools are hidden and computer exposes only reads.
HYPR_AGENT_PORTAL_READONLY=1 python3 mcp/hypr-agent-portal-mcp.py

# Validate calls and return structured decisions without executing mutations.
HYPR_AGENT_PORTAL_DRYRUN=1 python3 mcp/hypr-agent-portal-mcp.py

# Restrict mutations to launched windows, Firefox classes, or workspace 3.
HYPR_AGENT_PORTAL_CONFINE='launched,class:firefox*,workspace:3' \
  python3 mcp/hypr-agent-portal-mcp.py
```

The long-form `HYPR_AGENT_PORTAL_SECURITY_*` variables are the canonical
configuration surface. Common settings are:

- `DEFAULT_AUTHORIZATION=view|click|full` and
  `APP_AUTHORIZATIONS='firefox*=full,org.keepassxc.KeePassXC=view'`.
- `CLIPBOARD_PERMISSIONS='write,paste_text,paste_file,paste_image'`.
  Clipboard read is intentionally absent by default. Set
  `restore_clipboard=true` on a paste and add `read` permission only when the
  previous clipboard must be restored.
- `PRIVACY_CLASSES='org.keepassxc.KeePassXC,1password*'`. Matching windows are
  omitted from `list_apps`, cannot be targeted for observation, and block an
  untargeted full-compositor capture while visible.
- `CONFINE_LAUNCHED=1`, `CONFINE_CLASSES`, `CONFINE_WORKSPACES`,
  `CONFINE_ADDRESSES`, and `CONFINE_MATCH=any|all`.
- `BLOCK_LOCKED_VIEW`, `BLOCK_LOCKED_MUTATION`, `BLOCK_LAYER_MUTATION`,
  `BLOCK_KEYBOARD_GRAB_MUTATION`, `HUMAN_TAKEOVER`, and
  `HUMAN_TAKEOVER_COOLDOWN`.
- `MUTATION_LEASE_REQUIRED=1`, `CONFIRMATION_TTL=60`,
  `CONFIRMATION_PENDING_LIMIT=128`, `CONFIRMATION_PENDING_PER_OWNER=16`, and
  optional `CONFIRMATION_MIN_INTERVAL=0` (seconds). Expired pending/approved
  records are reclaimed before the fail-closed total and per-owner limits are
  checked. The MCP additionally
  takes a non-blocking cross-process lease under the private
  `$XDG_RUNTIME_DIR/hypr-agent-portal` directory for every mutation.

Prefix each long-form name with `HYPR_AGENT_PORTAL_SECURITY_`. Short aliases
are provided for `READONLY`, `DRYRUN`, `CONFINE`, `APP_POLICIES`, `CLIPBOARD`,
and `PRIVACY_CLASSES`; canonical variables win when both are set.

Native human takeover is scoped to the conflicting resource. A physical
pointer event cancels an in-flight agent drag, while a physical keyboard event
does not; either input class may terminate the shared XWayland keyboard-focus
lease. Native Wayland agent keyboard delivery remains isolated from native
pointer work. `HUMAN_TAKEOVER_COOLDOWN` is a server-local policy signal for
explicitly recorded takeover activity, not compositor feedback that turns all
physical input into a global MCP cooldown.

High-risk actions such as submit/delete/purchase-style clicks, destructive
shortcuts, and clearing the panic latch return `confirmation_required`. Call
`request_confirmation` with the exact tool name and exact arguments. It returns
a pending challenge ID, not a self-authorizing token. A person must run the
approval waiter locally and press **F12 on a real keyboard** while its
short-lived native challenge is armed:

```sh
python3 mcp/security_policy.py approve CHALLENGE_ID
```

The CLI can only arm and query the compositor challenge; neither it nor any MCP
tool has an approve operation. Approval is produced only by the plugin's
physical-keyboard listener, which rejects virtual-keyboard events. Agent native
key injection goes directly to the target Wayland resource and cannot reach
that listener. The compositor keeps the matching physical proof until the exact
approved action consumes it; an approved-looking JSON file without live native
proof is rejected and removed. Before the F12 press, retrying the action with
the ID returns `confirmation_pending` and never executes. After approval, make the exact
original call once with the challenge ID as `confirmation_token`.
Challenges are short lived, one-time, owner-bound, target-bound, and
payload-bound. Pending and approved records live in a current-user private
directory below `$XDG_RUNTIME_DIR`; symlinked or permissive directories and
files are rejected.

Set `HYPR_AGENT_PORTAL_SECURITY_AUDIT=1` to enable a private mode-0600 JSONL
journal below the user state directory. Text, clipboard data, tokens, paths,
and other sensitive values are replaced by digests. `audit_replay` defaults to
plan-only and rejects stale targets, ephemeral element indices, redacted
payloads, and clipboard actions unless explicitly allowed. Journals rotate at
16 MiB with two same-directory mode-0600 backups by default. Bound these with
`HYPR_AGENT_PORTAL_SECURITY_AUDIT_MAX_BYTES` (1 byte to 1 GiB) and
`HYPR_AGENT_PORTAL_SECURITY_AUDIT_BACKUPS` (0 to 16); zero backups makes a full
journal fail closed instead of truncating it.

The native panic path is independent of MCP policy:

```sh
scripts/hypr-agent-portalctl panic panic   # cancel and latch mutations off
scripts/hypr-agent-portalctl panic cancel  # cancel current async work only
scripts/hypr-agent-portalctl panic status
scripts/hypr-agent-portalctl panic resume  # clear latch; treat as high risk
```

`cancel` is one-shot: after cancelling the current asynchronous pointer work,
timer, and XWayland lease, later mutations may proceed. `panic` performs the
same cancellation and latches mutations off until a physically confirmed
`resume` passes the high-risk confirmation flow above.

For disposable integration runs, `scripts/hypr-agent-portal-sandbox doctor`
checks nested/headless prerequisites and `run -- ...` creates isolated
HOME/XDG/DBus state. This is process/config isolation, not a privilege or
network security sandbox.

The app-state coordinate contract hides Hyprland global logical coordinates from semantic tools. Pass `coordinate_space=screenshot` for screenshot pixels from `get_app_state`, or `coordinate_space=window` for logical coordinates relative to the captured target window. `coordinate: [x, y]` is accepted by click/hover/scroll aliases; `start_coordinate` plus `coordinate` is accepted by drag aliases. The MCP bridge converts these values to the compositor coordinates internally before dispatch. Compatibility calls that provide `target` instead of `app` use the same target-relative conversion unless `coordinate_space=global` is explicit.

Screenshots returned to MCP clients are downsampled for model use by default to
the compositor logical resolution, removing HiDPI scaling. On a 2x display, a
`2862x1686` target capture is sent as `1431x843`. Set
`HYPR_AGENT_PORTAL_MODEL_RESOLUTION=full` to return full HiDPI resolution. An
optional `HYPR_AGENT_PORTAL_MODEL_MAX_DIMENSION` value can apply an additional
long-edge cap after logical downsampling. `get_app_state` reports the model
image size in `screenshot.width` and `screenshot.height`, and keeps the original
capture size in `sourceWidth/sourceHeight`. Screenshot coordinates always refer
to the image actually sent to the model.

Each `screenshot` request may additionally provide
`region={x,y,width,height}`, `coordinate_space=screenshot|window`, `scale` (or
the `zoom` alias), `format=png|jpeg|webp`, `quality`, and `max_dimension`.
Regions are intersected with the captured target bounds; a wholly out-of-bounds
region is rejected. Results report source and output dimensions, actual encoded
format, and affine screenshot/output (and, when applicable,
window/screenshot) mappings so a point selected in a cropped or magnified image
can be mapped back before input. PNG remains the default compatibility format;
JPEG and WebP availability follows the local Pillow build.

### AT-SPI App State

Linux does not expose a system-wide accessibility model as consistently as macOS Accessibility. `get_app_state` therefore treats AT-SPI as a semantic enhancement on top of compositor screenshots, not as the only source of truth.

The returned tree is limited to the current screen state. Hidden menu subtrees are filtered out, and huge table controls such as spreadsheets are sampled through the AT-SPI table interface so visible cells are returned without walking millions of off-screen cells. If traversal hits a time or record budget, `accessibility.treeTruncated` reports it and coordinate fallback remains available.

AT-SPI role names are toolkit reports, not the user's visual intent. Some apps
draw ribbon or notebook-style page selectors while exposing top labels as
`menu` roles. In that case agents should not treat a same-named `menu` as proof
that a tab/page is active; they should use `uiHints`, the screenshot, and
window-relative coordinates to click the visible tab label, then refresh
`get_app_state` before selecting controls revealed by that page.

### Global App Menus

Some Linux apps expose semantic app-menu models outside AT-SPI. `get_app_state`
best-effort loads KDE's `appmenu` kded module and starts
`plasma-gmenudbusmenuproxy.service`, then scans D-Bus services owned by the
target window PID for:

- DBusMenu providers such as `/com/canonical/dbusmenu`.
- GMenu providers such as `org.gtk.Menus` paths ending in `/menus/menubar`.

Discovered entries are returned as `globalMenu.items` and rendered as "Global
menu actions" with stable `menu_index` values for the current snapshot. Use
`activate_menu_item` with that `menu_index` to trigger DBusMenu/GMenu commands
without relying on visual menu popups or AT-SPI role names.

This is an opportunistic provider. Some apps expose a menu service with no
items, expose only media/status menus, or do not publish a menu model for the
current window. In those cases `globalMenu.status` is `unavailable` or the
provider has `itemCount=0`; agents should continue with the visible app state
and screenshot/window-coordinate controls.

Expected coverage:

- GTK/GNOME apps usually expose the best trees once `org.gnome.desktop.interface toolkit-accessibility` is enabled.
- Qt/KDE apps can expose useful trees, but they normally need to be launched with `QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1`.
- Firefox and LibreOffice generally expose meaningful document and control trees.
- Chromium, Chrome, Electron, and VS Code often need `--force-renderer-accessibility`; without it they may only expose a top-level frame or nothing useful.
- XWayland does not by itself prevent AT-SPI. The deciding factor is whether the app toolkit publishes an AT-SPI tree.
- Custom-rendered apps, games, SDL/OpenGL surfaces, Flutter apps, and many proprietary chat clients often expose little or no semantic state. For those, use the screenshot image plus coordinate fallback.

Recommended session setup for better app-state trees:

```sh
gsettings set org.gnome.desktop.interface toolkit-accessibility true
systemctl --user start at-spi-dbus-bus.service
systemctl --user set-environment QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1
dbus-update-activation-environment --systemd QT_LINUX_ACCESSIBILITY_ALWAYS_ON
```

Persist `QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1` in the compositor environment before launching Qt apps, and add `--force-renderer-accessibility` to Chromium/Electron app flags where available. Apps usually need to be restarted after these settings change.

The compatibility `computer` tool still exposes these lower-level actions:

- `screenshot`: captures compositor screenshots and returns PNG image content plus metadata. Pass `target` for unoccluded target-window capture. Screenshot cursor drawing is a debug option and is off by default; use `show_cursor=true` or `cursor_source` values `auto`, `agent`, `hyprland`, `none` to draw it into the returned PNG.
- `windows`: lists Hyprland clients with addresses, classes, titles, geometry, and workspace data. Pass `related_to` to return the selected client plus same-process related windows such as dialogs or helper popups.
- `move`, `click`, `doubleclick`, `press`, `release`: sends pointer input to a target window selector such as `address:0x1234`; screenshot/window coordinate spaces are converted relative to that target.
- `scroll`: sends wheel axis events to a target window.
- `drag`: presses, moves, and releases on the target window through the native pointer dispatcher; screenshot/window coordinate spaces are converted relative to that target.
- `key`: sends a shortcut such as `ctrl+v`, `enter`, `alt+left`, or `escape` to a target window. It accepts `key`, `keys`, `modifiers`, and raw evdev `keycode` for ydotool-style fallback.
- `type`: sends short text to the target input. Use `method` values `auto`, `keys`, `paste`, or `atspi`; by default it uses background key/paste input. Prefer `paste_text` for datasets, multiline text, CSV/TSV, or anything long.
- `paste_text`, `paste_file`, `paste_image`: writes clipboard data and sends a background paste shortcut to the target window.
- Text paste actions do not automatically retarget same-process popup/dialog windows; inspect the returned app state and explicitly use the popup's `address:0x...` target. They keep
  the target session active while a related dialog is open. Restoring the
  previous text clipboard is opt-in because it requires clipboard read access.
- `copy_text`: writes text to the clipboard without sending input.
- `session`: begins, syncs, or ends a related-window workspace guard session. Use `session_action` values `begin`, `sync`, or `end`.
- `wait`: sleeps briefly between UI actions.
- `doctor`: reports AT-SPI/session diagnostics and target accessibility environment hints.
- `activate_menu_item`: activates a `globalMenu` app-menu action by `menu_index` when the target exposes DBusMenu or GMenu.
- `launch`, `launch_app`, `open_app`: opens an app from the compatibility `computer` tool using the same accessibility environment and Chromium/Electron flags as the direct `launch_app` tool. Existing matching windows are reused by default; pass `reuse_existing=false` only for an explicitly requested new instance.
- Compatibility action aliases inside `computer`: `left_click`, `right_click`, `middle_click`, `double_click`, `triple_click`, `hover`, `left_click_drag`, and `get_cursor_position`.
- Rich compatibility actions inside `computer`: `ocr`, `click_text`,
  `get_marks`, `click_mark`, `type_into`, `sequence`, `manage_window`,
  `list_workspaces`, and `manage_workspace`. Screenshot also accepts per-request
  region/zoom/format/quality/max-dimension parameters.

The command-line bridge is also usable directly:

```sh
scripts/hypr-agent-portalctl screenshot --base64
scripts/hypr-agent-portalctl screenshot --target 'address:0x1234' --base64
scripts/hypr-agent-portalctl screenshot --target 'address:0x1234' --base64 --model-resolution logical
scripts/hypr-agent-portalctl screenshot --cursor-source agent --base64
scripts/hypr-agent-portalctl windows
scripts/hypr-agent-portalctl windows --related-to 'address:0x1234'
scripts/hypr-agent-portalctl pointer 'address:0x1234' 930 520 click left
scripts/hypr-agent-portalctl pointer 'address:0x1234' 930 520 scroll -3
scripts/hypr-agent-portalctl pointer 'address:0x1234' 930 520 drag left 1180 760 --duration 0.2
scripts/hypr-agent-portalctl indicator 'address:0x1234' 930 520 type
scripts/hypr-agent-portalctl keyboard 'address:0x1234' tap v ctrl
scripts/hypr-agent-portalctl keyboard 'address:0x1234' tap 28
scripts/hypr-agent-portalctl session begin 'address:0x1234'
scripts/hypr-agent-portalctl session end 'address:0x1234'
scripts/hypr-agent-portalctl panic status
```

## Known Issues

- The 0.4.0 visual, socket2, sequence, and window/workspace paths have headless
  regression coverage and the native plugin is built against Hyprland 0.56.2.
  They have not all been exercised in a live user session for this release;
  inspect returned verification/backend metadata and retain the documented
  polling and coordinate fallbacks where needed.

- 2026-05-05: Native Wayland Chrome/Discord accepts background pointer focus and
  individual key events, but MCP paste actions that set the clipboard and send
  `ctrl+v` did not paste into the Discord composer. Use `type` or explicit key
  events as a temporary fallback until modifier/clipboard paste delivery is
  fixed.

## Config

```ini
plugin {
  hypr-agent-portal {
    allow_screenshot = 1
    allow_pointer = 1
    allow_keyboard = 1
    allow_session = 1
    show_indicator = 1
    indicator_timeout_ms = 30000
    # XWayland-only upper bound for a modified shortcut lease. Physical keyboard
    # input preempts the lease immediately; native Wayland never uses this delay.
    keyboard_restore_delay_ms = 700
    cancel_on_human_input = 1
    # Comma-separated class glob patterns hidden from targeted screenshots.
    privacy_class_denylist = org.keepassxc.KeePassXC,1Password
    # cursor_texture_path = ~/.config/hypr-agent-portal/codex-cursor-252.abgr
  }
}
```

With Hyprland Lua config, plugin config keys are written under
`plugin.hypr_agent_portal` because Lua normalizes the plugin namespace:

```lua
hl.config({
  plugin = {
    hypr_agent_portal = {
      allow_screenshot = true,
      allow_pointer = true,
      allow_keyboard = true,
      allow_session = true,
      show_indicator = true,
      indicator_timeout_ms = 30000,
      keyboard_restore_delay_ms = 700,
      cancel_on_human_input = true,
      privacy_class_denylist = "org.keepassxc.KeePassXC,1Password",
      -- cursor_texture_path = "~/.config/hypr-agent-portal/codex-cursor-252.abgr",
    },
  },
})
```

The visible cursor uses `~/.config/hypr-agent-portal/codex-cursor-252.abgr` when present, and otherwise falls back to a procedural texture. Install an extracted Codex Computer Use cursor PNG into that local raw format with:

```sh
scripts/install-codex-cursor-asset
```

## Rename compatibility

The corrected `portal` spelling is canonical. For one release, the old
`hypr-agent-protal:*` dispatchers, Lua namespace, config namespace, MCP/CLI
launchers, HyprPM plugin entry, and existing `HYPR_AGENT_PROTAL_*` runtime
variables remain compatibility aliases. New names take precedence; do not
enable both HyprPM entries. The compatibility aliases are deprecated and will
be removed in a later release.

## License

hypr-agent-portal is licensed under the GNU General Public License, version 3
only (`GPL-3.0-only`). See [LICENSE](LICENSE).
