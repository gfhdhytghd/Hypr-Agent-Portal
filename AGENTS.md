# hypr-agent-portal Agent Notes

When a task says to use `hypr-agent-portal`, use the `hypr-agent-portal` MCP tools, not Browser MCP, shell GUI automation, or the obsolete `hyprcum` namespace.

For browser/app-control tasks:

1. Unless the user explicitly asks to open, launch, create, or use a new app/window/instance, call `list_apps` first and reuse an existing matching target.
2. If the user asks to open or launch an app, call `launch_app`/`open_app`; these tools reuse existing windows by default. Set `reuse_existing=false` or `new_window=true` only when the user explicitly asks for a new instance/window.
3. Use the returned `target` selector, usually `address:0x...`, for the rest of the task.
4. Call `get_app_state` after launch and after each navigation/action that changes the page.
5. If `get_app_state` reports `ACTIVE RELATED POPUP DETECTED`, switch to the shown `target=address:0x...` and operate that popup/dialog first. The popup screenshot is attached before the root-window screenshot.
   If an action closes the popup/dialog and the returned state reports `ACTION RESULT` / `lastAction.targetClosed=true`, continue from the returned `continuedWithTarget` instead of retrying the closed popup target.
   When an action is expected to open or close a dialog/window, use `wait_for_window` or `wait_for_close` instead of acting on stale app state.
6. Prefer `element_index` actions from the app-state tree. Use screenshot coordinates only when the tree is missing or ambiguous.
7. Use `paste_text` for multiline, tabular, CSV/TSV, Unicode-heavy, or long text. Do not enter datasets with repeated `type_text`/`key` calls unless paste is unavailable. On grid-like targets, bulk paste exits cell edit mode before pasting so TSV/CSV expands into cells.
8. For shortcuts, use `press_key`/`key` with `key`, `keys`, `modifiers`, or `keycode`; examples: `enter`, `alt+left`, `{"key":"left","modifiers":"alt"}`.
9. If direct tools are not exposed, the compatibility `computer` tool supports equivalent actions, including `launch_app`, `get_app_state`, `click`, `type`, `paste_text`, `key`, `scroll`, `drag`, `wait`, `wait_for_window`, and `wait_for_close`.
10. Read `uiHints` before acting on menus, tabs, or toolbars. `controlType=menu` is a toolkit role and may be a classic menu, command label, or ribbon/notebookbar page selector; verify the current screenshot/app state instead of assuming the visual meaning.
11. If `get_app_state` exposes `globalMenu` actions, use `activate_menu_item` with the returned `menu_index` for app-menu commands. If no global menu item is exposed, use visible elements or screenshot/window-relative coordinates.
12. Do not invent app-specific shortcuts or search-result heuristics; refresh `get_app_state` and act on visible elements or screenshot/window-relative coordinates.
13. Honor structured security denials and dry-run results. Do not retry through a lower-level alias to bypass policy. For `confirmation_required`, request a token only for the exact proposed call and then use it once without changing the arguments. `panic` with `panic` or `cancel` remains available as the emergency stop path, including in read-only mode.

Do not switch to Browser MCP just because the target app is a browser; `hypr-agent-portal` controls Chromium through Hyprland background screenshots, AT-SPI app state, and background input.
