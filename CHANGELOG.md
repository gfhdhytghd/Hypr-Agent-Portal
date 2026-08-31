# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-08-31

### Added

- Bind MCP window targets end-to-end as address + PID + `/proc` process start
  time, with compositor-thread revalidation and strong window references across
  pointer, keyboard, session, screenshot, indicator, and compatibility
  dispatchers. Legacy unqualified CLI selectors remain supported.
- Add centralized MCP safety policy enforcement with read-only and dry-run
  modes, target confinement, per-application authorization, clipboard
  capabilities, mutation leases, privacy exclusions, confirmation tokens, and
  human-takeover handling.
- Add redacted security audit journals, conservative replay preflight, security
  readiness diagnostics, and an isolated session runner.
- Add Python and Hyprland build CI, Python package artifacts, and MCP Registry
  metadata.
- Add local Tesseract CLI and optional `pytesseract` OCR backends with
  dependency diagnostics and structured text, confidence, and screenshot-box
  results.
- Add screenshot-bound `click_text`, numbered Set-of-Marks overlays and
  `click_mark`; stale screenshot, process, and geometry bindings are rejected.
- Add per-request screenshot regions, zoom/scale, PNG/JPEG/WebP encoding,
  maximum-dimension limits, and reversible coordinate mapping metadata. Pillow
  is optional and missing codec/transform support is reported explicitly.
- Add atomic `type_into` targeting for editable controls by element, accessible
  text/name, OCR, or mark with AT-SPI, paste, and key input methods.
- Add non-transactional ordered `sequence` execution with per-step results,
  stop-on-error and dry-run modes. Each step retains ordinary policy,
  confirmation, confinement, lease, audit, cancel, and panic enforcement.
- Add event-driven `wait_for_window` and `wait_for_close` through Hyprland
  socket2, including reconnect handling, sandbox runtime paths, and an
  explicitly reported compatibility polling fallback.
- Add targeted, verified window management for focus, close, move, resize,
  maximize, fullscreen, floating, pin, workspace moves, and inverse actions.
  Minimize/restore is implemented with a private special workspace because
  Hyprland has no portable minimize primitive.
- Add workspace listing, switching, create-or-activate, rename, targeted window
  moves, and explicit show/hide/toggle handling for `special:` workspaces.
- License the project under GPL-3.0-only.

### Changed

- Correct the public project and MCP server spelling from
  `hypr-agent-protal` to `hypr-agent-portal`.
- Scope native human takeover by conflicting resource: physical pointer input
  cancels asynchronous agent pointer work, physical keyboard input does not,
  and both can restore an XWayland keyboard-focus lease. Make `cancel` one-shot,
  while `panic` remains latched until a high-risk resume receives native
  physical-F12 confirmation.

### Testing

- Add headless fixtures for OCR, image transforms and codecs, Set-of-Marks,
  stale visual bindings, sequences including cancel/panic interruption,
  socket2 event/reconnect/fallback behavior, and Hyprland window/workspace
  command generation and verification.
- Build the native plugin against Hyprland 0.56.2. These additions were not all
  exercised through a live compositor session before release, so runtime
  results continue to disclose verification and fallback metadata.

## [0.3.47] - 2026-08-05

### Changed

- Adapt the plugin to Hyprland 0.56 and pin compatible Hyprland commits.
- Route native Wayland keyboard input without taking global keyboard focus.
- Reduce MCP request stalls and app-state latency.
- Repair Lua configuration-provider dispatcher calls.

## [0.3.45] - 2026-05-09

### Added

- Add compositor-side background screenshots, pointer and keyboard input,
  related-window sessions, and XWayland compatibility routing.
- Add a stdio MCP bridge with semantic app state, application launching,
  Computer Use aliases, window lifecycle waits, global menu discovery, and
  target-relative actions.
- Add a visible compositor-rendered agent cursor and logical-resolution,
  HiDPI-aware screenshots.

### Changed

- Adapt the plugin and Lua dispatcher bridge to Hyprland 0.55.
- Keep related popups with the controlled window without stealing the user's
  workspace or focus.
- Stabilize element geometry, menu activation, input focus, text paste, and
  action-result verification.

[Unreleased]: https://github.com/gfhdhytghd/Hypr-Agent-Portal/compare/v0.4.0-0.56...HEAD
[0.4.0]: https://github.com/gfhdhytghd/Hypr-Agent-Portal/compare/v0.3.47-0.56...v0.4.0-0.56
[0.3.47]: https://github.com/gfhdhytghd/Hypr-Agent-Portal/compare/v0.3.45-0.55...v0.3.47-0.56
[0.3.45]: https://github.com/gfhdhytghd/Hypr-Agent-Portal/releases/tag/v0.3.45-0.55
