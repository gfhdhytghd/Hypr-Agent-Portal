# Security Policy

## Supported versions

Security fixes are made on the latest released version of hypr-agent-portal.
Older releases and untagged development snapshots are not supported.

| Version | Supported |
| --- | --- |
| 0.4.0 | Yes |
| 0.3.47 | No |
| Earlier versions | No |

The Hyprland plugin API is version-sensitive. A report is actionable only when
the plugin is built for the Hyprland version identified by its release tag or
commit pin.

## Runtime boundary

The MCP security policy is optional and disabled by default. It gates
physical confirmation, including MCP panic resume, when enabled. Native
panic and lock-screen checks cover native input and window management.
AT-SPI, DBusMenu, clipboard operations, and app launch rely on the enabled
MCP policy for those checks.

Confinement restricts mutations. Screenshot and accessibility visibility use
the configured privacy filters. Processes with access to the Hyprland IPC
socket can invoke the native dispatchers directly, outside MCP policy.

The F12 approval check uses Hyprland's non-virtual keyboard classification.
Access to the compositor's input devices or to a kernel input emulator
such as uinput is outside this approval boundary.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
vulnerability reporting for this repository:

<https://github.com/gfhdhytghd/Hypr-Agent-Portal/security/advisories/new>

Include the hypr-agent-portal version or commit, Hyprland version, compositor
configuration provider, affected application type (native Wayland or
XWayland), and minimal reproduction steps. Remove credentials, clipboard
contents, screenshots containing private data, and other secrets before
submitting the report.

Reports about background input, screenshots, clipboard access, focus routing,
window confinement, lock-screen behavior, or a bypass of an advertised safety
control are treated as security-sensitive. The visible agent cursor is a user
interface indicator, not a security boundary.

The maintainer will coordinate validation, remediation, and disclosure through
the private advisory. Please allow time for a fix to be tested against the
supported Hyprland build before public disclosure.
