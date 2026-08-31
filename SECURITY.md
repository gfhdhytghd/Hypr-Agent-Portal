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
