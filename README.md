# Open in New Tab - IDA Pro Plugin
> This is a work in progress. This plugin can and probably will contain bugs. Please report any inconveniences and share your feedback on what could and/or should be improved to create a better user experience for you, me, and everyone.

An IDA Pro Python plugin that adds context menu entries for directly viewing functions in our familiar disassembly and pseudocode views. Tested and confirmed to work on IDA Pro 9.2.

## Features

Right-click on any function in the **Functions list**, **Disassembly**, or **Pseudocode** view to access:

- **Open in new view** - Opens in the same view type you're currently in (Disassembly -> Disassembly, Pseudocode -> Pseudocode)
- **Open in new disassembly view** - Always opens a new disassembly window
- **Open in new pseudocode view** - Always opens a new pseudocode window

![Animation](https://github.com/user-attachments/assets/c0e79dbc-03d6-42ec-9fef-2544aeb668b8)

## Installation

Copy `open_in_new_tab.py` to your IDA plugins directory:

**Windows:** `%APPDATA%\Hex-Rays\IDA Pro\plugins\`  
**Linux/macOS:** `~/.idapro/plugins/`

Restart IDA Pro.

## Known Issues

- When no main area views exist (no `IDA View-*` or `Pseudocode-*` windows), new views opened from the Functions window may dock incorrectly

## Settings
<img src="https://github.com/user-attachments/assets/28dd1f7b-08ac-4d1b-8443-ac441c37d05c" />

Access via **Edit -> Plugins -> Open in new tab** to:
- Enable/disable the plugin

## License

MIT License - See [LICENSE](LICENSE) for details
