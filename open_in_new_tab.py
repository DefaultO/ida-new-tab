"""
MIT License

Copyright (c) 2025 DefaultO

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import ida_kernwin
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_diskio
import os

try:
    from PySide6 import QtCore, QtGui, QtWidgets
except ImportError:
    try:
        from PyQt5 import QtCore, QtGui, QtWidgets
    except ImportError:
        from PySide2 import QtCore, QtGui, QtWidgets

ACTION_NAME = "open_in_new_tab:open_func"

def get_config_file_path():
    user_dir = ida_diskio.get_user_idadir()
    config_file = os.path.join(user_dir, "open_in_new_tab.cfg")
    return config_file

def load_plugin_enabled_state():
    try:
        config_file = get_config_file_path()
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("ENABLE_PLUGIN="):
                        value = line.split("=", 1)[1].strip()
                        return value == "1" or value.lower() == "true"
    except:
        pass
    return True  # Default to enabled

def save_plugin_enabled_state(enabled):
    try:
        config_file = get_config_file_path()
        with open(config_file, 'w') as f:
            f.write(f"# Set to 1 to enable, 0 to disable\n")
            f.write(f"ENABLE_PLUGIN={'1' if enabled else '0'}\n")
    except Exception as e:
        print(f"Failed to save plugin state: {e}")

class AboutDialog(QtWidgets.QDialog):

    def __init__(self, plugin_enabled, parent=None):
        super(AboutDialog, self).__init__(parent)
        self.setWindowTitle("About")
        self.setWindowFlags(self.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint)
        self.plugin_enabled = plugin_enabled
        self.setAutoFillBackground(True)
        
        main_layout = QtWidgets.QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        content_widget = QtWidgets.QWidget()
        content_layout = QtWidgets.QVBoxLayout()
        content_layout.setSpacing(0)
        content_layout.setContentsMargins(30, 20, 30, 20)
        
        title_layout = QtWidgets.QHBoxLayout()
        title_layout.setSpacing(0)
        
        title_label = QtWidgets.QLabel('"Open in new tab" - IDA Pro Plugin')
        title_font = QtGui.QFont()
        title_font.setPointSize(11)
        title_label.setFont(title_font)
        title_label.setAlignment(QtCore.Qt.AlignLeft)
        title_layout.addWidget(title_label)
        
        title_layout.addStretch()
        
        reload_button = QtWidgets.QPushButton("Reload Plugin")
        reload_button.setToolTip("Reload the plugin without restarting IDA")
        reload_button.clicked.connect(self.reload_plugin)
        title_layout.addWidget(reload_button)
        
        content_layout.addLayout(title_layout)
        
        content_layout.addSpacing(4)
        
        source_label = QtWidgets.QLabel(
            'Source: <a href="https://github.com/DefaultO/ida-new-tab" style="color: #5c9fd8; text-decoration: none;">https://github.com/DefaultO/ida-new-tab</a>'
        )
        source_label.setOpenExternalLinks(True)
        source_label.setAlignment(QtCore.Qt.AlignLeft)
        source_font = QtGui.QFont()
        source_font.setPointSize(8)
        source_label.setFont(source_font)
        content_layout.addWidget(source_label)
        
        version_label = QtWidgets.QLabel('Version: 1.0')
        version_label.setAlignment(QtCore.Qt.AlignLeft)
        version_font = QtGui.QFont()
        version_font.setPointSize(8)
        version_label.setFont(version_font)
        content_layout.addWidget(version_label)
        
        content_layout.addSpacing(8)
        
        desc_label = QtWidgets.QLabel('Description: Right-click function names to open in new window tabs')
        desc_label.setAlignment(QtCore.Qt.AlignLeft)
        desc_font = QtGui.QFont()
        desc_font.setPointSize(8)
        desc_label.setFont(desc_font)
        content_layout.addWidget(desc_label)
        
        content_layout.addSpacing(5)
        
        self.enable_checkbox = QtWidgets.QCheckBox("Enable plugin")
        self.enable_checkbox.setChecked(plugin_enabled)
        content_layout.addWidget(self.enable_checkbox)
        
        content_layout.addSpacing(10)
        
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addStretch()
        ok_button = QtWidgets.QPushButton("OK")
        ok_button.setDefault(True)
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)
        button_layout.addStretch()
        content_layout.addLayout(button_layout)
        
        content_widget.setLayout(content_layout)
        main_layout.addWidget(content_widget)

        self.setLayout(main_layout)
        self.adjustSize()
        self.setFixedSize(self.size())
    
    def is_enabled(self):
        return self.enable_checkbox.isChecked()
    
    def reload_plugin(self):
        try:
            import sys
            import types
            
            plugin_module = None
            module_name = None
            
            for name, module in list(sys.modules.items()):
                if hasattr(module, 'OpenInNewTabPlugin') and hasattr(module, 'PLUGIN_ENTRY'):
                    module_name = name
                    plugin_module = module
                    print(f"[DEBUG] Found plugin module: {module_name}")
                    break
            
            if plugin_module and hasattr(plugin_module, '__file__'):
                plugin_file = plugin_module.__file__
                print(f"[DEBUG] Plugin file: {plugin_file}")
                
                with open(plugin_file, 'r', encoding='utf-8') as f:
                    code = f.read()
                
                exec(compile(code, plugin_file, 'exec'), plugin_module.__dict__)
                
                print(f"✓ Reloaded plugin successfully from {plugin_file}")
                
                QtWidgets.QMessageBox.information(
                    self,
                    "Plugin Reloaded",
                    f"Plugin reloaded successfully!\n\n"
                    f"File: {os.path.basename(plugin_file)}\n\n"
                    f"Note: Close and reopen this dialog to see changes."
                )
            else:
                loaded_plugins = [m for m in sys.modules.keys() if 'open' in m.lower() and 'tab' in m.lower()]
                print(f"✗ Plugin module not found")
                print(f"[DEBUG] Searched in {len(sys.modules)} modules")
                print(f"[DEBUG] Possible matches: {loaded_plugins}")
                
                QtWidgets.QMessageBox.warning(
                    self,
                    "Reload Failed",
                    f"Plugin module not found in loaded modules.\n\n"
                    f"Found {len(loaded_plugins)} possible matches."
                )
        except Exception as e:
            print(f"✗ Failed to reload plugin: {e}")
            import traceback
            traceback.print_exc()
            QtWidgets.QMessageBox.critical(
                self,
                "Reload Error",
                f"Failed to reload plugin:\n{str(e)}"
            )

def set_window_title(view, newtitle):
    widget   = ida_kernwin.PluginForm.TWidgetToPyQtWidget(view)
    oldtitle = ida_kernwin.get_widget_title(view)

    def set_title_recursive(widget, oldtitle, newtitle):
        if widget is not None:
            curtitle = ida_kernwin.get_widget_title(ida_kernwin.PluginForm.QtWidgetToTWidget(widget))
            if curtitle == oldtitle:
                widget.setWindowTitle(newtitle)
            set_title_recursive(widget.parentWidget(), oldtitle, newtitle)
    
    set_title_recursive(widget, oldtitle, newtitle)

class OpenInNewTabHandler(ida_kernwin.action_handler_t):

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    def get_unique_title(self, base_title, prefix=""):
        check_title = f"{prefix}{base_title}" if prefix else base_title
        
        if ida_kernwin.find_widget(check_title) is None:
            return base_title
        
        counter = 1
        while True:
            numbered_title = f"{base_title} ({counter})"
            check_title = f"{prefix}{numbered_title}" if prefix else numbered_title
            if ida_kernwin.find_widget(check_title) is None:
                return numbered_title
            counter += 1
    
    def activate(self, ctx):
        func_ea = None
        
        if ctx.cur_value != ida_idaapi.BADADDR:
            target_func = ida_funcs.get_func(ctx.cur_value)
            if target_func is not None:
                func_ea = target_func.start_ea
        
        if func_ea is None:
            if ctx.cur_func is None:
                print("No function at cursor position")
                return 0
            func_ea = ctx.cur_func.start_ea
        
        func_name = ida_funcs.get_func_name(func_ea)
        
        widget_type = ctx.widget_type
        
        if widget_type == ida_kernwin.BWN_PSEUDOCODE:
            try:
                vdui = ida_hexrays.open_pseudocode(func_ea, ida_hexrays.OPF_NEW_WINDOW)
                if vdui:
                    base_title = f"Pseudocode: {func_name}"
                    title = self.get_unique_title(base_title)
                    set_window_title(vdui.toplevel, title)
                    print(f"Opened function '{func_name}' in new pseudocode tab")
                else:
                    print(f"Failed to open pseudocode for '{func_name}'")
            except Exception as e:
                print(f"Error opening pseudocode: {e}")
                
        elif widget_type == ida_kernwin.BWN_DISASM:
            try:
                base_title = f"IDA View: {func_name}"
                title = self.get_unique_title(base_title)
                
                widget = ida_kernwin.open_disasm_window(func_name)
                if widget:
                    ida_kernwin.activate_widget(widget, True)
                    ida_kernwin.jumpto(func_ea, -1, ida_kernwin.UIJMP_ACTIVATE | ida_kernwin.UIJMP_IDAVIEW)
                    
                    set_window_title(widget, title)
                    print(f"Opened function '{func_name}' in new disassembly tab")
                else:
                    print(f"Failed to open disassembly window for '{func_name}'")
            except Exception as e:
                print(f"Error opening disassembly: {e}")
        else:
            print(f"Unknown widget type: {widget_type}")
            return 0
        
        return 1
    
    def update(self, ctx):
        if ctx.widget_type in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            if ctx.cur_func is not None:
                return ida_kernwin.AST_ENABLE_FOR_WIDGET
        
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class UIHooks(ida_kernwin.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup):
        widget_type = ida_kernwin.get_widget_type(widget)
        
        if widget_type in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME, None)


class OpenInNewTabPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Open function in a new tab"
    help = "Right-click on a function and select 'Open in a new tab' to open it in a new view"
    wanted_name = "Open in new tab"
    wanted_hotkey = ""
    
    def __init__(self):
        super(OpenInNewTabPlugin, self).__init__()
        self.enabled = True
        self.ui_hooks = None
    
    def init(self):
        self.enabled = load_plugin_enabled_state()
        
        action_desc = ida_kernwin.action_desc_t(
            ACTION_NAME,                          # Action name
            "Open in a new tab",                  # Action label
            OpenInNewTabHandler(),                # Action handler
            None,                                 # Optional shortcut
            "Open this function in a new tab",    # Tooltip
            -1                                    # Icon (use -1 for no icon)
        )
        
        if not ida_kernwin.register_action(action_desc):
            print("Failed to register \"Open in new tab\" action")
            return ida_idaapi.PLUGIN_SKIP
        
        self.ui_hooks = UIHooks()
        if self.enabled:
            self.ui_hooks.hook()
            print("\"Open in new tab\" plugin loaded (enabled)")
        else:
            print("\"Open in new tab\" plugin loaded (disabled)")
        
        return ida_idaapi.PLUGIN_KEEP
    
    def run(self, arg):
        dialog = AboutDialog(self.enabled)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            new_enabled = dialog.is_enabled()
            if new_enabled != self.enabled:
                self.enabled = new_enabled
                save_plugin_enabled_state(self.enabled)
                
                if self.enabled:
                    if self.ui_hooks is not None:
                        self.ui_hooks.hook()
                    print("Open in new tab plugin enabled")
                else:
                    if self.ui_hooks is not None:
                        self.ui_hooks.unhook()
                    print("\"Open in new tab\" plugin disabled")
    
    def term(self):
        if hasattr(self, 'ui_hooks'):
            self.ui_hooks.unhook()
        
        ida_kernwin.unregister_action(ACTION_NAME)
        
        print("\"Open in new tab\" plugin unloaded")


def PLUGIN_ENTRY():
    return OpenInNewTabPlugin()
