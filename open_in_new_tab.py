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
import ida_name
import os

try:
    from PySide6 import QtCore, QtGui, QtWidgets
except ImportError:
    try:
        from PyQt5 import QtCore, QtGui, QtWidgets
    except ImportError:
        from PySide2 import QtCore, QtGui, QtWidgets

ACTION_NAME = "open_in_new_tab:open_func"
ACTION_NAME_DISASM = "open_in_new_tab:open_disasm"
ACTION_NAME_PSEUDO = "open_in_new_tab:open_pseudo"

def get_config_path():
    return os.path.join(ida_diskio.get_user_idadir(), "open_in_new_tab.cfg")

def load_enabled_state():
    try:
        if os.path.exists(get_config_path()):
            with open(get_config_path(), 'r') as f:
                for line in f:
                    if line.strip().startswith("ENABLE_PLUGIN="):
                        return line.split("=", 1)[1].strip() in ("1", "true", "True")
    except:
        pass
    return True

def save_enabled_state(enabled):
    try:
        with open(get_config_path(), 'w') as f:
            f.write(f"ENABLE_PLUGIN={'1' if enabled else '0'}\n")
    except Exception as e:
        print(f"Failed to save plugin state: {e}")

def get_next_window_name():
    # Excel-style naming: A, B, ..., Z, AA, AB, ...
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    
    def num_to_letters(n):
        result = ""
        while True:
            result = letters[n % 26] + result
            n = n // 26
            if n == 0:
                break
            n -= 1
        return result
    
    for i in range(10000):
        name = num_to_letters(i)
        if ida_kernwin.find_widget(f"IDA View-{name}") is None:
            return name
    
    import time
    return str(int(time.time() % 100000))

def find_main_area_widget():
    for i in range(50):
        letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if i < 26:
            name = f"IDA View-{letters[i]}"
        else:
            name = f"IDA View-{i - 25}"
        if ida_kernwin.find_widget(name):
            return name
    
    for i in range(20):
        name = f"Pseudocode-{chr(65 + i) if i < 26 else i - 25}"
        if ida_kernwin.find_widget(name):
            return name
    
    for name in ["Hex View-1", "Exports", "Imports", "Local Types", "Strings"]:
        if ida_kernwin.find_widget(name):
            return name
    
    return None

def dock_to_main_area(widget, widget_type):
    def do_dock():
        title = ida_kernwin.get_widget_title(widget)
        target_name = find_main_area_widget()
        
        if target_name:
            try:
                ida_kernwin.set_dock_pos(title, target_name, ida_kernwin.DP_TAB)
            except:
                pass
    
    ida_kernwin.execute_sync(do_dock, ida_kernwin.MFF_FAST)

def get_function_ea(ctx):
    widget_type = ctx.widget_type
    
    if widget_type == ida_kernwin.BWN_FUNCS:
        if ctx.chooser_selection and len(ctx.chooser_selection) > 0:
            func = ida_funcs.getn_func(ctx.chooser_selection[0])
            return func.start_ea if func else None
        return None
    
    func_ea = None
    
    if widget_type == ida_kernwin.BWN_PSEUDOCODE:
        try:
            vu = ida_hexrays.get_widget_vdui(ctx.widget)
            if vu:
                for use_mouse in [True, False]:
                    vu.get_current_item(ida_hexrays.USE_MOUSE if use_mouse else ida_hexrays.USE_KEYBOARD)
                    item = vu.item
                    
                    if item.citype == ida_hexrays.VDI_EXPR and item.e:
                        expr = item.e
                        if expr.op == ida_hexrays.cot_call and expr.x:
                            if expr.x.op == ida_hexrays.cot_obj:
                                func_ea = expr.x.obj_ea
                                break
                            elif expr.x.op == ida_hexrays.cot_helper and expr.x.helper:
                                helper_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, expr.x.helper)
                                if helper_ea != ida_idaapi.BADADDR:
                                    func_ea = helper_ea
                                    break
                        elif expr.op == ida_hexrays.cot_obj:
                            target_func = ida_funcs.get_func(expr.obj_ea)
                            if target_func:
                                func_ea = target_func.start_ea
                                break
                    if func_ea:
                        break
        except:
            pass
    
    if func_ea is None and ctx.cur_value != ida_idaapi.BADADDR:
        target_func = ida_funcs.get_func(ctx.cur_value)
        if target_func:
            func_ea = target_func.start_ea
        else:
            name = ida_name.get_name(ctx.cur_value)
            if name:
                named_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
                if named_ea != ida_idaapi.BADADDR:
                    named_func = ida_funcs.get_func(named_ea)
                    if named_func:
                        func_ea = named_func.start_ea
    
    if func_ea is None and ctx.cur_ea != ida_idaapi.BADADDR:
        target_func = ida_funcs.get_func(ctx.cur_ea)
        if target_func and (not ctx.cur_func or target_func.start_ea != ctx.cur_func.start_ea):
            func_ea = target_func.start_ea
    
    if func_ea is None and ctx.cur_func:
        func_ea = ctx.cur_func.start_ea
    
    return func_ea

class AboutDialog(QtWidgets.QDialog):
    def __init__(self, plugin_enabled, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About")
        self.setWindowFlags(self.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint)
        
        content_layout = QtWidgets.QVBoxLayout()
        content_layout.setSpacing(0)
        content_layout.setContentsMargins(30, 20, 30, 20)
        
        title_layout = QtWidgets.QHBoxLayout()
        title_layout.setSpacing(0)
        
        title_label = QtWidgets.QLabel('"Open in new tab" - IDA Pro Plugin')
        title_font = QtGui.QFont()
        title_font.setPointSize(11)
        title_label.setFont(title_font)
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        
        reload_button = QtWidgets.QPushButton("Reload Plugin")
        reload_button.setToolTip("Reload without restarting IDA")
        reload_button.clicked.connect(self.reload_plugin)
        title_layout.addWidget(reload_button)
        
        content_layout.addLayout(title_layout)
        content_layout.addSpacing(4)
        
        source_label = QtWidgets.QLabel(
            'Source: <a href="https://github.com/DefaultO/ida-new-tab" style="color: #5c9fd8; text-decoration: none;">https://github.com/DefaultO/ida-new-tab</a>'
        )
        source_label.setOpenExternalLinks(True)
        source_font = QtGui.QFont()
        source_font.setPointSize(8)
        source_label.setFont(source_font)
        content_layout.addWidget(source_label)
        
        version_label = QtWidgets.QLabel('Version: 1.0')
        version_font = QtGui.QFont()
        version_font.setPointSize(8)
        version_label.setFont(version_font)
        content_layout.addWidget(version_label)
        
        content_layout.addSpacing(8)
        
        desc_label = QtWidgets.QLabel('Description: Right-click function names to open in new window tabs')
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
        
        self.setLayout(content_layout)
        self.adjustSize()
        self.setFixedSize(self.size())
    
    def is_enabled(self):
        return self.enable_checkbox.isChecked()
    
    def reload_plugin(self):
        try:
            import sys
            
            plugin_module = None
            for name, module in sys.modules.items():
                if hasattr(module, 'OpenInNewTabPlugin') and hasattr(module, 'PLUGIN_ENTRY'):
                    plugin_module = module
                    break
            
            if plugin_module and hasattr(plugin_module, '__file__'):
                with open(plugin_module.__file__, 'r', encoding='utf-8') as f:
                    exec(compile(f.read(), plugin_module.__file__, 'exec'), plugin_module.__dict__)
                
                QtWidgets.QMessageBox.information(
                    self, "Plugin Reloaded",
                    f"Plugin reloaded successfully!\n\nClose and reopen this dialog to see changes."
                )
            else:
                QtWidgets.QMessageBox.warning(self, "Reload Failed", "Plugin module not found.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Reload Error", f"Failed to reload:\n{str(e)}")

class OpenInNewTabHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        func_ea = get_function_ea(ctx)
        if not func_ea:
            return 0
        
        func_name = ida_funcs.get_func_name(func_ea)
        widget_type = ctx.widget_type
        target_type = ida_kernwin.BWN_DISASM if widget_type == ida_kernwin.BWN_FUNCS else widget_type
        
        try:
            if target_type == ida_kernwin.BWN_PSEUDOCODE:
                vdui = ida_hexrays.open_pseudocode(func_ea, ida_hexrays.OPF_NEW_WINDOW | ida_hexrays.OPF_NO_WAIT)
                if vdui and widget_type == ida_kernwin.BWN_FUNCS:
                    dock_to_main_area(vdui.toplevel, "pseudo")
                if vdui:
                    print(f"Opened '{func_name}' ({hex(func_ea)}) in new pseudocode view")
                return 1
            else:
                widget = ida_kernwin.open_disasm_window(get_next_window_name())
                if widget:
                    if widget_type == ida_kernwin.BWN_FUNCS:
                        dock_to_main_area(widget, "disasm")
                    ida_kernwin.activate_widget(widget, True)
                    ida_kernwin.jumpto(func_ea, -1, ida_kernwin.UIJMP_ACTIVATE | ida_kernwin.UIJMP_IDAVIEW)
                    print(f"Opened '{func_name}' ({hex(func_ea)}) in new disassembly view")
                return 1
        except Exception as e:
            print(f"Error: {e}")
            return 0
    
    def update(self, ctx):
        if ctx.widget_type not in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE, ida_kernwin.BWN_FUNCS):
            return ida_kernwin.AST_DISABLE_FOR_WIDGET
        
        if ctx.widget_type == ida_kernwin.BWN_FUNCS:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.chooser_selection else ida_kernwin.AST_DISABLE_FOR_WIDGET
        
        func_ea = get_function_ea(ctx)
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if func_ea and ida_funcs.get_func_name(func_ea) else ida_kernwin.AST_DISABLE_FOR_WIDGET

class OpenInDisasmHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        func_ea = get_function_ea(ctx)
        if not func_ea:
            return 0
        
        func_name = ida_funcs.get_func_name(func_ea)
        
        try:
            widget = ida_kernwin.open_disasm_window(get_next_window_name())
            if widget:
                if ctx.widget_type == ida_kernwin.BWN_FUNCS:
                    dock_to_main_area(widget, "disasm")
                ida_kernwin.activate_widget(widget, True)
                ida_kernwin.jumpto(func_ea, -1, ida_kernwin.UIJMP_ACTIVATE | ida_kernwin.UIJMP_IDAVIEW)
                print(f"Opened '{func_name}' ({hex(func_ea)}) in new disassembly view")
            return 1
        except Exception as e:
            print(f"Error: {e}")
            return 0
    
    def update(self, ctx):
        if ctx.widget_type not in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE, ida_kernwin.BWN_FUNCS):
            return ida_kernwin.AST_DISABLE_FOR_WIDGET
        
        if ctx.widget_type == ida_kernwin.BWN_FUNCS:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.chooser_selection else ida_kernwin.AST_DISABLE_FOR_WIDGET
        
        func_ea = get_function_ea(ctx)
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if func_ea and ida_funcs.get_func_name(func_ea) else ida_kernwin.AST_DISABLE_FOR_WIDGET

class OpenInPseudoHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        func_ea = get_function_ea(ctx)
        if not func_ea:
            return 0
        
        func_name = ida_funcs.get_func_name(func_ea)
        
        try:
            vdui = ida_hexrays.open_pseudocode(func_ea, ida_hexrays.OPF_NEW_WINDOW | ida_hexrays.OPF_NO_WAIT)
            if vdui and ctx.widget_type == ida_kernwin.BWN_FUNCS:
                dock_to_main_area(vdui.toplevel, "pseudo")
            if vdui:
                print(f"Opened '{func_name}' ({hex(func_ea)}) in new pseudocode view")
            return 1
        except Exception as e:
            print(f"Error: {e}")
            return 0
    
    def update(self, ctx):
        if ctx.widget_type not in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE, ida_kernwin.BWN_FUNCS):
            return ida_kernwin.AST_DISABLE_FOR_WIDGET
        
        if ctx.widget_type == ida_kernwin.BWN_FUNCS:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.chooser_selection else ida_kernwin.AST_DISABLE_FOR_WIDGET
        
        func_ea = get_function_ea(ctx)
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if func_ea and ida_funcs.get_func_name(func_ea) else ida_kernwin.AST_DISABLE_FOR_WIDGET

class UIHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        widget_type = ida_kernwin.get_widget_type(widget)
        
        if widget_type in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME, None)
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME_DISASM, None)
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME_PSEUDO, None)
        elif widget_type == ida_kernwin.BWN_FUNCS:
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME_DISASM, None)
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME_PSEUDO, None)

class OpenInNewTabPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Open functions in new tabs"
    help = "Right-click functions to open in new views"
    wanted_name = "Open in new tab"
    wanted_hotkey = ""
    
    def __init__(self):
        super().__init__()
        self.enabled = True
        self.ui_hooks = None
    
    def init(self):
        self.enabled = load_enabled_state()
        
        actions = [
            (ACTION_NAME, "Open in new view", OpenInNewTabHandler()),
            (ACTION_NAME_DISASM, "Open in new disassembly view", OpenInDisasmHandler()),
            (ACTION_NAME_PSEUDO, "Open in new pseudocode view", OpenInPseudoHandler()),
        ]
        
        for action_name, label, handler in actions:
            desc = ida_kernwin.action_desc_t(action_name, label, handler, None, f"{label}", -1)
            if not ida_kernwin.register_action(desc):
                print(f"Failed to register {label}")
                return ida_idaapi.PLUGIN_SKIP
        
        self.ui_hooks = UIHooks()
        if self.enabled:
            self.ui_hooks.hook()
        
        return ida_idaapi.PLUGIN_KEEP
    
    def run(self, arg):
        dialog = AboutDialog(self.enabled)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            new_enabled = dialog.is_enabled()
            if new_enabled != self.enabled:
                self.enabled = new_enabled
                save_enabled_state(self.enabled)
                
                if self.ui_hooks:
                    self.ui_hooks.hook() if self.enabled else self.ui_hooks.unhook()
    
    def term(self):
        if self.ui_hooks:
            self.ui_hooks.unhook()
        
        for action in [ACTION_NAME, ACTION_NAME_DISASM, ACTION_NAME_PSEUDO]:
            ida_kernwin.unregister_action(action)

def PLUGIN_ENTRY():
    return OpenInNewTabPlugin()
