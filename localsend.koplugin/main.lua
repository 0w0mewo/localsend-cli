local DataStorage = require("datastorage")
local Device = require("device")
local Dispatcher = require("dispatcher")
local InfoMessage = require("ui/widget/infomessage")
local InputDialog = require("ui/widget/inputdialog")
local PathChooser = require("ui/widget/pathchooser")
local UIManager = require("ui/uimanager")
local WidgetContainer = require("ui/widget/container/widgetcontainer")
local ffiutil = require("ffi/util")
local logger = require("logger")
local util = require("util")
local _ = require("gettext")
local T = ffiutil.template
local json = require("json")

local data_dir = DataStorage:getFullDataDir()
local plugin_path = data_dir .. "/plugins/localsend.koplugin"
local binary_path = plugin_path .. "/localsend"
local cert_storage_path = plugin_path .. "/certs"
local pid_file = "/tmp/localsend_koreader.pid"
local transfer_log_file = "/tmp/localsend_transfers.log"

-- Extension presets
local EXTENSION_PRESETS = {
    { name = _("All files"), value = "" },
    { name = _("eBooks (epub, pdf, mobi, azw3)"), value = "epub,pdf,mobi,azw3" },
    { name = _("eBooks + CBZ (comics)"), value = "epub,pdf,mobi,azw3,cbz,cbr" },
    { name = _("PDF only"), value = "pdf" },
    { name = _("EPUB only"), value = "epub" },
    { name = _("Custom..."), value = nil },
}

-- Check if binary exists
if not util.pathExists(binary_path) then
    return { disabled = true, }
end

local LocalSend = WidgetContainer:extend{
    name = "LocalSend",
    is_doc_only = false,
    last_transfer_count = 0,
}

function LocalSend:init()
    self.port = G_reader_settings:readSetting("LocalSend_port") or "53317"
    self.save_dir = G_reader_settings:readSetting("LocalSend_save_dir") or "/mnt/us/documents"
    self.device_name = G_reader_settings:readSetting("LocalSend_device_name") or ""
    self.use_https = G_reader_settings:nilOrTrue("LocalSend_use_https")
    self.autostart = G_reader_settings:isTrue("LocalSend_autostart")
    self.pin = G_reader_settings:readSetting("LocalSend_pin") or ""
    self.accept_ext = G_reader_settings:readSetting("LocalSend_accept_ext") or ""
    self.last_transfer_count = 0

    if self.autostart then
        self:start()
    end

    self.ui.menu:registerToMainMenu(self)
    self:onDispatcherRegisterActions()
end

function LocalSend:setupCertificates()
    -- Ensure cert storage directory exists
    if not util.pathExists(cert_storage_path) then
        os.execute("mkdir -p " .. cert_storage_path)
    end

    local stored_key = cert_storage_path .. "/server.key.pem"
    local stored_cert = cert_storage_path .. "/server.crt"
    local tmp_key = "/tmp/server.key.pem"
    local tmp_cert = "/tmp/server.crt"

    -- If we have stored certs, symlink them to /tmp where localsend expects them
    if util.pathExists(stored_key) and util.pathExists(stored_cert) then
        os.execute("ln -sf " .. stored_key .. " " .. tmp_key)
        os.execute("ln -sf " .. stored_cert .. " " .. tmp_cert)
        logger.dbg("[LocalSend] Using stored certificates")
        return true
    end

    return false
end

function LocalSend:saveCertificates()
    -- After first run, copy generated certs to persistent storage
    local tmp_key = "/tmp/server.key.pem"
    local tmp_cert = "/tmp/server.crt"
    local stored_key = cert_storage_path .. "/server.key.pem"
    local stored_cert = cert_storage_path .. "/server.crt"

    if util.pathExists(tmp_key) and util.pathExists(tmp_cert) then
        if not util.pathExists(stored_key) then
            os.execute("cp " .. tmp_key .. " " .. stored_key)
            os.execute("cp " .. tmp_cert .. " " .. stored_cert)
            logger.dbg("[LocalSend] Saved certificates for future use")
        end
    end
end

function LocalSend:openFirewall()
    if Device:isKindle() then
        -- TCP for file transfer
        os.execute(string.format(
            "iptables -A INPUT -p tcp --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT",
            self.port))
        os.execute(string.format(
            "iptables -A OUTPUT -p tcp --sport %s -m conntrack --ctstate ESTABLISHED -j ACCEPT",
            self.port))
        -- UDP for device discovery
        os.execute(string.format(
            "iptables -A INPUT -p udp --dport %s -j ACCEPT",
            self.port))
        os.execute(string.format(
            "iptables -A OUTPUT -p udp --sport %s -j ACCEPT",
            self.port))
        logger.dbg("[LocalSend] Firewall opened for port " .. self.port)
    end
end

function LocalSend:closeFirewall()
    if Device:isKindle() then
        os.execute(string.format(
            "iptables -D INPUT -p tcp --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT",
            self.port))
        os.execute(string.format(
            "iptables -D OUTPUT -p tcp --sport %s -m conntrack --ctstate ESTABLISHED -j ACCEPT",
            self.port))
        os.execute(string.format(
            "iptables -D INPUT -p udp --dport %s -j ACCEPT",
            self.port))
        os.execute(string.format(
            "iptables -D OUTPUT -p udp --sport %s -j ACCEPT",
            self.port))
        logger.dbg("[LocalSend] Firewall closed for port " .. self.port)
    end
end

function LocalSend:validateSaveDir(path)
    -- Check if path exists
    if not util.pathExists(path) then
        -- Try to create it
        local result = os.execute("mkdir -p " .. path)
        if result ~= 0 then
            return false, _("Directory does not exist and could not be created.")
        end
    end

    -- Check if writable by trying to create a temp file
    local test_file = path .. "/.localsend_write_test"
    local f = io.open(test_file, "w")
    if not f then
        return false, _("Directory is not writable.")
    end
    f:close()
    os.remove(test_file)

    return true
end

function LocalSend:getTransferLog()
    local transfers = {}
    if not util.pathExists(transfer_log_file) then
        return transfers
    end

    local f = io.open(transfer_log_file, "r")
    if not f then return transfers end

    for line in f:lines() do
        local ok, entry = pcall(json.decode, line)
        if ok and entry then
            table.insert(transfers, entry)
        end
    end
    f:close()

    return transfers
end

function LocalSend:getTransferCount()
    local count = 0
    if not util.pathExists(transfer_log_file) then
        return 0
    end

    local f = io.open(transfer_log_file, "r")
    if not f then return 0 end

    for _ in f:lines() do
        count = count + 1
    end
    f:close()

    return count
end

function LocalSend:clearTransferLog()
    os.remove(transfer_log_file)
    self.last_transfer_count = 0
end

function LocalSend:checkForNewTransfers()
    if not self:isRunning() then
        return
    end

    local current_count = self:getTransferCount()
    if current_count > self.last_transfer_count then
        local new_count = current_count - self.last_transfer_count
        local transfers = self:getTransferLog()

        -- Get the most recent transfer
        local latest = transfers[#transfers]
        if latest then
            local text
            if new_count == 1 then
                text = T(_("File received: %1"), latest.filename)
            else
                text = T(_("%1 files received. Latest: %2"), new_count, latest.filename)
            end

            UIManager:show(InfoMessage:new{
                text = text,
                timeout = 5,
            })
        end

        self.last_transfer_count = current_count
    end

    -- Schedule next check
    UIManager:scheduleIn(5, function()
        self:checkForNewTransfers()
    end)
end

function LocalSend:start()
    if self:isRunning() then
        logger.dbg("[LocalSend] Server already running")
        return
    end

    -- Validate save directory
    local valid, err = self:validateSaveDir(self.save_dir)
    if not valid then
        UIManager:show(InfoMessage:new{
            icon = "notice-warning",
            text = T(_("Invalid save directory: %1"), err),
        })
        return
    end

    -- Setup persistent certificates
    self:setupCertificates()

    -- Clear old transfer log and reset count
    self:clearTransferLog()

    -- Build command
    local cmd = string.format("%s recv -d '%s' -l '%s'",
        binary_path,
        self.save_dir,
        transfer_log_file)

    if self.device_name ~= "" then
        cmd = string.format("%s -n '%s'", cmd, self.device_name)
    end

    if self.pin ~= "" then
        cmd = string.format("%s -p '%s'", cmd, self.pin)
    end

    if self.accept_ext ~= "" then
        cmd = string.format("%s -a '%s'", cmd, self.accept_ext)
    end

    if not self.use_https then
        cmd = string.format("%s --https=false", cmd)
    end

    -- Open firewall before starting
    self:openFirewall()

    -- Run in background and save PID
    cmd = string.format("(%s) & echo $! > %s", cmd, pid_file)

    logger.dbg("[LocalSend] Starting server: ", cmd)

    local result = os.execute(cmd)

    if result == 0 then
        -- Give it a moment to start and generate certs
        ffiutil.sleep(2)

        -- Verify it actually started
        if self:isRunning() then
            self:saveCertificates()

            -- Start checking for new transfers
            UIManager:scheduleIn(5, function()
                self:checkForNewTransfers()
            end)

            local info = InfoMessage:new{
                timeout = 10,
                text = T(_("LocalSend server started.\n\nPort: %1\nSave directory: %2\n%3"),
                    self.port,
                    self.save_dir,
                    Device.retrieveNetworkInfo and Device:retrieveNetworkInfo() or _("Could not retrieve network info.")),
            }
            UIManager:show(info)
        else
            self:closeFirewall()
            UIManager:show(InfoMessage:new{
                icon = "notice-warning",
                text = _("LocalSend process exited unexpectedly. Check if the binary works."),
            })
        end
    else
        self:closeFirewall()
        local info = InfoMessage:new{
            icon = "notice-warning",
            text = _("Failed to start LocalSend server."),
        }
        UIManager:show(info)
    end
end

function LocalSend:isRunning()
    if not util.pathExists(pid_file) then
        return false
    end

    -- Also verify the process is actually alive
    local f = io.open(pid_file, "r")
    if not f then return false end
    local pid = f:read("*l")
    f:close()

    if pid and tonumber(pid) then
        return util.pathExists("/proc/" .. pid)
    end

    return false
end

function LocalSend:stopServer(force)
    if not util.pathExists(pid_file) then
        return true
    end

    local function readPID()
        local f = io.open(pid_file, "r")
        if not f then return nil end
        local s = f:read("*l")
        f:close()
        return s and tonumber(s) or nil
    end

    local pid = readPID()

    local function isProcAlive(p)
        return p and util.pathExists("/proc/" .. p)
    end

    local function send(sig, p)
        return os.execute(string.format("kill -%s %d", sig, p)) == 0
    end

    if pid then
        send("TERM", pid)
        for _ = 1, 20 do
            if not isProcAlive(pid) then break end
            ffiutil.sleep(0.1)
        end

        if isProcAlive(pid) and force then
            send("KILL", pid)
            for _ = 1, 10 do
                if not isProcAlive(pid) then break end
                ffiutil.sleep(0.1)
            end
        end

        if not isProcAlive(pid) then
            os.remove(pid_file)
            self:closeFirewall()
            return true
        end
        return false, "LocalSend process did not exit"
    end

    os.remove(pid_file)
    self:closeFirewall()
    return true
end

function LocalSend:stop()
    local ok, err = self:stopServer(false)
    if not ok then
        logger.warn("[LocalSend] Graceful stop failed:", err)
        ok, err = self:stopServer(true)
        if not ok then
            logger.err("[LocalSend] Force stop failed:", err)
            UIManager:show(InfoMessage:new{
                icon = "notice-warning",
                text = _("Failed to stop LocalSend server."),
            })
            return
        end
    end
    UIManager:show(InfoMessage:new{
        text = _("LocalSend server stopped."),
        timeout = 2,
    })
end

function LocalSend:restart()
    if self:isRunning() then
        self:stopServer(true)
    end
    self:start()
end

function LocalSend:onToggleLocalSend()
    if self:isRunning() then
        self:stop()
    else
        self:start()
    end
end

function LocalSend:showSaveDirPicker(touchmenu_instance)
    local path_chooser = PathChooser:new{
        select_directory = true,
        select_file = false,
        path = self.save_dir,
        onConfirm = function(path)
            local valid, err = self:validateSaveDir(path)
            if valid then
                self.save_dir = path
                G_reader_settings:saveSetting("LocalSend_save_dir", self.save_dir)
                touchmenu_instance:updateItems()
            else
                UIManager:show(InfoMessage:new{
                    icon = "notice-warning",
                    text = T(_("Cannot use this directory: %1"), err),
                })
            end
        end,
    }
    UIManager:show(path_chooser)
end

function LocalSend:showDeviceNameDialog(touchmenu_instance)
    self.device_name_dialog = InputDialog:new{
        title = _("Device name"),
        description = _("Leave empty for random name (e.g., 'Special Pineapple')"),
        input = self.device_name,
        input_hint = "My Kindle",
        buttons = {
            {
                {
                    text = _("Cancel"),
                    id = "close",
                    callback = function()
                        UIManager:close(self.device_name_dialog)
                    end,
                },
                {
                    text = _("Save"),
                    is_enter_default = true,
                    callback = function()
                        self.device_name = self.device_name_dialog:getInputText()
                        G_reader_settings:saveSetting("LocalSend_device_name", self.device_name)
                        UIManager:close(self.device_name_dialog)
                        touchmenu_instance:updateItems()
                    end,
                },
            },
        },
    }
    UIManager:show(self.device_name_dialog)
    self.device_name_dialog:onShowKeyboard()
end

function LocalSend:showPinDialog(touchmenu_instance)
    self.pin_dialog = InputDialog:new{
        title = _("PIN code"),
        description = _("Leave empty to disable PIN protection"),
        input = self.pin,
        input_hint = "1234",
        buttons = {
            {
                {
                    text = _("Cancel"),
                    id = "close",
                    callback = function()
                        UIManager:close(self.pin_dialog)
                    end,
                },
                {
                    text = _("Save"),
                    is_enter_default = true,
                    callback = function()
                        self.pin = self.pin_dialog:getInputText()
                        G_reader_settings:saveSetting("LocalSend_pin", self.pin)
                        UIManager:close(self.pin_dialog)
                        touchmenu_instance:updateItems()
                    end,
                },
            },
        },
    }
    UIManager:show(self.pin_dialog)
    self.pin_dialog:onShowKeyboard()
end

function LocalSend:showCustomExtDialog()
    self.accept_ext_dialog = InputDialog:new{
        title = _("Custom extensions"),
        description = _("Comma-separated list (e.g., 'epub,pdf,mobi')"),
        input = self.accept_ext,
        input_hint = "epub,pdf,mobi",
        buttons = {
            {
                {
                    text = _("Cancel"),
                    id = "close",
                    callback = function()
                        UIManager:close(self.accept_ext_dialog)
                    end,
                },
                {
                    text = _("Save"),
                    is_enter_default = true,
                    callback = function()
                        self.accept_ext = self.accept_ext_dialog:getInputText()
                        G_reader_settings:saveSetting("LocalSend_accept_ext", self.accept_ext)
                        UIManager:close(self.accept_ext_dialog)
                    end,
                },
            },
        },
    }
    UIManager:show(self.accept_ext_dialog)
    self.accept_ext_dialog:onShowKeyboard()
end

function LocalSend:buildExtensionPresetsMenu()
    local menu = {}
    for _, preset in ipairs(EXTENSION_PRESETS) do
        if preset.value == nil then
            -- Custom option
            table.insert(menu, {
                text = preset.name,
                keep_menu_open = true,
                callback = function()
                    self:showCustomExtDialog()
                end,
            })
        else
            table.insert(menu, {
                text = preset.name,
                checked_func = function()
                    return self.accept_ext == preset.value
                end,
                callback = function()
                    self.accept_ext = preset.value
                    G_reader_settings:saveSetting("LocalSend_accept_ext", self.accept_ext)
                end,
            })
        end
    end
    return menu
end

function LocalSend:showRecentTransfers()
    local transfers = self:getTransferLog()

    if #transfers == 0 then
        UIManager:show(InfoMessage:new{
            text = _("No recent transfers."),
            timeout = 3,
        })
        return
    end

    -- Build text showing recent transfers (last 10)
    local lines = {}
    local start_idx = math.max(1, #transfers - 9)
    for i = start_idx, #transfers do
        local t = transfers[i]
        local size_str = ""
        if t.size then
            if t.size >= 1048576 then
                size_str = string.format(" (%.1f MB)", t.size / 1048576)
            elseif t.size >= 1024 then
                size_str = string.format(" (%.1f KB)", t.size / 1024)
            else
                size_str = string.format(" (%d B)", t.size)
            end
        end
        table.insert(lines, string.format("%d. %s%s", i, t.filename, size_str))
    end

    UIManager:show(InfoMessage:new{
        text = T(_("Recent transfers (%1 total):\n\n%2"), #transfers, table.concat(lines, "\n")),
    })
end

function LocalSend:rotateCertificates()
    -- Remove stored certificates so new ones will be generated
    os.execute("rm -f " .. cert_storage_path .. "/server.key.pem")
    os.execute("rm -f " .. cert_storage_path .. "/server.crt")
    os.execute("rm -f /tmp/server.key.pem")
    os.execute("rm -f /tmp/server.crt")

    UIManager:show(InfoMessage:new{
        text = _("Certificates cleared. New certificates will be generated on next start."),
        timeout = 3,
    })
end

function LocalSend:addToMainMenu(menu_items)
    menu_items.localsend = {
        text_func = function()
            if self:isRunning() then
                local count = self:getTransferCount()
                if count > 0 then
                    return T(_("LocalSend (%1 received)"), count)
                end
                return _("LocalSend (running)")
            end
            return _("LocalSend")
        end,
        sorting_hint = "network",
        sub_item_table = {
            {
                text_func = function()
                    if self:isRunning() then
                        return _("Stop server")
                    else
                        return _("Start server")
                    end
                end,
                callback = function(touchmenu_instance)
                    self:onToggleLocalSend()
                    ffiutil.sleep(1)
                    touchmenu_instance:updateItems()
                end,
            },
            {
                text = _("Restart server"),
                enabled_func = function() return self:isRunning() end,
                callback = function(touchmenu_instance)
                    self:restart()
                    ffiutil.sleep(1)
                    touchmenu_instance:updateItems()
                end,
            },
            {
                text = _("Recent transfers"),
                enabled_func = function() return self:getTransferCount() > 0 end,
                callback = function()
                    self:showRecentTransfers()
                end,
            },
            {
                text = "---",
            },
            {
                text_func = function()
                    if self.device_name ~= "" then
                        return T(_("Device name (%1)"), self.device_name)
                    else
                        return _("Device name (random)")
                    end
                end,
                keep_menu_open = true,
                enabled_func = function() return not self:isRunning() end,
                callback = function(touchmenu_instance)
                    self:showDeviceNameDialog(touchmenu_instance)
                end,
            },
            {
                text_func = function()
                    return T(_("Save directory (%1)"), self.save_dir)
                end,
                keep_menu_open = true,
                enabled_func = function() return not self:isRunning() end,
                callback = function(touchmenu_instance)
                    self:showSaveDirPicker(touchmenu_instance)
                end,
            },
            {
                text_func = function()
                    if self.accept_ext ~= "" then
                        return T(_("Allowed extensions (%1)"), self.accept_ext)
                    else
                        return _("Allowed extensions (all)")
                    end
                end,
                enabled_func = function() return not self:isRunning() end,
                sub_item_table_func = function()
                    return self:buildExtensionPresetsMenu()
                end,
            },
            {
                text_func = function()
                    if self.pin ~= "" then
                        return _("PIN code (enabled)")
                    else
                        return _("PIN code (disabled)")
                    end
                end,
                keep_menu_open = true,
                enabled_func = function() return not self:isRunning() end,
                callback = function(touchmenu_instance)
                    self:showPinDialog(touchmenu_instance)
                end,
            },
            {
                text = "---",
            },
            {
                text = _("Use HTTPS"),
                checked_func = function() return self.use_https end,
                enabled_func = function() return not self:isRunning() end,
                callback = function()
                    self.use_https = not self.use_https
                    G_reader_settings:flipNilOrTrue("LocalSend_use_https")
                end,
            },
            {
                text = _("Start with KOReader"),
                checked_func = function() return self.autostart end,
                callback = function()
                    self.autostart = not self.autostart
                    G_reader_settings:flipNilOrFalse("LocalSend_autostart")
                end,
            },
            {
                text = _("Rotate certificates"),
                keep_menu_open = true,
                enabled_func = function() return not self:isRunning() end,
                callback = function()
                    self:rotateCertificates()
                end,
            },
        }
    }
end

function LocalSend:onDispatcherRegisterActions()
    Dispatcher:registerAction("toggle_localsend_server",
        { category = "none", event = "ToggleLocalSend", title = _("Toggle LocalSend server"), general = true })
end

return LocalSend
