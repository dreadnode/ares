local function strip_ansi_osc(text)
    text = text:gsub('\27%].-\7', '')      -- OSC to BEL
    text = text:gsub('\27%].-\27\\', '')   -- OSC to ST
    text = text:gsub('\27%[[%d;?]*[ -/]*[@-~]', '')
    text = text:gsub('\27.', '')
    return text
end

local function undo_backspace_echo(line)
    while line:find(".\b") do
        line = line:gsub(".\b", "", 1)
    end
    return line
end

local function clean_line(line)
    line = strip_ansi_osc(line or "")
    line = line:gsub('[\r\x07\x0B]', '')
    line = undo_backspace_echo(line)
    return line
end

-- Identify prompt lines – ONLY treat full prompt+command as candidate
local function is_prompt(line)
    line = line:match("^%s*(.-)%s*$") or ""
    if line:match("^└*─*#%s*$") or line:match("^└*─*[$#]%s*$") then return true end
    if line:match("^[$#]%s*$") then return true end
    if line:match("^[^@]+@[^:]+:.*[%$#]%s*$") then return true end
    return false
end

-- Ignore bash/readline artifacts
local function is_readline_junk(line)
    line = clean_line(line)
    return line:match("^bck%-i%-search:") or line:find("bash%-i%-search:")
end

-- Junk-echo or paste detection
local function is_tick_junk(cmd)
    if not cmd then return false end

    -- If it's echoed form of the prompt or the prompt itself
    if cmd:match("^┌──") then return true end
    if is_prompt(cmd) then return true end

    -- Avoid false positives with Python and shell commands containing quotes
    if cmd:match("([%w_]+)%s+[%w_]+%s+%1%s+[%w_]+%s+%1") then return true end

    -- Special case: Don't flag Python commands as junk
    if cmd:match("^python[23]?%s+%-c%s+") then return false end

    return false
end

-- Output that looks like a re-printed prompt banner
local function is_only_prompt_banner(line)
    line = clean_line(line)
    if line:match("^┌──") or is_prompt(line) then return true end
    return false
end

-- Track both command records and pending outputs
local sessions = {}
-- Track commands waiting for output
local pending_commands = {}

-- Ignore lines that contain Lua code, Fluent Bit debug, or filter noise
local function is_junk_log(s)
    if not s then return false end
    -- Only block if a HUGE chunk (say, 10+ lines) matches your actual Lua script
    local suspect = 0
    local lua_signatures = {
        'local function strip_ansi_osc',
        'undo_backspace_echo',
        'clean_line',
        'is_prompt',
        'is_readline_junk',
        'is_tick_junk',
        'is_only_prompt_banner',
        'sessions = {',
        'function process_ssm_logs',
    }
    for _, pat in ipairs(lua_signatures) do
        if s:find(pat, 1, true) then suspect = suspect + 1 end
        if suspect > 2 then return true end -- found 3+ source signature lines, block this as junk
    end
    return false
end

function process_ssm_logs(tag, timestamp, record)
    if not record.raw_output then return 1, timestamp, record end

    -- Only skip if the ENTIRE payload looks like a pasted Lua script!
    if is_junk_log(record.raw_output) then return -1 end

    local lines = {}
    for line in record.raw_output:gmatch("[^\n]+") do
        table.insert(lines, line)
    end

    local s = sessions[tag] or { last_command = nil, last_prompt_ts = nil, emitted_commands = {} }
    sessions[tag] = s

    -- 1. Find prompt+command
    for _, rawline in ipairs(lines) do
        local cline = clean_line(rawline)
        if is_readline_junk(cline) or cline == "" then goto continue end

        -- Look for prompt+command: [prompt][space][command]
        local prompt, cmd = cline:match("^(└*─*[$#])%s+(.+)$")
        if not prompt then prompt, cmd = cline:match("^([$#])%s+(.+)$") end
        if not prompt then
            local _, _, userprompt, usercmd = cline:find("^([%w%-_%.]+@[%w%-_%.]+:.*[%$#])%s+(.+)$")
            if userprompt and usercmd then prompt, cmd = userprompt, usercmd end
        end

        if prompt and cmd and not is_tick_junk(cmd) then
            -- Check if we've already emitted this exact command recently (within 1 second)
            local command_key = cmd .. tostring(math.floor(timestamp))
            if not s.emitted_commands[command_key] then
                s.last_command = cmd
                s.last_prompt_ts = timestamp

                local cmd_record = {
                    log_type = "command",
                    command = cmd,
                    timestamp = timestamp,
                    original_record = record
                }

                -- Store the command by its unique key for later
                pending_commands[command_key] = cmd_record

                -- Mark this command as processed
                s.emitted_commands[command_key] = timestamp
                sessions[tag] = s

                -- CHANGED: DON'T return the command record yet
                -- We'll return it later if we find an output
                -- return 1, timestamp, record

                -- Skip processing for now
                return -1
            end
        end

        ::continue::
    end

    -- 2. Output after command (within 5 seconds, skip junk, skip prompt banners)
    if s.last_command and s.last_prompt_ts and ((timestamp - s.last_prompt_ts) < 5) then
        local output_lines = {}
        for _, rawline in ipairs(lines) do
            local cline = clean_line(rawline)
            if is_readline_junk(cline) then goto continue2 end
            if is_prompt(cline) or cline == "" then goto continue2 end
            if is_only_prompt_banner(cline) then goto continue2 end
            -- Discard lines that are just new banners
            table.insert(output_lines, cline)
            ::continue2::
        end
        local output = table.concat(output_lines, "\n")

        if #output > 0 then
            -- We found output for the most recent command
            local command_key = s.last_command .. tostring(math.floor(s.last_prompt_ts))
            local cmd_record = pending_commands[command_key]

            -- Create an output record
            record.log_type = "output"
            record.command = s.last_command
            record.command_output = output

            -- Clear the pending command record since we found its output
            pending_commands[command_key] = nil

            -- Prevent duplicate emission for same command/output combo
            s.last_command = nil
            s.last_prompt_ts = nil
            sessions[tag] = s

            -- Return the output record with the command info
            return 1, timestamp, record
        end
    end

    -- Clean up old entries from emitted_commands (older than 10 seconds)
    local current_time = timestamp
    for cmd_key, cmd_time in pairs(s.emitted_commands) do
        if current_time - cmd_time > 10 then
            s.emitted_commands[cmd_key] = nil
            -- Also clean up any pending commands older than 10 seconds
            pending_commands[cmd_key] = nil
        end
    end
    sessions[tag] = s

    return -1
end
