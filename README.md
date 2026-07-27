# sockpuppets

<img width="271.5" and height="362" alt="sockpuppets" src="https://github.com/user-attachments/assets/7105b452-0388-457b-b70f-3e2b623b7155" />

multi-language, multi-transport c2 framework with edr evasion, polymorphic code morphing, malleable c2 profiles, and steganographic delivery.

**shoutout and special thanks to:**
Skyler Knecht (@skylerknecht), Jeremy Schoeneman (@y4utj4), Matt Jackoski (@ds-koolaid), Mason Davis (@mas0nd), Kevin Clark (@clarkkev), Michael Weber (@michaelweber)

---

## quick start

```bash
git clone https://github.com/ajm4n/sockpuppets.git
cd sockpuppets
./setup.sh
python3 main.py
```

```
sockpuppets> start https 0.0.0.0 443
sockpuppets> generate 10.0.0.1 443 --lang=go --transport=https --beacon --interval=120 --jitter=30
sockpuppets> interact <agent_id>
```

```bash
# web gui
python3 main.py --gui

# tui
python3 main.py --tui
```

## features

- 6 agent languages (python, go, rust, c, c#, powershell)
- 3 transports (http, https, websocket) with compile-time selection
- beacon and streaming modes
- aes-256-gcm encrypted comms with per-agent keys
- exe, dll, and shellcode output formats
- malleable c2 profiles (m365, teams, slack, google docs, windows update, zoom)
- polymorphic code morphing, 85%+ structural uniqueness per build
- 60+ evasion functions across windows/linux/macos
- steganographic payload delivery via png
- staged delivery with encrypted stagers
- environmental keying (hostname, domain, mac, registry, string)
- socks5 proxy tunneling
- bof execution (cobalt strike compatible)
- redirector support with nginx/apache config generation
- ghost profiles for ml/vt evasion

## usage

```
generate <host> <port> [options]

--lang=go|python|rust|c|csharp|powershell|all
--transport=http|https|websocket
--beacon --interval=N --jitter=N
--dll / --shellcode / --staged / --stego
--os=windows|linux|macos
--env-hostname=TARGET --env-domain=CORP --env-mac=AA:BB:CC
--evasion-all
```

## research and sources

- [Praetorian Ghost Profiles / LLM Signature Reduction](https://www.praetorian.com/blog/llm-edr-signature-reduction)
- [HookChain: IAT Hooking + Indirect Syscalls (arxiv 2404.16856)](https://arxiv.org/abs/2404.16856)
- [Acheron: Indirect Syscalls in Go](https://github.com/f1zm0/acheron)
- [Cobalt Strike 4.11 Sleep Mask / Heap Encryption](https://www.cobaltstrike.com/blog/cobalt-strike-411-shh-beacon-is-sleeping)
- [MDSec Nighthawk Evanesco (CET bypass)](https://www.mdsec.co.uk/2024/11/nighthawk-0-3-3-evanesco/)
- [ShellcodeFluctuation RW/RX page flipping](https://github.com/mgeeky/ShellcodeFluctuation)
- [SilentMoonwalk Call Stack Spoofing](https://github.com/klezVirus/SilentMoonwalk)
- [EvilBytecode Patchless AMSI VEH](https://github.com/EvilBytecode/Ebyte-amsi-patchless-vehhwbp)
- [Binarly ETW Design Issues](https://www.binarly.io/blog/design-issues-of-modern-edrs-bypassing-etw-based-solutions)
- [Praetorian ETW-TI + Hardware Breakpoints](https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/)

## license

for authorized security testing only.
