# kcptun-libev

[![MIT License](https://img.shields.io/github/license/hexian000/kcptun-libev)](https://github.com/hexian000/kcptun-libev/blob/master/LICENSE)
[![Build](https://github.com/hexian000/kcptun-libev/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/kcptun-libev/actions/workflows/build.yml)
[![Downloads](https://img.shields.io/github/downloads/hexian000/kcptun-libev/total.svg)](https://github.com/hexian000/kcptun-libev/releases)
[![Release](https://img.shields.io/github/release/hexian000/kcptun-libev.svg?style=flat)](https://github.com/hexian000/kcptun-libev/releases)

A powerful, extremely lightweight, encrypted port forwarder built on a reliable UDP transport.

Status: **Stable**

[User Wiki](https://github.com/hexian000/kcptun-libev/wiki)

- [Introduction](#introduction)
- [Features](#features)
- [Security](#security)
  - [Encryption](#encryption)
  - [Obfuscation](#obfuscation)
- [Compatibility](#compatibility)
  - [System](#system)
  - [Version Compatibility](#version-compatibility)
- [Build](#build)
  - [Dependencies](#dependencies)
  - [Build on Unix-like Systems](#build-on-unix-like-systems)
- [Runtime](#runtime)
  - [Dependencies](#dependencies-1)
  - [Configurations](#configurations)
    - [Basic Usage](#basic-usage)
    - [Rendezvous Mode](#rendezvous-mode)
- [Tunables](#tunables)
- [Observability](#observability)
- [Credits](#credits)

## Introduction

kcptun-libev is a TCP port forwarder that converts the transport to a UDP‑based protocol called [KCP](https://github.com/skywind3000/kcp).
KCP is more configurable and typically performs much better on lossy, lightly congested networks. This project can help you achieve higher throughput in such situations.

Example: wrap your service to use KCP instead of TCP:
```
client -> kcptun-libev client ->
    lossy network (carried by KCP)
-> kcptun-libev server -> server
```

A common setup is to pair kcptun-libev with a proxy to speed up Internet access over lossy links:
```
network access -> proxy client -> kcptun-libev client ->
    lossy network (carried by KCP)
-> kcptun-libev server -> proxy server -> stable network
```

Reliable UDP can also help connect to TCP services behind NAT; see [Rendezvous Mode](#rendezvous-mode).
```
client -> NAT1 -> rendezvous server
server -> NAT2 -> rendezvous server

client -> NAT1 -> NAT2 -> server
```

Because KCP retransmits packets aggressively, we recommend enabling proper QoS at the NIC level when running on public networks.

Read more about [KCP](https://github.com/skywind3000/kcp/blob/master/README.en.md)

## Features

- Secure: Proper integration with modern authenticated encryption.
- Responsive: No multiplexer; one TCP connection maps to one KCP connection with 0‑RTT opening.
- Precise: KCP flushes on demand; no artificial latency introduced.
- Simple: Does one thing well — acts as a Layer 4 forwarder.
- Modern: Full IPv6 support.
- Dynamic DNS aware: Dynamic IP addresses can be resolved automatically.
- NAT traversal: Servers behind certain types of NAT can connect directly via a well‑known rendezvous server.
- Configurable: When used with other encryption (e.g., udp2raw, WireGuard), built‑in encryption can be disabled or omitted at build time.
- Portable: Compliant with ISO C; supports both GNU/Linux and POSIX APIs.
- Long-Term Supported: Follow the latest releases of the dependent projects. Even if we don't make any changes, the binary release will be rebuilt at least once a year.

There is a previous implementation of [kcptun](https://github.com/xtaci/kcptun) which is written in Go.

Compared to it, kcptun-libev is much more lightweight. The main executable is 100~200 KiB on most platforms\* and it also has much lower CPU usage and memory footprint.

*\* Some required libraries are dynamically linked; see runtime dependencies below. Statically linked executables can be larger due to these libraries.*

For your convenience, some statically-linked executables are also provided in the [Releases](https://github.com/hexian000/kcptun-libev/releases) section.

## Security

### Encryption

kcptun-libev can encrypt packets with a password or pre-shared key. Security and privacy can only be guaranteed if encryption is enabled. We use the [authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) methods provided by [libsodium](https://github.com/jedisct1/libsodium).

In config file:

```json
"method": "// name here"
```

If encryption is disabled or not compiled in, there is no packet overhead. However, no authentication tag is added to protect the server from crafted packets. In this case, security relies on third‑party components. We recommend disabling encryption only when unsolicited packets cannot reach the service, or when the traffic is already protected (e.g., WireGuard).

In practice, we suggest using the `--genpsk` command‑line argument to generate a strong random pre‑shared key instead of a simple password.

| Encryption Method      | Since | Form | Packet Overhead | Notes                        |
| ---------------------- | ----- | ---- | --------------- | ---------------------------- |
| xchacha20poly1305_ietf | v1.0  | AEAD | 40 bytes        | recommended                  |
| xsalsa20poly1305       | v2.2  | AE   | 40 bytes        |                              |
| chacha20poly1305_ietf  | v2.0  | AEAD | 28 bytes        |                              |
| aes256gcm              | v2.0  | AEAD | 28 bytes        | requires specific hardware\* |

*\* Specifically: x86 CPU with SSSE3, AES‑NI, and PCLMUL.*

kcptun-libev ships with additional encryption methods to ensure that users have alternatives for specific reasons. Although the strength of each method is discussed, in most cases the recommended one just works.

### Obfuscation

Obfuscation is optional and helps evade inspection. This feature is available on Linux only.

In config file:

```json
"obfs": "// name here"
```

Currently one obfuscator is implemented: `dpi/tcp-wnd`. It behaves like a HTTP service and cannot be probed without the pre‑shared key.

With obfuscation enabled, kcptun-libev sends IP packets over raw sockets. Therefore, Linux capability [CAP_NET_RAW](https://man7.org/linux/man-pages/man7/capabilities.7.html) is required. For example, the following commands may work on some Linux distributions:

```sh
# run as root and drop privileges after necessary setup
sudo ./kcptun-libev -u nobody:nogroup -c server.json
# or grant the capability and run as a normal user
sudo setcap cap_net_raw+ep kcptun-libev
./kcptun-libev -c server.json
```

## Compatibility
### System

All systems that support ISO C11 and POSIX.1‑2008.

| System                | Tier      | Notes              |
| --------------------- | --------- | ------------------ |
| Ubuntu                | developed |                    |
| OpenWrt               | tested    |                    |
| Other Linux / Android | supported |                    |
| macOS                 | supported | without obfuscator |
| Windows (MSYS2)       | supported | without obfuscator |

### Version Compatibility

For security reasons, kcptun-libev does NOT provide compatibility with any other KCP implementation.

We use [semantic versioning](https://semver.org/).

Given a version number `MAJOR.MINOR.PATCH`:

- As long as `MAJOR` remains unchanged, the versions should speak a compatible protocol.

- As long as `MAJOR.MINOR` remains unchanged, later versions should be compatible with working configuration files from previous versions.

## Build
### Dependencies

| Name      | Version   | Required | Feature     |
| --------- | --------- | -------- | ----------- |
| json-c    | >= 0.15   | yes      | config file |
| libev     | >= 4.31   | yes      |             |
| libsodium | >= 1.0.18 | no       | encryption  |

```sh
# Debian / Ubuntu
sudo apt install libjson-c-dev libev-dev libsodium-dev
# Alpine Linux
apk add json-c-dev libev-dev libsodium-dev
```

### Build on Unix-like Systems

```sh
git clone https://github.com/hexian000/kcptun-libev.git
mkdir -p kcptun-libev-build && cd kcptun-libev-build
cmake -DCMAKE_BUILD_TYPE="Release" \
    ../kcptun-libev
cmake --build . --parallel
```

See [m.sh](m.sh) for cross‑compiling support.

## Runtime
### Dependencies

**Statically-linked setup**: Download a `-static` build from the [Releases](https://github.com/hexian000/kcptun-libev/releases) section — no additional runtime dependencies are needed.

**Dynamically-linked setup**: 

```sh
# Debian / Ubuntu
sudo apt install libjson-c5 libev4 libsodium23
# Alpine Linux
apk add json-c libev libsodium
# OpenWRT
opkg install libjson-c5 libev libsodium
```

### Configurations
#### Basic Usage

Generate a random key for encryption:

```sh
./kcptun-libev --genpsk xchacha20poly1305_ietf
```

Create a `server.json` file and fill in the options:

```json
{
    "kcp_bind": "0.0.0.0:12345",
    "connect": "127.0.0.1:1080",
    "method": "xchacha20poly1305_ietf",
    "psk": "// your key here"
}
```

Start the server:

```sh
./kcptun-libev -c server.json
```

Create a `client.json` file and fill in the options:

```json
{
    "listen": "127.0.0.1:1080",
    "kcp_connect": "203.0.113.1:12345",
    "method": "xchacha20poly1305_ietf",
    "psk": "// your key here"
}
```

Start the client:

```sh
./kcptun-libev -c client.json
```

127.0.0.1:1080 on the client is now forwarded to the server via kcptun-libev.

See [server.json](server.json) and [client.json](client.json) in the repository for more tunables.

Common fields in `server.json`/`client.json`:
- Client: `listen` defines the local TCP address; traffic is sent to `kcp_connect`.
- Server: receives on `kcp_bind` and forwards connections to `connect`.
- Setting `password` or `psk` is strongly recommended on public networks.
- `loglevel`: 0–7 map to Silence, Fatal, Error, Warning, Notice, Info, Debug, Verbose. The default is 4 (Notice). Higher levels can affect performance.

#### Rendezvous Mode

Rendezvous mode helps access servers behind NAT. The rendezvous server only bootstraps the connection; traffic flows directly between client and server.

Rendezvous mode requires UDP at the transport layer; it is incompatible with non‑UDP obfuscators.

*The method is non-standard and may not work with all NAT implementations.*

`rendezvous_server.json`: The rendezvous server should have an address which is reachable by both client and server.

```json
{
    "kcp_bind": "0.0.0.0:12345",
    "method": "xchacha20poly1305_ietf",
    "psk": "// your key here"
}
```

`server.json`: The server may be behind one or more levels of NAT.

```json
{
    "connect": "127.0.0.1:25565",
    "rendezvous_server": "203.0.113.1:12345",
    "service_id": "myservice",
    "method": "xchacha20poly1305_ietf",
    "psk": "// your key here"
}
```

`client.json`: The client may be behind one or more levels of NAT, which may or may not be the same ones as the server.

```json
{
    "listen": "127.0.0.1:25565",
    "rendezvous_server": "203.0.113.1:12345",
    "service_id": "myservice",
    "method": "xchacha20poly1305_ietf",
    "psk": "// your key here"
}
```

rendezvous_server : server : client = 1 : m : m*n

All peers must be either all IPv4 or all IPv6.

## Tunables

*kcptun-libev works out of the box. In most cases, the default options are recommended.*

Some tunables are the same as [KCP](https://github.com/skywind3000/kcp); read their docs for a full explanation. Hints:

- `kcp.sndwnd`, `kcp.rcvwnd`:
  1. Tune according to RTT.
  2. To estimate theoretical bandwidth, start an idle client with `loglevel >= 5` and wait ~1 minute.
  3. On memory‑constrained systems, reduce these values to save memory.
- `kcp.nodelay`: Enabled by default. Note: not equivalent to `TCP_NODELAY`.
- `kcp.interval`:
  1. Because KCP runs differently here, the recommended value is higher than in previous implementations and saves CPU.
  2. Not intended for [traffic shaping](https://en.wikipedia.org/wiki/Traffic_shaping). On Linux, see [sqm-scripts](https://github.com/tohojo/sqm-scripts) and [CAKE](https://man7.org/linux/man-pages/man8/CAKE.8.html).
- `kcp.resend`: Disabled by default.
- `kcp.nc`: Enabled by default.
- `kcp.mtu`: Specifies the final IP packet size, including all overhead.

kcptun-libev–specific options:

- `kcp.flush`: 0 = periodic only; 1 = flush after sending; 2 = also flush ACKs (for benchmarking).
- `tcp.sndbuf`, `tcp.rcvbuf`, `udp.sndbuf`, `udp.rcvbuf`: Socket buffer sizes; see your OS manual.
  1. Defaults usually work.
  2. Larger UDP buffers (e.g., 1048576) can help; however, overly large receive buffers may be counterproductive here.
  3. Avoid too‑small buffers to prevent performance degradation.
- `user`: switch to this user to drop privileges, e.g., `"user": "nobody:"` means the user named "nobody" and that user's login group

## Observability

There is a built‑in HTTP server for monitoring service status.

Add this line to your config file:

```json
"http_listen": "127.0.1.1:8081"
```

Then run the commands below from shell:

```sh
watch curl -sX POST http://127.0.1.1:8081/stats
```

The URI "/healthy" always responds with HTTP 200; use it for health checks.

## Credits

Thanks to:
- [kcp](https://github.com/skywind3000/kcp) (with modifications)
- [json-c](https://github.com/json-c/json-c)
- [libev](http://software.schmorp.de/pkg/libev.html)
- [libsodium](https://github.com/jedisct1/libsodium)
- [libbloom](https://github.com/jvirkki/libbloom) (with modifications)
- [cityhash](https://github.com/google/cityhash) (with modifications)
