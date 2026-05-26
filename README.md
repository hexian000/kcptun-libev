# kcptun-libev

[![MIT License](https://img.shields.io/github/license/hexian000/kcptun-libev)](https://github.com/hexian000/kcptun-libev/blob/master/LICENSE)
[![Build](https://github.com/hexian000/kcptun-libev/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/kcptun-libev/actions/workflows/build.yml)
[![Downloads](https://img.shields.io/github/downloads/hexian000/kcptun-libev/total.svg)](https://github.com/hexian000/kcptun-libev/releases)
[![Release](https://img.shields.io/github/release/hexian000/kcptun-libev.svg?style=flat)](https://github.com/hexian000/kcptun-libev/releases)

A powerful, extremely lightweight, encrypted port forwarder with NAT traversal support, built on a reliable UDP transport.

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
    - [Rendezvous Mode (NAT Traversal)](#rendezvous-mode-nat-traversal)
    - [Basic Usage](#basic-usage)
- [Tunables](#tunables)
- [Observability](#observability)
- [Credits](#credits)

## Introduction

kcptun-libev is a TCP port forwarder built on [KCP](https://github.com/skywind3000/kcp), a reliable UDP‑based transport protocol.

**NAT traversal** is the primary use case: kcptun-libev can connect a TCP service behind NAT to clients anywhere on the internet, without port forwarding or a VPN. A small, publicly reachable rendezvous server bootstraps the connection; all subsequent traffic flows directly between peers.

```
client -> NAT1 -> rendezvous server
server -> NAT2 -> rendezvous server

              (after hole-punching)
client -> NAT1 -> NAT2 -> server
```

Example: play LAN multiplayer games with friends over the internet. The game host runs kcptun-libev server behind their home NAT; each friend runs kcptun-libev client. After hole-punching via the rendezvous server, everyone connects to the host's game port as if on a local network — no router configuration needed on either side.

It also works as a plain KCP transport accelerator for services on networks with packet loss or congestion:

```
client -> kcptun-libev client ->
    lossy network (carried by KCP)
-> kcptun-libev server -> server
```

Because KCP retransmits packets aggressively, we recommend enabling proper QoS at the NIC level when running on public networks.

Read more about [KCP](https://github.com/skywind3000/kcp/blob/master/README.en.md)

## Features

- NAT traversal: Servers behind certain types of NAT can connect directly to clients via a well‑known rendezvous server, with no port forwarding required.
- Secure: Proper integration with modern authenticated encryption.
- Responsive: No multiplexer; one TCP connection maps to one KCP connection with 0‑RTT opening.
- Precise: KCP flushes on demand; no artificial latency introduced.
- Simple: Does one thing well — acts as a Layer 4 forwarder.
- Modern: Full IPv6 support.
- Dynamic DNS aware: Dynamic IP addresses can be resolved automatically.
- Configurable: When used with other encryption (e.g., udp2raw, WireGuard), built‑in encryption can be disabled or omitted at build time.
- Portable: Compliant with ISO C; supports both GNU/Linux and POSIX APIs.
- Long-Term Supported: Follow the latest releases of the dependent projects. Even if we don't make any changes, the binary release will be rebuilt at least once a year.

kcptun-libev is extremely lightweight. The main executable is 100~200 KiB on most platforms\*, with low CPU usage and memory footprint.

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

| Name      | Version   | Required | Feature    |
| --------- | --------- | -------- | ---------- |
| libev     | >= 4.31   | yes      |            |
| libsodium | >= 1.0.18 | no       | encryption |

```sh
# Debian / Ubuntu
sudo apt install libev-dev libsodium-dev
# Alpine Linux
apk add libev-dev libsodium-dev
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

**Dynamically-linked setup**: The following dependencies should be installed.

```sh
# Debian / Ubuntu
sudo apt install libev4 libsodium23
# Alpine Linux
apk add libev libsodium
# OpenWRT
opkg install libev libsodium
```

### Configurations

Common fields in `server.json`/`client.json`:
- Client: `listen` defines the local TCP address; traffic is sent to `kcp_connect`.
- Server: receives on `kcp_bind` and forwards connections to `connect`.
- Setting `password` or `psk` is strongly recommended on public networks.
- `loglevel`: 0–8 map to Silence, Fatal, Error, Warning, Notice, Info, Debug, Verbose, VeryVerbose. The default is 4 (Notice). Higher levels can affect performance.

First, generate a random key for encryption:

```sh
./kcptun-libev --genpsk xchacha20poly1305_ietf
```

#### Rendezvous Mode (NAT Traversal)

Rendezvous mode lets a server behind NAT accept connections from clients, without any port forwarding. The rendezvous server only bootstraps the connection; all subsequent traffic flows directly between client and server.

Rendezvous mode requires UDP at the transport layer; it is incompatible with non‑UDP obfuscators.

*The method is non-standard and may not work with all NAT implementations.*

`rendezvous_server.json`: Deploy the rendezvous server at a publicly reachable address accessible by both client and server.

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

Scaling: rendezvous_server : server : client = 1 : m : m×n

All peers must use the same address family (all IPv4 or all IPv6).

#### Basic Usage

For direct connectivity where both peers have reachable addresses, use the standard forwarding mode.

Create a `server.json` file:

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

Create a `client.json` file:

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
- [libev](http://software.schmorp.de/pkg/libev.html)
- [libsodium](https://github.com/jedisct1/libsodium)
- [libbloom](https://github.com/jvirkki/libbloom) (with modifications)
- [cityhash](https://github.com/google/cityhash) (with modifications)
