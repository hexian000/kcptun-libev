# kcptun-libev

[![MIT License](https://img.shields.io/github/license/hexian000/kcptun-libev)](https://github.com/hexian000/kcptun-libev/blob/master/LICENSE)
[![Build](https://github.com/hexian000/kcptun-libev/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/kcptun-libev/actions/workflows/build.yml)
[![Downloads](https://img.shields.io/github/downloads/hexian000/kcptun-libev/total.svg)](https://github.com/hexian000/kcptun-libev/releases)
[![Release](https://img.shields.io/github/release/hexian000/kcptun-libev.svg?style=flat)](https://github.com/hexian000/kcptun-libev/releases)

A powerful and extremely lightweight encrypted port forwarder based on reliable UDP protocol.

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
  - [Build on Unix-like systems](#build-on-unix-like-systems)
- [Runtime](#runtime)
  - [Dependencies](#dependencies-1)
  - [Configurations](#configurations)
    - [Basic Usage](#basic-usage)
    - [Rendezvous Mode](#rendezvous-mode)
- [Tunables](#tunables)
- [Observability](#observability)
- [Credits](#credits)

## Introduction

kcptun-libev is a TCP port forwarder which converts the actual transferring protocol into a UDP based one, called [KCP](https://github.com/skywind3000/kcp).
KCP is more configurable and usually has a much better performance in a lossy but not really congested network. This project can help you to get better bandwidth in such situation.

For example, wrap your server to use KCP instead of TCP:
```
client -> kcptun-libev client ->
    lossy network (carried by KCP)
-> kcptun-libev server -> server
```

Or typically, the people who using a lossy network may setup kcptun-libev with a proxy server. To get the internet access speeded up.
```
network access -> proxy client -> kcptun-libev client ->
    lossy network (carried by KCP)
-> kcptun-libev server -> proxy server -> stable network
```

Reliable UDP can also help users connect to TCP services behind NAT, see [rendezvous mode](#rendezvous-mode).
```
client -> NAT1 -> rendezvous server
server -> NAT2 -> rendezvous server

client -> NAT1 -> NAT2 -> server
```

Since KCP retransmits packets more aggressively. It is recommended to enable proper QoS at the NIC level when running on a public network.

Read more about [KCP](https://github.com/skywind3000/kcp/blob/master/README.en.md)

## Features

- Secure: For proper integration with the cryptography methods.
- Responsive: No muxer, one TCP connection to one KCP connection with 0 RTT connection open.
- Proper: KCP will be flushed on demand, no mechanistic lag introduced.
- Simple: Do one thing well. kcptun-libev only acts as a layer 4 forwarder.
- Morden: Full IPv6 support.
- DDNS aware: Dynamic IP addresses can be automatically resolved.
- NAT traversal: Server behind certain types of NAT can be connected directly with the help of a well-known rendezvous server.
- Configurable: If you plan to use with another encryption implementation (such as udp2raw, wireguard, etc.), encryption can be completely disabled or even excluded from build.
- Portable: Compliant with ISO C standard. Support both GNU/Linux and POSIX APIs.

There is a previous implementation of [kcptun](https://github.com/xtaci/kcptun) which is written in Go.

Compared to that, kcptun-libev should be much more lightweight. The main executable is around 100~200KiB on most platforms\* and it also have a much lower cpu/mem footprint.

*\* Some required libraries are dynamically linked, see runtime dependencies below. Statically linked executable can be larger due to these libraries.*

For your convenience, some statically-linked executables are also provided in the [Releases](https://github.com/hexian000/kcptun-libev/releases) section.

## Security

### Encryption

kcptun-libev can encrypt packets with a password or preshared key. Security and privacy can only be guaranteed if encryption is enabled. We use the [authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) methods provided by [libsodium](https://github.com/jedisct1/libsodium).

In config file:

```json
"method": "// name here"
```

If the encryption is not enabled or not even compiled, no packet overhead is consumed. However, no authentication tag is added to protect the server from well-crafted packets by an attacker. In this case, security relies on third-party libraries. We recommend that users only disable encryption when unexpected packets cannot be received. For example: the traffic is already protected by Wireguard etc.

In practice, we suggest user to use `--genpsk` command-line argument to generate a strong random preshared key instead of using a simple password.

| Encryption Method      | Since | Form | Packet Overhead | Notes              |
| ---------------------- | ----- | ---- | --------------- | ------------------ |
| xchacha20poly1305_ietf | v1.0  | AEAD | 40 bytes        | recommended        |
| xsalsa20poly1305       | v2.2  | AE   | 40 bytes        |                    |
| chacha20poly1305_ietf  | v2.0  | AEAD | 28 bytes        |                    |
| aes256gcm              | v2.0  | AEAD | 28 bytes        | limited hardware\* |

*\* Specifically: x86 CPU with SSSE3, aesni and pclmul.*

kcptun-libev ships with additional encryption methods to ensure that users have alternatives for specific reasons. Although the strength of each method is discussed, in most cases the recommended one just works.

### Obfuscation

The obfuscator is an optional tool to fool eavesdroppers. This feature is only available on Linux.

In config file:

```json
"obfs": "// name here"
```

With obfuscator enabled, kcptun-libev will directly send IP packets over raw sockets. Therefore, Linux capability [CAP_NET_RAW](https://man7.org/linux/man-pages/man7/capabilities.7.html) is required. For example, the following command may works on some Linux distributions:

```sh
# run as root and drop privileges after necessary setup
sudo ./kcptun-libev -u nobody -c server.json
# or grant the capability and run as a normal user
sudo setcap cap_net_raw+ep kcptun-libev
./kcptun-libev -c server.json
```

Currently only one obfuscator implemented: `dpi/tcp-wnd`

## Compatibility
### System

Theoretically all systems that support ISO C11 and POSIX.1-2008.

| System                | Tier      | Notes              |
| --------------------- | --------- | ------------------ |
| Ubuntu                | developed |                    |
| OpenWRT               | tested    |                    |
| Other Linux / Android | supported |                    |
| macOS                 | supported | without obfuscator |
| Windows (MSYS2)       | supported | without obfuscator |

### Version Compatibility

For security reasons, kcptun-libev does NOT provide compatibility to any other KCP implementations.

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
# Debian & Ubuntu
sudo apt install libev-dev libsodium-dev
# Alpine Linux
apk add libev-dev libsodium-dev
```

### Build on Unix-like systems

```sh
git clone https://github.com/hexian000/kcptun-libev.git
mkdir "kcptun-libev-build"
cmake -DCMAKE_BUILD_TYPE="Release" \
    -S "kcptun-libev" \
    -B "kcptun-libev-build"
cmake --build "kcptun-libev-build" --parallel
```

See [m.sh](m.sh) for more information about cross compiling support.

## Runtime
### Dependencies

If you downloaded a *-static build in the [Releases](https://github.com/hexian000/kcptun-libev/releases) section, you don't have to install the dependencies below.

```sh
# Debian & Ubuntu
sudo apt install libev4 libsodium23
# Alpine Linux
apk add libev libsodium
# OpenWRT
opkg install libev libsodium
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

Now 127.0.0.1:1080 on client is forwarded to server by kcptun-libev.

See [server.json](server.json)/[client.json](client.json) in the source repo for more tunables.

Let's explain some common fields in server.json/client.json:
- The client side "listen" TCP ports and send data to "kcp_connect".
- The server side receive data from "kcp_bind" and forward the connections to "connect".
- Set a "password" or "psk" is strongly suggested when using in public networks.
- "loglevel": 0-7 are Silence, Fatal, Error, Warning, Notice, Info, Debug, Verbose respectively. The default is 4 (Notice). High log levels can affect performance.

#### Rendezvous Mode

Rendezvous mode may be useful for accessing servers behind NAT. The rendezvous server only helps establish the connection, the traffic goes directly between client and server.

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
    "method": "xchacha20poly1305_ietf",
    "psk": "// your key here"
}
```

`client.json`: The client may be behind one or more levels of NAT, which may or may not be the same ones as the server.

```json
{
    "listen": "127.0.0.1:25565",
    "rendezvous_server": "203.0.113.1:12345",
    "method": "xchacha20poly1305_ietf",
    "psk": "// your key here"
}
```

rendezvous_server : server : client = 1 : 1 : n

Peers should be all IPv4 or all IPv6.

## Tunables

*kcptun-libev works out of the box. In most cases, the default options are recommended.*

Some tunables are the same as [KCP](https://github.com/skywind3000/kcp), read their docs for full explaination. Here are some hints:

- "kcp.sndwnd", "kcp.rcvwnd":
  1. Should be tuned according to RTT.
  2. For enthusiasts, you can start an idle client with loglevel >= 5 and wait 1 minute to check the theoretical bandwidth of current window values.
  3. On systems with very little memory, you may need to reduce it to save memory.
- "kcp.nodelay": Enabled by default. Note that this is not an equivalent to `TCP_NODELAY`.
- "kcp.interval":
  1. Since we run KCP differently, the recommended value is longer than the previous implementation. This will save some CPU power.
  2. This option is not intended for [traffic shaping](https://en.wikipedia.org/wiki/Traffic_shaping). For Linux, check out [sqm-scripts](https://github.com/tohojo/sqm-scripts) for it. Read more about [CAKE](https://man7.org/linux/man-pages/man8/CAKE.8.html).
- "kcp.resend": Disabled by default.
- "kcp.nc": Enabled by default.
- "kcp.mtu": Specifies the final IP packet size, including all overhead.

Again, there is some kcptun-libev specific options:

- "kcp.flush": 0 - periodic only, 1 - flush after sending, 2 - also flush acks (for benchmarking)
- "tcp.sndbuf", "tcp.rcvbuf", "udp.sndbuf", "udp.rcvbuf": Socket options, see your OS manual for further information.
  1. Normally, default value just works.
  2. Usually setting the udp buffers relatively large (e.g. 1048576) gives performance benefits. But since kcptun-libev handles packets efficiently, a receive buffer that is too large doesn't make sense.
  3. All buffers should not be too small, otherwise you may experience performance degradation.
- "user": switch to this user to drop privileges, e.g. `"user": "nobody:"` means the user named "nobody" and that user's login group

## Observability

There is a builtin HTTP server for monitoring service status.

Add this line to your config file:

```json
"http_listen": "127.0.1.1:8081"
```

Then run the commands below from shell:

```sh
watch curl -sX POST http://127.0.1.1:8081/stats
```

The URI "/healthy" always responds with HTTP 200, feel free to use it for healthy checks.

## Credits

Thanks to:
- [kcp](https://github.com/skywind3000/kcp) (with modifications)
- [libev](http://software.schmorp.de/pkg/libev.html)
- [libsodium](https://github.com/jedisct1/libsodium)
- [cJSON](https://github.com/DaveGamble/cJSON)
- [libbloom](https://github.com/jvirkki/libbloom) (with modifications)
- [cityhash](https://github.com/google/cityhash) (with modifications)
