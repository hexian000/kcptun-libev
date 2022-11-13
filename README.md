# kcptun-libev
A lightweight alternative implementation to kcptun

[Just take me to setup guide](#runtime)

## What's this?

kcptun-libev is a TCP port forwarder which converts the actual transferring protocol into a UDP based one, called [KCP](https://github.com/skywind3000/kcp).
KCP is more configurable and usually has a much better performance in a lossy network. This project can help you to get better bandwidth in such situation.

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

Read more about [KCP](https://github.com/skywind3000/kcp/blob/master/README.en.md)

## Features

- Secure: For proper integration of the cryptography methods.
- Fast: No muxer, one TCP connection to one KCP connection with 0 RTT connection open.
- Proper: KCP will be flushed on demand, no mechanistic lag introduced.
- Simple: Behave as a transport layer forwarder. Do one thing well.
- Morden: Full IPv6 support.
- DDNS aware: Dynamic IP addresses are automatically resolved.
- Configurable: If you want to be unecrypted or plan to use with another encryption implementation (such as udp2raw, wireguard, etc.), encryption can be completely disabled or even excluded from build.
- Portable: Compliant with ISO C standard. Support both GNU/Linux and POSIX APIs.

There is a previous implementation of [kcptun](https://github.com/xtaci/kcptun) which is written in Go.

Compared to that, kcptun-libev should be much more lightweight. The main executable is around 100~200KiB on most platforms\* and it also have a much lower cpu/mem footprint.

*\* Some required libraries are dynamically linked, see runtime dependencies below.*

For your convenience, some statically-linked executables are also provided in the [Releases](https://github.com/hexian000/kcptun-libev/releases) section.

## Security

kcptun-libev can optionally encrypt KCP packets with a password/preshared key. Security and privacy can only be guaranteed if encryption is enabled. It uses the [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) method provided by [libsodium](https://doc.libsodium.org/).

If the encryption is not enabled or not even compiled, no packet overhead is consumed. Therefore, please note that exposing an unencrypted instance on the public networks is considered insecure.

In practice, I strongly suggest user to use "--genpsk" command-line argument to generate a strong random preshared key instead of using a simple password.

| Encryption Method      | Status    | Notes       |
| ---------------------- | --------- | ----------- |
| xchacha20poly1305_ietf | supported | recommended |
| chacha20poly1305_ietf  | supported | since v2.0  |
| aes256gcm              | supported | since v2.0  |

kcptun-libev will not provide known practically vulnerable encryption method in latest release.

## Obfuscator

Obfuscator is a tool to fool eavesdroppers. This feature is only available on Linux.

With obfuscator enabled, kcptun-libev will directly send IP packets over raw sockets. Therefore, Linux capability [CAP_NET_RAW](https://man7.org/linux/man-pages/man7/capabilities.7.html) is required. For example, the following command may works on some Linux distributions:

```sh
# run as root and drop privileges after necessary setup
sudo ./kcptun-libev -u nobody -c server.json
# or grant the capability and run as a normal user
sudo setcap cap_net_raw+ep kcptun-libev
./kcptun-libev -c server.json
```

## Compatibility
### System

Theoretically all systems that support ISO C11 and POSIX.1-2008.

| System       | Level     | Notes |
| ------------ | --------- | ----- |
| Ubuntu       | developed |       |
| OpenWRT      | tested    |       |
| Unix-like    | supported |       |
| Cygwin/MinGW | supported |       |

### Version Compatibility

For security reasons, kcptun-libev does NOT provide compatibility to any other KCP implements.

kcptun-libev uses [semantic versioning](https://semver.org/).

## Build
### Dependencies

| Name      | Kind     | Related Feature       |
| --------- | -------- | --------------------- |
| libev     | required |                       |
| libsodium | optional | Connection encrypting |

```sh
# Debian & Ubuntu
sudo apt install -y libev-dev libsodium-dev
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
sudo apt install -y libev4 libsodium23
# OpenWRT
opkg install libev libsodium
```

### Configurations

#### Generate a random key for encryption:

```sh
./kcptun-libev --genpsk xchacha20poly1305_ietf
```

#### Create a server.json file and fill in the options:

```json
{
    "kcp_bind": "0.0.0.0:12345",
    "connect": "127.0.0.1:1080",
    "method": "xchacha20poly1305_ietf",
    "psk": "// your key here"
}
```

#### Start the server:

```sh
./kcptun-libev -c server.json
```

#### Create a client.json file and fill in the options:

```json
{
    "listen": "127.0.0.1:1080",
    "kcp_connect": "203.0.113.1:12345",
    "method": "xchacha20poly1305_ietf",
    "psk": "// your key here"
}
```

#### Start the client:

```sh
./kcptun-libev -c client.json
```

Now 127.0.0.1:1080 on client is forwarded to server by kcptun-libev.

See [server.json](server.json)/[client.json](client.json) in the source repo for more tunables.

Let's explain some common fields in server.json/client.json:
- The client side "listen" TCP ports and send data to "kcp_connect".
- The server side receive data from "kcp_bind" and forward the connections to "connect".
- Set a "password" or "psk" is strongly suggested when using in public networks.
- "loglevel": 0-6, the default is 4 (INFO)

Some options are same as [KCP](https://github.com/skywind3000/kcp), read their docs for full explaination. Here is some hints:

- "kcp.sndwnd", "kcp.rcvwnd": Must be tuned based on RTT. For enthusiasts, start an idle client with loglevel > 5 and wait 1 minute to read the theoretical bandwidth of current window values. Make it slightly larger than real transfer speed.
- "kcp.nodelay": Enabled mode 1 by default.
- "kcp.interval": Since we have "kcp.flush", you can set this relatively larger than other implements.
- "kcp.resend": Disabled by default.
- "kcp.nc": Enabled by default.

Again, there is some kcptun-libev only options:

- "kcp.flush": 0 - periodic only, 1 - flush after message (default), 2 - also flush acks
- "tcp.\*", "udp.\*": socket options, read your OS manual for further information
- "obfs": obfuscator, disabled by default. currently only one implemented: "dpi/tcp-wnd"
- "user": if running as root, switch to this user to drop privileges

*kcptun-libev works out of the box, thus the default options are also the recommends.*

## Credits

Thanks to:
- [kcp](https://github.com/skywind3000/kcp) (with modifications)
- [libev](http://software.schmorp.de/pkg/libev.html)
- [libsodium](https://github.com/jedisct1/libsodium)
- [json-parser](https://github.com/udp/json-parser)
- [b64.c](https://github.com/jwerle/b64.c)
- [libbloom](https://github.com/jvirkki/libbloom) (with modifications)
- [smhasher](https://github.com/aappleby/smhasher) (for murmurhash3, with modifications)
