# kcptun-libev
A lightweight alternative implementation to kcptun

## What's this?
kcptun-libev is a TCP port forwarder which converts the actual transferring protocol into a UDP based one, called [KCP](https://github.com/skywind3000/kcp).
KCP is more configurable and usually has a much better performance in a lossy network. This project can help you to get better bandwidth in such situation.

For example, wrap your server to use KCP instead of TCP:
```
client -> kcptun-libev client -> lossy network(KCP) -> kcptun-libev server -> server
```

Or typically, the people who using a lossy network may setup kcptun-libev with a proxy server. To get the internet access speeded up.
```
network access -> proxy client -> kcptun-libev client -> lossy network(KCP) -> kcptun-libev server -> proxy server -> stable network
```

Read more about [KCP](https://github.com/skywind3000/kcp/blob/master/README.en.md)

## Features

- Secure: For proper integration of the cryptography methods.
- Fast: No muxer, one TCP connection to one KCP connection with 0 RTT connection open.
- Proper: KCP will be updated on demand, no mechanistic lag introduced.
- Simple: Without FEC craps.
- Morden: Full IPv6 support.
- DDNS aware: Dynamic IP addresses are supported.
- Configurable: If you want to be unecrypted or plan to use with another encryption implementation (such as udp2raw, wireguard, etc.), encryption can be completely disabled or even excluded from build.
- Compatible: Compliant with ISO C standard. Support both GNU/Linux and POSIX APIs.

There is a previous implementation of [kcptun](https://github.com/xtaci/kcptun) which is written in Go.

Compared to that, kcptun-libev should be much more lightweight. The main executable is around 100KiB on most platforms\* and it also have a much lower cpu/mem usage.

*\* Some required libraries are dynamically linked, see runtime dependencies below.*

## Security

kcptun-libev can optionally encrypt KCP packets with a password/preshared key. With encryption enabled, the integrity and privacy is guaranteed. It uses the [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) method provided by libsodium.

If the encryption is not enabled or not even compiled, no packet overhead is consumed.

In practice, I strongly suggest user to use "--genpsk" command-line argument to generate a strong random preshared key instead of using a simple password.

| Encryption Method      | Status    | Notes      |
| ---------------------- | --------- | ---------- |
| chacha20poly1305_ietf  | supported | since v2.0 |
| xchacha20poly1305_ietf | supported |            |
| aes256gcm              | supported | since v2.0 |

## Compatibility
### System

Theoretically all systems that support ISO C11.

| System       | Level     | Notes |
| ------------ | --------- | ----- |
| Ubuntu       | developed |       |
| OpenWRT      | tested    |       |
| Unix-like    | supported |       |
| Cygwin/MinGW | supported |       |

### Protocol

kcptun-libev do NOT provide compatibility to any other KCP implements.

The major version number is the protocol version. Different protocol versions are not compatible.

Note: Protocol Compatibility Guarantee does not apply to pre-release versions.

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

### Build on UNIX-like systems

```sh
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE="Release" ..
make -j$(nproc --all)
```

See [m.sh](m.sh) for more information about cross compiling support.

## Runtime
### Dependencies

```sh
# Debian & Ubuntu
sudo apt install -y libev4 libsodium23
# OpenWRT
opkg install libev libsodium
```

### Usage

Create a config file and pass the file name. Just like:

```
./kcptun-libev -c server.json
```

See [server.json](server.json)/[client.json](client.json)/[peer.json](peer.json) in the source repo for your reference.

Let's explain some fields in server.json/peer.json:
- The client side "listen" TCP ports and send data to "udp_connect".
- The server side receive data from "udp_bind" and forward the connections to "connect".
- Set a password or PSK is strongly suggested when using in public networks.
- Log level: 0-6, the default is 2 (INFO)

## Credits

Thanks to:
- [kcp](https://github.com/skywind3000/kcp) (with modifications)
- [libev](http://software.schmorp.de/pkg/libev.html)
- [libsodium](https://github.com/jedisct1/libsodium)
- [json-parser](https://github.com/udp/json-parser)
- [b64.c](https://github.com/jwerle/b64.c)
- [libbloom](https://github.com/jvirkki/libbloom) (with modifications)
- [smhasher](https://github.com/aappleby/smhasher) (for murmurhash3, with modifications)
