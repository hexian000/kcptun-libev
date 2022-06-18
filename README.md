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

kcptun-libev can optionally encrypt your traffic with a password/preshared key. With encryption enabled, the integrity and privacy of your traffic is guaranteed. It uses the libsodium implementation of chacha20poly1305-ietf, which is an [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) method.

Read more about the [KCP](https://github.com/skywind3000/kcp/blob/master/README.en.md)

## Why another kcptun?
The previous implementation [kcptun](https://github.com/xtaci/kcptun) is written in Go.
Compared to that, kcptun-libev should be:
- More lightweight and run faster, main executable < 100KiB on most platforms
- More secure: For proper use of the cryptography library.
- Simpler: No muxer, one TCP connection to one KCP connection
- Without FEC craps

kcptun-libev is **NOT** production ready yet.

## Build
### Dependencies
libev: required
libsodium: optional, if you want to encrypt the connection.

```sh
# Debian & Ubuntu
sudo apt install -y libev-dev libsodium-dev
```

### To build on UNIX-like systems
```sh
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE="Release" ..
make -j$(nproc --all)
```

## Usage
Create a config file and pass the file name. Just like:
```
./kcptun-libev -c server.json
```
See [server.json](server.json)/[client.json](client.json) in the source repo for more details.

Let's explain some fields in server.json/client.json:
- The client side "listen" TCP ports and send data to "udp_connect".
- The server side receive data from "udp_bind" and forward the connections to "connect".
- Set a password is strongly suggested when using in public networks.
- log level: 0-6

## Credits
kcptun-libev is made by glue the following projects together. Thanks to:
- [kcp](https://github.com/skywind3000/kcp)
- [libev](http://software.schmorp.de/pkg/libev.html)
- [libsodium](https://github.com/jedisct1/libsodium)
- [json-parser](https://github.com/udp/json-parser)
