QKD Hardened WireGuard
======================

Introduction
------------

This package provides an utility that injects PSKs into an active WireGuard
tunnel. This is a proof of concept that incorporates symmetric QKD key data into
a tunnel to enable QKD hardening.

A connection with a KMS is established to read QKD key data in a streaming
fashion. At a fixed (but configurable) interval, this key data is inserted into
the WireGuard tunnel as a PSK. The KMS ensures the QKD stream remains
synchronized, allowing this utility to operate in an entirely standalone
fashion, however it is recommended to enable stream synchronization.

Usage
-----

An existing WireGuard tunnel is assumed to be set up. It is important that this
tunnel initially is configured with a _private_ PSK that is not shared with the
peer, to ensure no non-QKD-hardened encryption is set up, as otherwise the
initial data transferred via the tunnel may be subject to quantum attacks.

An example invocation looks like:

```shell
aqira --host localhost --port 5000 --interface wg0 --peer_key="31ZNbQz4cz3W8YBgAwePW4CVqQRiq+ArfAQ3tIlamyg=" --sync_port=51821 --peer_port=51821
```

The `host` and `port` values specify the network address at which the KMS is
reachable. The `interface` is the name of the WireGuard tunnel, and the
`peer_key` the peer to configure the PSK for.

Optionally, the `--interval` option can be used to specify an additional
interval by which to retrieve PSK keys. This interval is rounded up to the
nearest WireGuard handshake interval, and enables a PSK to be used for more than
one handshake.

The `sync_port` and `peer_port` are the respectively the port to listen on for
synchronization messages and the port to send them to. An optional
`peer_address` specifies the address at which the peer is reachable. If this
address is not specified, the endpoint configured for the WireGuard interface is
used. The optional `sync_address` specified the address to bind the listening
socket on. If the `sync_port` or `peer_port` argument is not provided, no
synchronization is performed. This enables stand-alone mode.

TLS can be enabled by specifying the `--ca` argument with a path to the CA root
store. To enable client authentication, also specify `--certificate` and `--key`
with the paths to the certificate and private key files respectively.

Note that the program must be run as root, or with CAP_NET_ADMIN privileges.

Operation
---------

When starting, a key stream is opened, using a key stream identifier derived
from the public keys of the local and peer interfaces. The first key of this
stream is then retrieved to be used to authenticate synchronization messages,
ensuring the local instance and the peer access the same key stream.

When subsequent keys are retrieved from the key stream, their position is sent
using an authenticated message to the peer instance of Aqira. The same message
is then awaited on, which ensures both the local instance and the peer have
obtained the same key.

The first PSK is set immediately after synchronization. Afterwards, the system
enters a loop:

First, the following WireGuard handshake is awaited. WireGuard triggers a new
handshake every 120 seconds, which will use the last set PSK. This event is used
to synchronize both ends of the tunnel. If an additional interval is set, the
program delays until it has passed. The next PSK is then retrieved from the KMS
and inserted into the tunnel. The loop then restarts.

### Synchronization Protocol

A synchronization protocol is used to protect against significant between the
local instance receiving a QKD key, and the peer doing so. Synchronizing on the
key position ensures that both sides are at the same position.

Synchronization is based on simple messages transmitted over UDP. Each message
contains a payload, a simple 4-byte integer indicating a stream position
followed by a one byte Boolean for retransmitted messages, and a MAC over the
payload, derived from a PSK. This PSK is simply the first key of the key stream
shared between both peers.

When a new key is retrieved from the key stream, the position of that key is
sent to the peer. Next, a message from the peer with the same position is
awaited on.

If no message is received from the peer, the previous message is retransmitted.
When receiving a retransmitted message, the previous message is sent in reply.
This enables recovery from dropped messages.

Note that desynchronization may still occur if messages are blocked in a single
direction.

Testing
-------

The `test` directory contains Dockerfiles and a Docker compose configuration
that creates a local network that runs aqira. To start the test, run, from the
`test` directory,

```shell
docker-compose up
```

This will start services for "Alice" and "Bob". The `qkd_` containers run a QKD
test server. The `aqira_` containers run Aqira. Finally, the `alice` and `bob`
containers simply pipe data over the wireguard interfaces.

To observe if the WireGuard interface is working correctly, run a command such
as

```shell
docker-compose exec alice wg
docker-compose exec bob wg
```

which should output that data is being transferred (with most data being
transferred from alice to bob), and a PSK is set.

The aqira status can be observed using

```shell
docker-compose logs aqira_alice aqira_bob
```
