QKD Hardened WireGuard
======================

Introduction
------------

This package provides an utility that injects PSKs into an active WireGuard
tunnel. This is a proof of concept that incorporates symmetric QKD key data into
a tunnel to enable QKD hardening.

A connection with a KMS is established to read QKD key data in a streaming
fashion. At a fixed (but configurable) interval, this key data is inserted into
the WIreGuard tunnel as a PSK. The KMS ensures the QKD stream remains
synchronized, allowing this utility to operate in an entirely standalone
fashion.

Usage
-----

An existing WireGuard tunnel is assumed to be set up. It is important that this
tunnel initially is configured with a _private_ PSK that is not shared with the
peer, to ensure no non-QKD-hardened encryption is set up, as otherwise the
initial data transferred via the tunnel may be subject to quantum attacks.

An example invocation looks like:

```shell
aqira --host localhost --port 5000 --interface wg0 --peer_key="31ZNbQz4cz3W8YBgAwePW4CVqQRiq+ArfAQ3tIlamyg="
```

The host and port values specify the network address at which the KMS is
reachable. The interface is the name of the WireGuard tunnel, and the peer_key
the peer to configure the PSK for.

Optionally, the `--interval` option can be used to specify an additional
interval by which to retrieve PSK keys.

Note that the program must be run as root, or with CAP_NET_ADMIN privileges.

Operation
---------

Aqira immediately sets the PSK to the first key retrieved from the QKD stream.
After that, it will continue in a loop:

First, the following WireGuard handshake is awaited. WireGuard triggers a new
handshake every 120 seconds, which will use the last set PSK. This event is used
to synchronize both ends of the tunnel. If an additional interval is set, the
program delays until it has passed. The next PSK is then retrieved from the KMS
and inserted into the tunnel. The loop then restarts.

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
