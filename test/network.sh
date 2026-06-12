#!/bin/sh
set -eux

. .venv/bin/activate

ip link set up dev lo

ip link add dev wg0 type wireguard
ip link add dev wg1 type wireguard

ip addr add 10.1.0.1/24 dev wg0
ip addr add 10.1.0.2/24 dev wg1

wg setconf wg0 test/alice/wg0.conf
wg setconf wg1 test/bob/wg1.conf

ip link set up dev wg0
ip link set up dev wg1

aqira 