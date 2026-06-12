#!/bin/sh
set -eux

wg-quick up /conf/wg0.conf

pv -L 1024 -q </dev/zero | nc -s 10.1.0.1 10.1.0.2 3000
