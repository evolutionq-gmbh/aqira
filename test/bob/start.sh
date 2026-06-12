#!/bin/sh
set -eux

wg-quick up /conf/wg0.conf

nc -dkl -s 10.1.0.2 -p 3000
