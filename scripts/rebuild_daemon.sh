#!/usr/bin/env bash

set -e

source /etc/os-release
if ! [[ $ID == "debian" || $ID_LIKE == "debian" ]]
then
    echo "This script only works on debian[-based] systems"
    exit 1
fi


./scripts/create_changelogs.py
sudo apt remove -y proton-vpn-daemon
sudo mk-build-deps -ir --tool "apt-get -y"
dpkg-buildpackage -b --no-sign
pkg_version=$(dpkg-parsechangelog --show-field Version)
sudo dpkg -i "../proton-vpn-daemon_${pkg_version}_all.deb"
journalctl -u me.proton.vpn.split_tunneling.service -f
