#!/usr/bin/env python3
"""
Copyright (c) 2025 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton VPN is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
from __future__ import annotations

from dataclasses import dataclass

from dbus_fast.aio import MessageBus
from dbus_fast.service import ServiceInterface, method
from dbus_fast import BusType

from proton.vpn import logging
from proton.vpn.core.settings import SplitTunnelingConfig
from proton.vpn.daemon.split_tunneling import dbus_translator as translator
from proton.vpn.daemon.split_tunneling.split_tunneling import SplitTunnelingService

logger = logging.getLogger(__name__)


@dataclass
class UserConfig:
    """Associates `SplitTunnelingConfig` object to uid
    """
    uid: int
    config: SplitTunnelingConfig


class SplitTunnelingDbus(ServiceInterface):
    """Split tunneling dbus interface.

    This class defines the interface that is accessible via dbus.

    Args:
        ServiceInterface (str): The name of the dbus service.
    """

    def __init__(self):
        super().__init__("me.proton.vpn.split_tunneling")
        self._service = SplitTunnelingService()

    @method(name="SetConfig")
    async def set_config(self, uid: "q", config: "a{sv}"):  # type: ignore # noqa: F722,F821
        """Set split tunneling config

        The reason that the `Variant` datatype is used as value for the dict,
        is because the `SplitTunnelingConfig` dict contains two types of data,
        for `mode` is a string and for `app_paths` and `ip_ranges` are
        an array of strings, so `Variant` allows us to pass different
        datatypes for the value.

        To pass values to this method, the structure should look like this:
        ```
            1000,
            {
                "mode": Variant('s', "exclude"),
                "app_paths": Variant('as', ['/snap/firefox']),
                "ip_ranges": Variant('as', ['192.168.1.1'])
            }
        ```
        If you're testing via D-Feet,
        prefix variants with `GLib.`, ie:
        ```
            1000,
            {
                "mode": GLib.Variant('s', "exclude"),
                "app_paths": GLib.Variant('as', ['/snap/firefox']),
                "ip_ranges": GLib.Variant('as', ['192.168.1.1'])
            }
        ```

        Args:
            SplitTunnelingConfig: A dict object that
            follows the dbus format as follows:
                `a`: means it's an array
                `{}`: when prefixed `a` it transforms into a dict
                `s`: key is a string
                `v`: value is a `Variant`
            uid: `q` is a uint16
        """
        config: SplitTunnelingConfig = translator.from_dbus_dict(config)
        await self._service.set_config(uid, config)

    @method(name="GetConfig")
    async def get_config(self, uid: "q") -> "a{sv}":  # type: ignore # noqa: F722,F821
        """Returns configuration for specified uid.

        Since we can not return different types of data, we return
        an array with empty data in case no matching value is found.

        Returns:
            a{sv}: An array containing the information
                `a`: means it's an array
                `{}`: when prefixed `a` it transforms into a dict
                `s`: key is a string
                `v`: value is a `Variant`

            It can also return an array with empty values.
        """
        config = self._service.get_config(uid)
        return translator.to_dbus_dict(config) if config else {}

    @method(name="ClearConfig")
    async def clear_config(self, uid: "q"):  # noqa: F821
        """Clears the config for specified uid.

        Args:
            uid (uint16): uid of the user
        """
        await self._service.clear_config(uid)

    @method(name="LogStatus")
    def log_status(self):
        """Logs the service status."""
        self._service.log_status()

    @method(name="GetAllConfigs")
    async def get_all_configs(self) -> "a(qa{sv})":  # type: ignore # noqa: F722
        """Returns all stored configs

        Returns:
            list[dict[str, Variant]]: all stored configs
        """
        return [
            (uid, translator.to_dbus_dict(config))
            for uid, config in self._service.get_all_configs()
        ]


async def init_split_tunneling_daemon():
    """Main method that configures the bus.
    """
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    _ = await bus.request_name('me.proton.vpn.split_tunneling')
    bus.export('/me/proton/vpn/split_tunneling', SplitTunnelingDbus())
