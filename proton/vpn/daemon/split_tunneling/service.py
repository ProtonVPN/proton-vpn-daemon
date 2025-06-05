#!/usr/bin/env python3
"""All the assets the app uses are available in this module.


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
import logging

from dbus_fast.aio import MessageBus
from dbus_fast.service import ServiceInterface, method
from dbus_fast import BusType

from proton.vpn.daemon.split_tunneling.config import SplitTunnelingConfig
from proton.vpn.daemon.split_tunneling import dbus_translator as translator

log = logger = logging.getLogger(__name__)


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
        super().__init__("me.proton.VPN")
        self._user_configs = []

    @method(name="SetConfig")
    async def set_config(self, config: "a{sv}", uid: "q"):  # noqa: F722,F821
        """Set split tunneling config

        The reason that the `Variant` datatype is used as value for the dict,
        is because the `SplitTunnelingConfig` dict contains two types of data,
        for `mode` is a string and for `app_paths` and `ip_ranges` are
        an array of strings, so `Variant` allows us to pass different
        datatypes for the value.

        To pass values to this method, the structure should look like this:
        ```
            {
                "mode": Variant('s', "standard"),
                "app_paths": Variant('as', ['path1', 'path2']),
                "ip_ranges": Variant('as', ['192.168.1.1'])
            },
            1000
        ```
        If you're testing via D-Feet,
        prefix variants with `GLib.`, ie: `GLib.Variant`

        Args:
            SplitTunnelingConfig: A dict object that
            follows the dbus format as follows:
                `a`: means it's an array
                `{}`: when prefixed `a` it transforms into a dict
                `s`: key is a string
                `v`: value is a `Variant`
            uid: `q` is a uint16
        """
        # pylint: disable=logging-fstring-interpolation
        log.debug(f"set_config: config:{config} - uid:{uid}")
        self._user_configs.append(
            UserConfig(
                uid=uid,
                config=translator.from_dbus_dict(config)
            )
        )

    @method(name="GetConfig")
    async def get_config(self, uid: "q") -> "a{sv}":  # noqa: F722,F821
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
        # pylint: disable=logging-fstring-interpolation
        for user_config in self._user_configs:
            if user_config.uid == uid:
                log.debug(f"get_config: Found config for uid:{uid}")
                return translator.to_dbus_dict(user_config.config)

        log.debug(f"get_config: No config found for uid:{uid}")
        return translator.to_dbus_dict(SplitTunnelingConfig("none", [], []))

    @method(name="ClearConfig")
    async def clear_config(self, uid: "q"):  # noqa: F821
        """Clears the config for specified uid.

        Args:
            uid (uint16): uid of the user
        """
        # pylint: disable=logging-fstring-interpolation
        original_len = (self._user_configs)
        self._user_configs = [
            user_config
            for user_config in self._user_configs
            if user_config.uid != uid
        ]
        new_len = (self._user_configs)
        msg = f"deleted config for uid:{uid}" \
            if original_len != new_len else f"no config found for uid:{uid}"
        log.debug(f"clear_config: {msg}")


async def init_split_tunneling_daemon():
    """Main method that configures the bus.
    """
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    _ = await bus.request_name('me.proton.VPN')
    bus.export('/me/proton/VPN', SplitTunnelingDbus())
