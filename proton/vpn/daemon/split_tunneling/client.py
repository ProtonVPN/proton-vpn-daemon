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

from dbus_fast.aio import MessageBus
from dbus_fast import BusType
import dbus_fast

from proton.vpn.daemon.split_tunneling import dbus_translator as translator
from proton.vpn.daemon.split_tunneling.config import SplitTunnelingConfig
from proton.vpn.daemon import exceptions


class SplitTunnelingService:
    """Split tunneling service that abstracts from necessary initializations.

    Use this class to talk to our backend daemon.
    """

    def __init__(self, interface):
        self._interface = interface

    @staticmethod
    async def init() -> SplitTunnelingService:
        """Initializes the daemon.

        Returns:
            SplitTunnelingService: new instance of the daemon
        """
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        introspection = await bus.introspect("me.proton.VPN", "/me/proton/VPN")
        obj = bus.get_proxy_object(
            "me.proton.VPN", "/me/proton/VPN", introspection
        )
        return SplitTunnelingService(
            interface=obj.get_interface("me.proton.VPN")
        )

    async def set_config(self, config: SplitTunnelingConfig, uid: int) -> None:
        """Sets a new config. Sends data to the daemon.

        Args:
            config (SplitTunnelingConfig): the object containing the data
            uid (int): uid that the config has to be applied for
        """
        dbus_dict = translator.to_dbus_dict(config)
        try:
            await self._interface.call_set_config(dbus_dict, uid)
        except dbus_fast.errors.DBusError as excp:
            raise exceptions.SplitTunnelingError(
                f"Error setting new split tunneling configuration for {uid}"
            ) from excp

    async def get_config(self, uid: int) -> SplitTunnelingConfig:
        """Get config that is related to the specified uid.

        Args:
            uid (int): uid to get the data for

        Returns:
            SplitTunnelingConfig: data stored for the specified uid
        """
        try:
            dbus_dict = await self._interface.call_get_config(uid)
        except dbus_fast.errors.DBusError as excp:
            raise exceptions.SplitTunnelingError(
                f"Error getting split tunneling configuration for {uid}"
            ) from excp

        return translator.from_dbus_dict(dbus_dict)

    async def clear_config(self, uid: int) -> None:
        """Clears data stored for the specified uid.

        Args:
            uid (int): uid that data is to be cleared for
        """
        try:
            await self._interface.call_clear_config(uid)
        except dbus_fast.errors.DBusError as excp:
            raise exceptions.SplitTunnelingError(
                f"Error clearing split tunneling config for {uid}"
            ) from excp
