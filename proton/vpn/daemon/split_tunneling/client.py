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
from typing import Optional, Union
import asyncio
import sys

from dbus_fast.aio import MessageBus
from dbus_fast import BusType
import dbus_fast

from proton.vpn.daemon.split_tunneling import dbus_translator as translator
from proton.vpn.core.settings import SplitTunnelingConfig
from proton.vpn.split_tunneling import exceptions
from proton.vpn.split_tunneling import SplitTunneling

is_python_3_11_or_higher = sys.version_info >= (3, 11)


async def _backwards_compatible_asyncio_timeout(timeout: int, func, *args):
    """
    Helper function to maintain compatibility across Python versions.

    Python 3.11 introduced `asyncio.timeout`, which is a context manager that
    can be used to set a timeout for an asynchronous operation. In earlier
    versions of Python, we used `asyncio.wait_for` to achieve similar functionality.
    """
    if is_python_3_11_or_higher:
        async with asyncio.timeout(timeout):
            await func(*args)
    else:
        await asyncio.wait_for(
            func(*args), timeout=timeout
        )


class SplitTunnelingDbusClient(SplitTunneling):
    """Split tunneling service that abstracts from necessary initializations.

    Use this class to talk to our backend daemon.
    """

    DEFAULT_TIMEOUT: int = 5

    def __init__(self, uid: int, interface: str, timeout: int = DEFAULT_TIMEOUT):
        super().__init__(uid)
        self._interface = interface
        self._timeout = timeout

    @staticmethod
    async def build(uid: int) -> SplitTunnelingDbusClient:
        """Initializes the daemon.

        Returns:
            SplitTunnelingDbusClient: new instance of the daemon
        """
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        try:
            introspection = await bus.introspect(
                "me.proton.vpn.split_tunneling", "/me/proton/vpn/split_tunneling"
            )
        except dbus_fast.errors.DBusError as excp:
            raise exceptions.SplitTunnelingError(
                "Unable to start introspection"
            ) from excp
        obj = bus.get_proxy_object(
            "me.proton.vpn.split_tunneling", "/me/proton/vpn/split_tunneling", introspection
        )
        return SplitTunnelingDbusClient(
            uid=uid, interface=obj.get_interface("me.proton.vpn.split_tunneling")
        )

    async def set_config(self, config: SplitTunnelingConfig) -> None:
        """Sets a new config for instance uid.

        Raises:
            exceptions.SplitTunnelingError: whenever there is a dbus exception

        Args:
            config (SplitTunnelingConfig): the object containing the data
        """
        dbus_dict = translator.to_dbus_dict(config)
        try:
            await _backwards_compatible_asyncio_timeout(
                self._timeout,
                self._interface.call_set_config,
                self._uid, dbus_dict
            )
        except TimeoutError as exc:
            raise exceptions.SplitTunnelingError(
                "Timeout setting split tunnelint configuration"
            ) from exc
        except dbus_fast.errors.DBusError as excp:
            raise exceptions.SplitTunnelingError(
                "Error setting new split tunneling "
                f"configuration for {self._uid}"
            ) from excp
        except Exception as exc:
            raise exceptions.SplitTunnelingError(
                "Unexpected error"
            ) from exc

    async def get_config(self) -> Optional[SplitTunnelingConfig]:
        """Returns config for instance uid.

        Raises:
            exceptions.SplitTunnelingError: whenever there is a dbus exception

        Returns:
            SplitTunnelingConfig: data stored for the specified uid
        """
        try:
            dbus_dict = await self._interface.call_get_config(self._uid)
        except dbus_fast.errors.DBusError as excp:
            raise exceptions.SplitTunnelingError(
                f"Error getting split tunneling configuration for {self._uid}"
            ) from excp
        except Exception as exc:
            raise exceptions.SplitTunnelingError(
                "Unexpected error"
            ) from exc

        if not dbus_dict:
            return None

        return translator.from_dbus_dict(dbus_dict)

    async def clear_config(self) -> None:
        """Clears config stored for instance uid.

        Raises:
            exceptions.SplitTunnelingError: whenever there is a dbus exception
        """
        try:
            await _backwards_compatible_asyncio_timeout(
                self._timeout,
                self._interface.call_clear_config,
                self._uid
            )
        except TimeoutError as exc:
            raise exceptions.SplitTunnelingError(
                "Timeout clearing split tunnelint configuration"
            ) from exc
        except dbus_fast.errors.DBusError as excp:
            raise exceptions.SplitTunnelingError(
                f"Error clearing split tunneling config for {self._uid}"
            ) from excp
        except Exception as exc:
            raise exceptions.SplitTunnelingError(
                "Unexpected error"
            ) from exc

    async def get_all_configs(
            self
    ) -> Union[
        list[tuple[int, SplitTunnelingConfig]],
        list
    ]:
        """Returns a list of all configs.

        Raises:
            exceptions.SplitTunnelingError: whenever there is a dbus exception

        Returns:
            list[Optional[tuple[int, SplitTunnelingConfig]]]: \
                all stored configs
        """
        try:
            all_configs = await self._interface.call_get_all_configs()
        except dbus_fast.errors.DBusError as excp:
            raise exceptions.SplitTunnelingError(
                "Error getting all configs"
            ) from excp

        list_of_parsed_configs = []
        for uid, config in all_configs:
            list_of_parsed_configs.append(
                (uid, translator.from_dbus_dict(config))
            )

        return list_of_parsed_configs

    @classmethod
    def _get_priority(cls) -> int:
        """
        Priority of the split tunneling implementation.

        To be implemented by subclasses.
        """
        return 1

    @classmethod
    def _validate(cls) -> bool:
        """
        Determines whether the split tunneling connection
        implementation is valid or not.
        """
        import subprocess  # noqa: E501 # pylint: disable=import-outside-toplevel # nosec B404 # nosemgrep: gitlab.bandit.B404

        try:
            subprocess.check_output(  # nosec B603
                [
                    "/usr/bin/systemctl",
                    "is-active",
                    "--quiet",
                    "me.proton.vpn.split_tunneling"
                ],
                stderr=subprocess.STDOUT
            )
        except subprocess.CalledProcessError:
            return False

        return True
