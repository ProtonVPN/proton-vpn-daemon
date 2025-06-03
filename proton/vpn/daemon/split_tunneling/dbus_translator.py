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
from typing import Dict
from dbus_fast import Variant
from proton.vpn.core.settings import SplitTunnelingConfig, SplitTunnelingMode


def to_dbus_dict(data: SplitTunnelingConfig) -> Dict[str, object]:
    """Convert object to dbus compatible dict.

    When passing through dbus, we can't pass a python object
    thus we need to convert it to a dbus friendly dict.

    Returns:
        dict: keys are strings and values are `Variant`
    """
    return {
        "mode": Variant("s", data.mode.value),
        "app_paths": Variant("as", data.app_paths),
        "ip_ranges": Variant("as", data.ip_ranges),
    }


def from_dbus_dict(data: Dict[str, object]) -> SplitTunnelingConfig:
    """Generates `Config` from dbus dict.

    Args:
        data: keys are strings and values are `Variant`

    Returns:
        SplitTunnelingConfig: new config object
    """
    return SplitTunnelingConfig(
        mode=SplitTunnelingMode(data["mode"].value),
        app_paths=data["app_paths"].value,
        ip_ranges=data["ip_ranges"].value
    )
