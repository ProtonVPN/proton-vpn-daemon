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
from typing import List, Dict
from dataclasses import dataclass, asdict


@dataclass
class SplitTunnelingConfig:
    """Config that is used for split tunneling
    """
    mode: str
    app_paths: List[str]
    ip_ranges: List[str]

    @staticmethod
    def from_dict(data: dict) -> SplitTunnelingConfig:
        """Generates `SplitTunnelingConfig` from regular python dict.

        Args:
            data (dict): the dict containing the necessary information

        Returns:
            SplitTunnelingConfig: new `SplitTunnelingConfig`
        """
        return SplitTunnelingConfig(
            mode=data["mode"],
            app_paths=data["app_paths"],
            ip_ranges=data["ip_ranges"]
        )

    def to_dict(self) -> Dict[str, object]:
        """Converts actual object to dict.

        Returns:
            dict: current object in dict
        """
        return asdict(self)
