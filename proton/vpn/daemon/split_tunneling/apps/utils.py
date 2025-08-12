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
from typing import Optional

from proton.vpn.core.settings import SplitTunnelingConfig


def get_removed_config_app_paths_by_uid(
    new_config_by_uid: dict[int, SplitTunnelingConfig],
    old_config_by_uid: Optional[dict[int, SplitTunnelingConfig]]
) -> dict[int, set[str]]:
    """Returns the app paths that were removed in the new config, comparing it to the old config."""
    if not old_config_by_uid:
        return {}

    removed_config_app_paths_by_uid = {}
    for uid, old_config in old_config_by_uid.items():
        new_config = new_config_by_uid.get(uid)
        removed_config_app_paths = _get_removed_config_app_paths(old_config, new_config)
        if removed_config_app_paths:
            removed_config_app_paths_by_uid[uid] = removed_config_app_paths

    return removed_config_app_paths_by_uid


def _get_removed_config_app_paths(
    old_config: SplitTunnelingConfig,
    new_config: Optional[SplitTunnelingConfig]
) -> set[str]:
    """
    Returns a set with the configured app paths that were removed
    """
    if old_config.mode != new_config.mode:
        raise RuntimeError("ST mode switch not implemented yet.")

    new_config_app_paths = set(new_config.app_paths) if new_config else set()

    removed_paths = set(old_config.app_paths) - new_config_app_paths
    return removed_paths
