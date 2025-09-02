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

from dataclasses import dataclass, field
import time

import psutil

from proton.vpn.core.settings import SplitTunnelingConfig, SplitTunnelingMode
from proton.vpn import logging

logger = logging.getLogger(__name__)


@dataclass
class Process:
    """
    Holds all required process information to do Split Tunneling.
    """
    uid: int
    pid: int
    ppid: int
    exe: str

    # configured ST paths this process matched against
    matched_config_paths: set[str] = field(default_factory=set)

    # whether the process is still running or it already exited
    running: bool = True

    @staticmethod
    def from_psutil(process: psutil.Process):
        """
        Builds a Process instance from a psutil.Process instance.
        """
        uid = process.uids().real
        ppid = process.ppid()
        exe = ""
        try:
            exe = process.exe()
        except (psutil.AccessDenied, psutil.ZombieProcess) as error:
            # Even when running as root, some processes raise this
            logger.warning("Error getting process path: %s: %s", type(error).__name__, error)

        return Process(
            pid=process.pid, uid=uid, ppid=ppid, exe=exe
        )


class ProcessMatcher:
    """Matches processes against ST configuration."""

    VPN_APP_BIN = "protonvpn-app"

    @classmethod
    def check_process(
            cls, process: Process, config_by_uid: dict[int, SplitTunnelingConfig]
    ) -> set[str]:
        """
        Given a process and the ST config, it returns a set with all the app paths in the
        ST config the process matched against.
        :param process: process to check for matches
        :param config_by_uid: ST config indexed by user ID (unix UID).
        :returns: the app path matches.
        """
        if process.uid not in config_by_uid:
            return set()

        # In include mode, the Proton VPN app should always be included in the VPN
        # so that it can establish the local agent connection to the VPN server.
        config = config_by_uid[process.uid]
        if config.mode == SplitTunnelingMode.INCLUDE and cls.VPN_APP_BIN in process.exe:
            return set([cls.VPN_APP_BIN])

        matches = set()
        for app_path in config.app_paths:
            if not app_path:
                continue
            if process.exe.startswith(app_path):
                matches.add(app_path)

        return matches

    @classmethod
    def check_all_processes(cls, config_by_uid) -> dict[int, Process]:
        """
        Returns a dict with all currently running processes indexed by ID. Each process
        contains the configured ST app paths it matched against.

        Note: processes started by users for which there is not ST config are ignored.
        """
        start = time.time_ns()
        tracked_procs = {}

        for psutil_process in psutil.process_iter():
            process = tracked_procs.get(psutil_process.pid) or Process.from_psutil(psutil_process)
            if process.uid not in config_by_uid:
                # only processes created by users that added ST config are checked
                continue

            if process.matched_config_paths:
                # already tracked child of a process matching config paths.
                continue

            matched_config_paths = cls.check_process(process, config_by_uid)
            process.matched_config_paths.update(matched_config_paths)
            tracked_procs[process.pid] = process

            if process.matched_config_paths:
                # if the process matched any config paths, then we also flag all its
                # descendant processes with the same config path matches
                for descendant in psutil_process.children(recursive=True):
                    descendant = tracked_procs.get(descendant.pid) \
                        or Process.from_psutil(descendant)
                    descendant.matched_config_paths.update(matched_config_paths)
                    tracked_procs[descendant.pid] = descendant

        logger.info("Existing processes inspected in %d ms", (time.time_ns() - start) // 1_000_000)

        return tracked_procs
