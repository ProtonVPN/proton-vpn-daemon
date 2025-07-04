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

from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Optional
from importlib.metadata import version

import asyncio
import errno
import logging
import time

from packaging.version import Version
import psutil

from proton.vpn.core.settings import SplitTunnelingConfig

logger = logging.getLogger(__name__)

if Version(version("pyroute2")) < Version("0.7.11"):
    # pyroute2 does not include connector netlink portocol in older versions.
    from .pyroute2.netlink.connector import cn_proc
    logger.warning("Using pyroute2 fallback")
else:
    from pyroute2.netlink.connector import cn_proc  # pylint: disable=E0401,E0611


class ProcessEvent(Enum):
    "Type of process events."
    EXEC = auto()
    FORK = auto()
    EXIT = auto()


@dataclass
class Process:
    """
    Hold all required process information to do Split Tunneling.
    """
    uid: int
    pid: int
    ppid: int
    exe: str

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


def _get_process(pid: int) -> Optional[Process]:
    try:
        return Process.from_psutil(psutil.Process(pid))
    except psutil.NoSuchProcess:
        return None


def _process_match(
        process: Optional[Process], config_by_uid: dict[int, SplitTunnelingConfig]
) -> bool:
    if not process:
        return False

    if process.uid not in config_by_uid:
        return False

    config = config_by_uid[process.uid]
    if not any(
        config_path and process.exe.startswith(config_path)
        for config_path in config.app_paths
    ):
        return False

    return True


class ProcessMonitor:
    """Monitors processes based on the specified Split Tunnelingconfiguration."""

    def __init__(self):
        self._socket: Optional[cn_proc.ProcEventSocket] = None
        self._background_task: Optional[asyncio.Task] = None
        self._stop_requested = False
        self._tracked_procs: dict[int, psutil.Process] = {}

    def start(
            self, config_by_uid: dict[int, SplitTunnelingConfig],
            process_match_callback: Callable[[ProcessEvent, Process], None]
    ) -> asyncio.Task:
        """
        Starts a background task to monitor processes.
        @param config_by_uid: map of split tunneling configuration by uid (unix user id)
        @param process_match_callback: callback called whenever there is a process match.

        Note that this method returns straight away, it doesn't wait that
        the background task is running.
        """
        if self._background_task:
            raise RuntimeError("Process monitoring background task already running")

        logger.info("Starting process monitor")
        self._background_task = asyncio.create_task(
            self._run_async(config_by_uid, process_match_callback)
        )
        return self._background_task

    async def stop(self):
        """
        Triggers a shutdown request to the background task monitoring processes,
        and waits for it to finish.
        """
        if not self._background_task:
            logger.info("Process monitor is already stopped.")
            return

        logger.info("Stopping process monitor")
        self._stop_requested = True
        if self._socket:
            self._socket.close()
        await self._background_task
        # reset object state
        self.__init__()  # pylint: disable=C2801
        logger.info("Process monitor stopped")

    async def restart(
            self, config_by_uid: dict[int, SplitTunnelingConfig],
            process_match_callback: Callable[[ProcessEvent, Process], None]
    ):
        """Stops and starts the process monitoring background task again."""
        await self.stop()
        self.start(config_by_uid, process_match_callback)

    async def _run_async(
            self, config_by_uid: dict[int, SplitTunnelingConfig],
            process_match_callback: Callable[[ProcessEvent, Process], None]
    ):
        await asyncio.get_running_loop()\
            .run_in_executor(None, self._run_sync, config_by_uid, process_match_callback)

    def _run_sync(
            self, config_by_uid: dict[int, SplitTunnelingConfig],
            process_match_callback: Callable[[ProcessEvent, Process], None]

    ):
        self._resolve_symlinks(config_by_uid)

        self._track_existing_processes(config_by_uid, process_match_callback)

        # start listening for process events via the connector netlink protocol
        self._socket = cn_proc.ProcEventSocket()
        self._socket.bind()
        self._socket.control(listen=True)
        while True:
            try:
                events = self._socket.get()
            except OSError as error:
                if self._stop_requested and error.errno == errno.EBADF:
                    # socket closed after shutdown request
                    break
                raise

            for event in events:
                self._process_proc_event(event, config_by_uid, process_match_callback)

    def _resolve_symlinks(self, config_by_uid):
        for config in config_by_uid.values():
            config.app_paths = [str(Path(path).resolve()) for path in config.app_paths]

        logger.info("Settings after resolving symlinks %s", config_by_uid)

    def _track_existing_processes(self, config_by_uid, process_match_callback):
        start = time.time_ns()

        for proc in psutil.process_iter():
            process = Process.from_psutil(proc)
            if process.pid in self._tracked_procs:
                continue

            if _process_match(process, config_by_uid):
                self._tracked_procs[process.pid] = process
                process_match_callback(ProcessEvent.EXEC, process)

                for child in proc.children(recursive=True):
                    child = Process.from_psutil(child)
                    self._tracked_procs[child.pid] = child
                    process_match_callback(ProcessEvent.FORK, child)

        logger.info("Existing processes inspected in %d ms", (time.time_ns() - start) // 1_000_000)

    def _process_proc_event(self, event, config_by_uid, process_match_callback):
        if isinstance(event, cn_proc.proc_event_exec):
            pid = event["process_pid"]
            if pid in self._tracked_procs:
                # forked process that's already being tracked
                return

            process = _get_process(pid)
            if _process_match(process, config_by_uid):
                self._tracked_procs[pid] = process
                process_match_callback(ProcessEvent.EXEC, process)
        elif isinstance(event, cn_proc.proc_event_fork):
            parent_pid = event["parent_pid"]
            if parent_pid in self._tracked_procs:
                # if the parent pid is already tracked then the child is too
                pid = event["child_pid"]
                process = _get_process(pid)
                if not process:
                    # the process already exited.
                    return

                self._tracked_procs[pid] = process
                process_match_callback(ProcessEvent.FORK, process)
        elif isinstance(event, cn_proc.proc_event_exit):
            pid = event["process_pid"]
            if pid in self._tracked_procs:
                process = self._tracked_procs[pid]
                process_match_callback(ProcessEvent.EXIT, process)
                del self._tracked_procs[pid]


def build_process_monitor_cli_parser(name: str):
    """Builds the process monitor CLI arg parser"""
    import argparse  # pylint: disable=C0415

    parser = argparse.ArgumentParser(
        prog=name,
        description="For testing purposes only"
    )
    parser.add_argument(
        "-p", "--path", required=True, action="append",
        help="Process paths to exclude."
    )
    parser.add_argument("--uid", required=False, type=int, help="UID to exclude process for.")

    return parser


async def main():
    """Test script"""
    import os  # pylint: disable=C0415

    root_logger = logging.getLogger()
    root_logger.addHandler(logging.StreamHandler())

    parser = build_process_monitor_cli_parser(
        name="Process monitor for app-based Split Tunneling"
    )
    args = parser.parse_args()

    process_monitor = ProcessMonitor()
    uid = args.uid or os.getuid()
    try:
        await process_monitor.start(
            config_by_uid={
                uid: SplitTunnelingConfig(app_paths=args.path)
            },
            process_match_callback=lambda event, process: logger.info(
                "event: %s, process: %s", event, process
            )
        )
    except asyncio.CancelledError:
        pass
    finally:
        try:
            await process_monitor.stop()
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    asyncio.run(main())
