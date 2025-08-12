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
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from pprint import pformat
from typing import Callable, Optional

import asyncio
import time

from bcc import BPF
import psutil

from proton.vpn import logging
from proton.vpn.core.settings import SplitTunnelingConfig

from proton.vpn.daemon.split_tunneling.apps.utils import get_removed_config_app_paths_by_uid

logger = logging.getLogger(__name__)

BPF_PROGRAM_PATH = Path(__file__.replace(".py", ".bpf.c"))


class ProcessEvent(Enum):
    "Type of process events."
    EXEC = auto()
    CLONE = auto()
    EXIT = auto()


class PerfBufferEventType(Enum):
    """Type of events sent to the BPF perf buffer"""
    EXEC_ARGUMENT = 0
    EXEC_RETURN = 1
    CLONE = 2
    EXIT = 3


@dataclass
class Process:
    """
    Hold all required process information to do Split Tunneling.
    """
    uid: int
    pid: int
    ppid: int
    exe: str

    # configured ST paths this process matched against
    matched_config_paths: set[str] = field(default_factory=set)

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


def _find_exe_path_matches(
        process: Optional[Process], config_by_uid: dict[int, SplitTunnelingConfig]
) -> set[str]:
    if not process:
        return set()

    if process.uid not in config_by_uid:
        return set()

    matches = set()
    config = config_by_uid[process.uid]
    for app_path in config.app_paths:
        if not app_path:
            continue
        if process.exe.startswith(app_path):
            matches.add(app_path)

    return matches


class ProcessMonitor:
    """Monitors processes based on the specified Split Tunneling configuration."""

    def __init__(
            self,
            bpf: Optional[BPF] = None,
            tracked_procs: Optional[dict[int, Process]] = None
    ):
        self._bpf = bpf
        self._background_task: Optional[asyncio.Task] = None
        self._stop_requested = False
        self._tracked_procs: dict[int, Process] = tracked_procs or {}
        self._argv = defaultdict(list)
        self._config_by_uid: Optional[dict[int, SplitTunnelingConfig]] = None
        self._process_match_callback: Callable[[ProcessEvent, Process], None] = None

    @property
    def config_by_uid(self) -> Optional[dict[int, SplitTunnelingConfig]]:
        """Returns the curret config in use."""
        return self._config_by_uid

    def log_status(self):
        """Logs the process monitor status."""
        logger.info("===============Process monitor status================")
        logger.info("Config: %s", self._config_by_uid)
        logger.info("Tracked procs: %s", pformat(self._tracked_procs))
        logger.info("=====================================================")

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
        old_config_by_uid = self._config_by_uid
        self._config_by_uid = config_by_uid.copy()
        self._process_match_callback = process_match_callback

        if not self._background_task:
            logger.info("Starting process monitor")

            self._track_existing_processes(config_by_uid, process_match_callback)
            self._attach_bpf()

            # start listening for process events via ebpf
            self._background_task = asyncio.create_task(
                self._run_process_monitoring()
            )
            # Ensure exceptions are bubbled up and caught by the exception handler
            self._background_task.add_done_callback(lambda f: f.result())
        else:
            removed_config_app_paths_by_uid = get_removed_config_app_paths_by_uid(
                new_config_by_uid=self._config_by_uid,
                old_config_by_uid=old_config_by_uid
            )
            if removed_config_app_paths_by_uid:
                logger.info("Removed app paths by UID: %s", removed_config_app_paths_by_uid)
                self._update_tracked_processes(removed_config_app_paths_by_uid)

            logger.info("Process monitor already running: config updated")

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
        self._detach_bpf()
        try:
            await self._background_task
        except Exception:  # pylint: disable=broad-except
            logger.exception("Unexpected error while monitoring processes")
        # reset object state
        self.__init__()  # pylint: disable=C2801
        logger.info("Process monitor stopped")

    def _attach_bpf(self):
        if not self._bpf:
            with open(BPF_PROGRAM_PATH, "r", encoding="utf-8") as file:
                bpf_text = file.read()
            self._bpf = BPF(text=bpf_text)

        execve_fnname = self._bpf.get_syscall_fnname("execve")
        self._bpf.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
        self._bpf.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")
        self._bpf.attach_tracepoint(tp="sched:sched_process_fork", fn_name="tracepoint_fork")
        self._bpf.attach_tracepoint(tp="sched:sched_process_exit", fn_name="tracepoint_exit")

    def _detach_bpf(self):
        execve_fnname = self._bpf.get_syscall_fnname("execve")
        self._bpf.detach_kprobe(event=execve_fnname, fn_name="syscall__execve")
        self._bpf.detach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")
        self._bpf.detach_tracepoint(tp="sched:sched_process_fork")
        self._bpf.detach_tracepoint(tp="sched:sched_process_exit")

    async def _run_process_monitoring(self):
        await asyncio.get_running_loop().run_in_executor(
            None, self._run_blocking_process_monitoring
        )

    def _run_blocking_process_monitoring(self):
        self._bpf["events"].open_perf_buffer(self._process_perf_buffer_event)
        while not self._stop_requested:
            self._bpf.perf_buffer_poll(timeout=30)  # timeout in ms

    def _track_existing_processes(self, config_by_uid, process_match_callback):
        start = time.time_ns()

        for proc in psutil.process_iter():
            process = Process.from_psutil(proc)
            if process.pid in self._tracked_procs:
                continue

            matches = _find_exe_path_matches(process, config_by_uid)
            if matches:
                process.matched_config_paths.update(matches)
                self._tracked_procs[process.pid] = process
                process_match_callback(ProcessEvent.EXEC, process)

                for child in proc.children(recursive=True):
                    child = Process.from_psutil(child)
                    child.matched_config_paths.update(matches)
                    self._tracked_procs[child.pid] = child
                    process_match_callback(ProcessEvent.CLONE, child)

        logger.info("Existing processes inspected in %d ms", (time.time_ns() - start) // 1_000_000)

    def _update_tracked_processes(
            self, removed_config_app_paths_by_uid: dict[int, set[str]]
    ):
        """
        Stop tracking processes created by apps that were removed from
        the ST config.
        """
        # check if any of the currently tracked processes matched one of the
        # removed app paths
        start = time.time_ns()
        for process in list(self._tracked_procs.values()):
            removed_config_app_paths = removed_config_app_paths_by_uid.get(process.uid)
            if not removed_config_app_paths:
                continue

            for removed_app_path in removed_config_app_paths:
                if removed_app_path in process.matched_config_paths:
                    # if the process matched the removed app path then invalidate the match.
                    process.matched_config_paths.remove(removed_app_path)

            if not process.matched_config_paths:
                # stop tracking processes that don't match any configured app paths and that
                # are not a child of a parent process that matches configured app paths either
                del self._tracked_procs[process.pid]
                # when working on include mode we'll need to change this event so that the process
                # is not ignored but added to the list of processes that don't match ST config
                self._process_match_callback(ProcessEvent.EXIT, process)

        logger.info("Process matches updated  in %d ms", (time.time_ns() - start) // 1_000_000)

    def _process_perf_buffer_event(self, _cpu, data, _size):
        event = self._bpf["events"].event(data)

        if event.type == PerfBufferEventType.EXEC_ARGUMENT.value:
            self._argv[event.pid].append(event.argv)
        elif event.type == PerfBufferEventType.EXEC_RETURN.value:
            command = b' '.join(self._argv[event.pid]).replace(b'\n', b'\\n').decode('utf-8')
            try:
                del self._argv[event.pid]
            except KeyError:
                pass
            self._process_proc_event(
                ProcessEvent.EXEC,
                Process(event.uid, event.pid, event.ppid, command)
            )
        elif event.type == PerfBufferEventType.CLONE.value:
            command = event.comm.decode('utf-8')
            self._process_proc_event(
                ProcessEvent.CLONE,
                Process(event.uid, event.pid, event.ppid, command)
            )
        elif event.type == PerfBufferEventType.EXIT.value:
            command = event.comm.decode('utf-8')
            self._process_proc_event(
                ProcessEvent.EXIT,
                Process(event.uid, event.pid, event.ppid, command)
            )

    def _process_proc_event(self, event: ProcessEvent, process: Process):
        if event is ProcessEvent.EXEC:
            if process.pid in self._tracked_procs:
                # process that's already being tracked running exec syscall
                return

            matches = _find_exe_path_matches(process, self._config_by_uid)
            if matches:
                process.matched_config_paths.update(matches)
                self._tracked_procs[process.pid] = process
                self._process_match_callback(ProcessEvent.EXEC, process)
        elif event is ProcessEvent.CLONE:
            if process.ppid in self._tracked_procs:
                # if the parent pid is already tracked then the child is too
                parent = self._tracked_procs[process.ppid]
                process.matched_config_paths.update(parent.matched_config_paths)
                self._tracked_procs[process.pid] = process
                self._process_match_callback(ProcessEvent.CLONE, process)
        elif event is ProcessEvent.EXIT:
            if process.pid in self._tracked_procs:
                process = self._tracked_procs[process.pid]
                self._process_match_callback(ProcessEvent.EXIT, process)
                del self._tracked_procs[process.pid]


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
