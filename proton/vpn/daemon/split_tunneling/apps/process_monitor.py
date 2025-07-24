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
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Optional

import asyncio
import time

from bcc import BPF
import psutil

from proton.vpn import logging
from proton.vpn.core.settings import SplitTunnelingConfig

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
        self._bpf: Optional[BPF] = None
        self._background_task: Optional[asyncio.Task] = None
        self._stop_requested = False
        self._tracked_procs: dict[int, psutil.Process] = {}
        self._argv = defaultdict(list)
        self._config_by_uid: Optional[dict[int, SplitTunnelingConfig]] = None
        self._process_match_callback: Callable[[ProcessEvent, Process], None] = None

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
        self._config_by_uid = config_by_uid
        # FIXME: think about what we do with symlinks  # pylint: disable=fixme
        # self._resolve_symlinks(self._config_by_uid)
        self._process_match_callback = process_match_callback
        self._track_existing_processes(config_by_uid, process_match_callback)
        self._attach_bpf()

        # start listening for process events via ebpf
        self._background_task = asyncio.create_task(
            self._run_process_monitoring()
        )
        # Ensure exceptions are bubbled up and caught by the exception handler
        self._background_task.add_done_callback(lambda f: f.result())
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

    async def restart(
            self, config_by_uid: dict[int, SplitTunnelingConfig],
            process_match_callback: Callable[[ProcessEvent, Process], None]
    ):
        """Stops and starts the process monitoring background task again."""
        await self.stop()
        self.start(config_by_uid, process_match_callback)

    def _attach_bpf(self):
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
                    process_match_callback(ProcessEvent.CLONE, child)

        logger.info("Existing processes inspected in %d ms", (time.time_ns() - start) // 1_000_000)

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

            if _process_match(process, self._config_by_uid):
                self._tracked_procs[process.pid] = process
                self._process_match_callback(ProcessEvent.EXEC, process)
        elif event is ProcessEvent.CLONE:
            if process.ppid in self._tracked_procs:
                # if the parent pid is already tracked then the child is too
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
