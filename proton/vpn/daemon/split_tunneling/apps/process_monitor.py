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
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

import asyncio

from bcc import BPF

from proton.vpn import logging
from proton.vpn.core.settings import SplitTunnelingConfig, SplitTunnelingMode

from proton.vpn.daemon.split_tunneling.apps.process_map import ProcessMap
from proton.vpn.daemon.split_tunneling.apps.process_matcher import \
    Process, ProcessMatcher

logger = logging.getLogger(__name__)

BPF_PROGRAM_PATH = Path(__file__.replace(".py", ".bpf.c"))


class PerfBufferEventType(Enum):
    """Type of events sent to the BPF perf buffer"""
    EXEC_ARGV_FRAGMENT = 0
    EXEC = 1
    CLONE = 2
    EXIT = 3


# pylint: disable=too-many-instance-attributes,
class ProcessMonitor:
    """Monitors processes based on the specified Split Tunneling configuration."""

    # pylint: disable=too-many-arguments
    def __init__(
            self,
            process_event_callback: Callable[[Process, SplitTunnelingMode]],
            config_by_uid: Optional[dict[int, SplitTunnelingConfig]] = None,
            tracked_procs: Optional[dict[int, Process]] = None,
            bpf: Optional[BPF] = None,
            process_matcher: Optional[ProcessMatcher] = None
    ):
        self._process_event_callback = process_event_callback
        self._config_by_uid = config_by_uid
        self._bpf = bpf
        self._process_matcher = process_matcher or ProcessMatcher()
        self._background_task: Optional[asyncio.Task] = None
        self._stop_requested = False
        self._tracked_procs = tracked_procs or {}
        self._argv = defaultdict(list)

    @property
    def config_by_uid(self) -> Optional[dict[int, SplitTunnelingConfig]]:
        """Returns the curret config in use."""
        return self._config_by_uid

    def log_status(self):
        """Logs the process monitor status."""
        logger.info("===============Process monitor status================")
        logger.info("Config: %s", self._config_by_uid)
        process_map = ProcessMap(self._tracked_procs)
        logger.info("Tracked processes dumped at: %s", process_map.dump())
        logger.info("Tracked process trees dumped at: %s", process_map.dump_process_trees())
        logger.info("=====================================================")

    def start(
            self, config_by_uid: dict[int, SplitTunnelingConfig]
    ) -> asyncio.Task:
        """
        Starts a background task to monitor processes.
        @param config_by_uid: map of split tunneling configuration by uid (unix user id)
        @param process_event_callback: callback called whenever there is a process event.

        Note that this method returns straight away, it doesn't wait that
        the background task is running.
        """
        self._config_by_uid = config_by_uid

        if not self._background_task:
            logger.info("Starting process monitor")

            self._tracked_procs = self._process_matcher.check_all_processes(config_by_uid)
            for process in self._tracked_procs.values():
                self._process_event_callback(process, config_by_uid[process.uid].mode)

            self._attach_bpf()

            # start listening for process events via ebpf
            self._background_task = asyncio.create_task(
                self._run_process_monitoring()
            )

            # Ensure exceptions are bubbled up and caught by the exception handler
            def on_done(future):
                try:
                    future.result()
                except asyncio.CancelledError:
                    pass

            self._background_task.add_done_callback(on_done)
        else:
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
        callback = self._process_event_callback
        self.__init__(process_event_callback=callback)  # pylint: disable=C2801
        logger.info("Process monitor stopped")

    def _attach_bpf(self):
        if not self._bpf:
            with open(BPF_PROGRAM_PATH, "r", encoding="utf-8") as file:
                bpf_text = file.read()
            self._bpf = BPF(text=bpf_text)

        # Explicitly attach kprobes/kretprobes,
        # tracepoints using TRACEPOINT_PROBE are automatically attached when
        # the BPF object is created
        execve_fnname = self._bpf.get_syscall_fnname("execve")
        self._bpf.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
        self._bpf.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

    def _detach_bpf(self):
        # Explicitly detach kprobes/kretprobes,
        # tracepoints using TRACEPOINT_PROBE are automatically detached when
        # the BPF object is destroyed
        execve_fnname = self._bpf.get_syscall_fnname("execve")
        self._bpf.detach_kprobe(event=execve_fnname, fn_name="syscall__execve")
        self._bpf.detach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

        # Destroy the BPF object to detach tracepoints
        self._bpf = None

    async def _run_process_monitoring(self):
        await asyncio.get_running_loop().run_in_executor(
            None, self._run_blocking_process_monitoring
        )

    def _run_blocking_process_monitoring(self):
        self._bpf["events"].open_perf_buffer(self._process_perf_buffer_event)
        while not self._stop_requested:
            self._bpf.perf_buffer_poll(timeout=30)  # timeout in ms

    def _process_perf_buffer_event(self, _cpu, data, _size):
        event = self._bpf["events"].event(data)

        if event.type == PerfBufferEventType.EXEC_ARGV_FRAGMENT.value:
            # Whenever an exec syscall is initiated, multiple EXEC_ARGV_FRAGMENT events are
            # sent, one per argv: the first one contains the full path, and the following
            # ones contain each argument (up to a limit, see ebpf program).
            self._argv[event.pid].append(event.argv)
            return

        exe = ""
        if event.type == PerfBufferEventType.EXEC.value:
            # Once the exec syscall returns, the final exe path is built out of all the
            # previous EXEC_ARGV_FRAGMENT events containing the fragments that make it up.
            exe = b' '.join(self._argv[event.pid]).replace(b'\n', b'\\n').decode('utf-8')
            try:
                del self._argv[event.pid]
            except KeyError:
                pass

        self.check_for_config_matches(
            PerfBufferEventType(value=event.type),
            Process(event.uid, event.pid, event.ppid, exe)
        )

    def check_for_config_matches(self, event: PerfBufferEventType, process: Process):
        """Checks if the process matches the ST config and calls the callback."""
        if process.uid not in self.config_by_uid:
            # processes started by users that didn't set any ST config are ignored
            return

        if event is PerfBufferEventType.EXEC:
            already_tracked_process = self._tracked_procs.get(process.pid)
            if already_tracked_process and already_tracked_process.matched_config_paths:
                # We do a sticky process matching: once a process matches one of the
                # config paths then any subsequent exec syscalls done by the same process
                # are ignored. This is because some apps start from an executable
                # but then run an exec syscall to a different one (e.g. Google Chrome).
                return

            # a new process was started: check for config path matches
            matches = self._process_matcher.check_process(process, self._config_by_uid)
            process.matched_config_paths.update(matches)
            self._tracked_procs[process.pid] = process
            self._process_event_callback(process, self.config_by_uid[process.uid].mode)

        elif event is PerfBufferEventType.CLONE:
            # a process was cloned/forked: check if its parent matched config paths
            parent = self._tracked_procs.get(process.ppid)
            if parent:
                # a cloned process inherits its parent config path matches
                process.matched_config_paths.update(parent.matched_config_paths)
                self._tracked_procs[process.pid] = process
                self._process_event_callback(process, self.config_by_uid[process.uid].mode)

        elif event is PerfBufferEventType.EXIT:
            # a process exited: stop tracking it
            if process.pid in self._tracked_procs:
                process = self._tracked_procs[process.pid]
                process.running = False
                self._process_event_callback(process, self.config_by_uid[process.uid].mode)
                del self._tracked_procs[process.pid]


def build_process_monitor_cli_parser(name: str):
    """Builds the process monitor CLI arg parser"""
    import argparse  # pylint: disable=C0415

    parser = argparse.ArgumentParser(
        prog=name,
        description="For testing purposes only"
    )
    parser.add_argument("-u", "--uid", required=True, type=int, help="UID to exclude process for.")
    parser.add_argument(
        "-m", "--mode", required=True, choices=["exclude", "include"],
        help="Split Tunneling mode"
    )
    parser.add_argument(
        "-p", "--path", required=True, action="append",
        help="Process paths to exclude."
    )

    return parser


async def main():
    """Test script"""
    logging.config(filename="stprocmon")
    _logger = logging.getLogger("stprocmon")

    parser = build_process_monitor_cli_parser(
        name="Process monitor for app-based Split Tunneling"
    )
    args = parser.parse_args()

    def callback(process: Process, mode: SplitTunnelingMode):  # pylint: disable=unused-argument
        if process.matched_config_paths:
            for config_path in args.path:
                if any(
                    process_path.startswith(config_path)
                    for process_path in process.matched_config_paths
                ):
                    _logger.info("Process match: %s", process)

    process_monitor = ProcessMonitor(process_event_callback=callback)
    try:
        await process_monitor.start(
            config_by_uid={
                args.uid: SplitTunnelingConfig(
                    mode=SplitTunnelingMode(value=args.mode),
                    app_paths=args.path
                )
            }
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
