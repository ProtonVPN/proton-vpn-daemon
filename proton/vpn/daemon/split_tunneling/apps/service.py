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
import asyncio

from typing import Awaitable

from proton.vpn.daemon.split_tunneling.apps.process_monitor import \
    Process, ProcessMonitor, build_process_monitor_cli_parser
from proton.vpn.daemon.split_tunneling.apps.socket_monitor import SocketMonitor

from proton.vpn import logging
from proton.vpn.core.settings import SplitTunnelingConfig, SplitTunnelingMode

logger = logging.getLogger(__name__)


class AppBasedSplitTunnelingService:
    """Service to split-tunnel applications."""

    def __init__(self):
        self._process_monitor = ProcessMonitor(self._on_process_event)
        self._socket_monitor = SocketMonitor()

    def _on_process_event(self, process: Process, mode: SplitTunnelingMode):
        if process.matched_config_paths:
            logger.info("Process match: %s", process)

        if process.running and (
            (mode == SplitTunnelingMode.EXCLUDE and process.matched_config_paths) or
            (mode == SplitTunnelingMode.INCLUDE and not process.matched_config_paths)
        ):
            self._socket_monitor.exclude_process_from_vpn(process.pid)
        else:
            self._socket_monitor.stop_tracking_process(process.pid)

    def log_status(self):
        """Logs the service status."""
        logger.info("==============App-based ST service status============")
        self._process_monitor.log_status()
        self._socket_monitor.log_status()
        logger.info("=====================================================")

    def start(self, config_by_uid: dict[int, SplitTunnelingConfig]) -> Awaitable[None]:
        """
        Starts the service in the background. This method is non-blocking.
        :param config_by_uid: split tunneling configuration indexed by unix user ID.
        :returns: an awaitable to be able to await until the service is stopped.
        """
        self._socket_monitor.start()
        return self._process_monitor.start(config_by_uid=config_by_uid)

    async def stop(self):
        """Stops the service."""
        try:
            await self._process_monitor.stop()
        finally:
            self._socket_monitor.stop()


async def main():
    """Test script"""

    parser = build_process_monitor_cli_parser(
        name="App-based Split Tunneling"
    )
    args = parser.parse_args()

    logging.config(filename="app-based-st-service")

    service = AppBasedSplitTunnelingService()
    try:
        await service.start(config_by_uid={
            args.uid: SplitTunnelingConfig(
                mode=SplitTunnelingMode(value=args.mode),
                app_paths=args.path
            )
        })
    except asyncio.CancelledError:
        pass
    finally:
        try:
            await service.stop()
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    asyncio.run(main())
