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
import logging
from typing import Awaitable

from proton.vpn.daemon.split_tunneling.apps.process_monitor import \
    Process, ProcessEvent, ProcessMonitor
from proton.vpn.daemon.split_tunneling.apps.socket_monitor import SocketMonitor

from proton.vpn.core.settings import SplitTunnelingConfig

from proton.vpn.daemon.split_tunneling.exceptions import WireGuardConnectionNotFound


logger = logging.getLogger(__name__)


class AppBasedSplitTunnelingService:
    """Service to split-tunnel applications."""

    def __init__(self):
        self._process_monitor = ProcessMonitor()
        self._socket_monitor = SocketMonitor()

    def _on_process_event(self, event: ProcessEvent, process: Process):
        logger.info("Process match: event=%s, process=%s", event, process)
        if event in (ProcessEvent.EXEC, ProcessEvent.FORK):
            logger.info("Removing pid %d from VPN", process.pid)
            self._socket_monitor.remove_process_from_vpn(process.pid)
        elif event == ProcessEvent.EXIT:
            logger.info("Forgetting pid %d", process.pid)
            self._socket_monitor.forget_process(process.pid)
        else:
            logger.error("Unexpected event: %s", event)

    def start(self, config_by_uid: dict[int, SplitTunnelingConfig]) -> Awaitable[None]:
        """
        Starts the service in the background. This method is non-blocking.
        :param config_by_uid: split tunneling configuration indexed by unix user ID.
        :returns: an awaitable to be able to await until the service is stopped.
        """
        done_future = asyncio.Future()
        done_future.set_result(None)
        if not self._is_app_based_config(config_by_uid):
            # Nothing to do, there isn't app-based split tunneling config
            return done_future

        self._socket_monitor.start()
        return self._process_monitor.start(
            config_by_uid=config_by_uid,
            process_match_callback=self._on_process_event
        )

    async def stop(self):
        """Stops the service."""
        try:
            await self._process_monitor.stop()
        finally:
            self._socket_monitor.stop()

    async def restart(self, config_by_uid: dict[int, SplitTunnelingConfig]):
        """Equivalent to calling stop() and then start(config_by_uid)."""
        await self.stop()
        return self.start(config_by_uid=config_by_uid)

    def _is_app_based_config(self, config_by_uid: dict[int, SplitTunnelingConfig]) -> bool:
        return any(
            any(path for path in config.app_paths)  # any non empty path
            for config in config_by_uid.values()    # on any user config
        )


async def main():
    """Test script"""

    import os  # pylint: disable=C0415
    import sys  # pylint: disable=C0415
    from proton.vpn.core.settings import SplitTunnelingMode  # pylint: disable=C0415

    root_logger = logging.getLogger()
    root_logger.addHandler(logging.StreamHandler())

    from proton.vpn.daemon.split_tunneling.apps.process_monitor import \
        build_process_monitor_cli_parser  # pylint: disable=C0415
    parser = build_process_monitor_cli_parser(
        name="App-based Split Tunneling"
    )
    args = parser.parse_args()

    uid = args.uid or os.getuid()
    service = AppBasedSplitTunnelingService()
    try:
        await service.start(config_by_uid={
            uid: SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE, app_paths=args.path)
        })

    except WireGuardConnectionNotFound as error:
        logger.error("Please start a VPN connection first: %s", error)
        sys.exit(1)
    except asyncio.CancelledError:
        pass
    finally:
        try:
            await service.stop()
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    asyncio.run(main())
