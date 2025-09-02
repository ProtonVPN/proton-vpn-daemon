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
from importlib.metadata import version
import asyncio

from proton.vpn import logging
from proton.vpn.daemon.split_tunneling.service import \
    init_split_tunneling_daemon
from proton.vpn.daemon.exception_handler import asyncio_exception_handler


async def main():
    """Main method to call daemons.
    """

    await init_split_tunneling_daemon()


def run_forever():
    """Runs the loop forever
    """
    logging.config(filename="vpn-daemon")
    logger = logging.getLogger(__name__)

    logger.info("Starting Proton VPN daemon v%s", version("proton-vpn-daemon"))
    loop = asyncio.new_event_loop()

    # Configure the exception handler for asyncio.
    loop.set_exception_handler(asyncio_exception_handler)

    loop.run_until_complete(main())
    loop.run_forever()

    # Restore to original exception handler.
    loop.set_exception_handler(None)


if __name__ == '__main__':
    try:
        run_forever()
    except KeyboardInterrupt:
        print("Service stopped.")
