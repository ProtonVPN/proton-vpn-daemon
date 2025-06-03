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
import os
import asyncio
import logging
from systemd.journal import JournalHandler

from proton.vpn.daemon.split_tunneling.service import \
    init_split_tunneling_daemon

log = logger = logging.getLogger(__name__)
log.addHandler(JournalHandler())


async def main():
    """Main method to call daemons.
    """
    logging_level = logging.INFO
    if os.environ.get("PROTON_VPN_DEBUG", "false").lower() == "true":
        logging_level = logging.DEBUG

    log.setLevel(logging_level)

    await init_split_tunneling_daemon()


def run_forever():
    """Runs the loop forever
    """
    log.info("Logging Proton VPN daemon journalctl")
    loop = asyncio.new_event_loop()
    loop.run_until_complete(main())
    loop.run_forever()


if __name__ == '__main__':
    try:
        run_forever()
    except KeyboardInterrupt:
        print("Service stopped.")
