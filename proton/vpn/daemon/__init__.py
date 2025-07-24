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
import sys
from proton.vpn import logging

# Only configure logging if this module is being run as the main daemon
if (
    __name__ == "__main__" or  # Direct execution
    "proton-vpn-daemon" in sys.argv[0]  # Daemon script
):
    logging.config(filename="vpn-daemon")
else:
    # We're being imported by another process
    # Don't configure logging - let the importing process handle it
    pass
