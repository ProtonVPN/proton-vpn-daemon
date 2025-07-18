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
from proton.vpn import logging

logger = logging.getLogger(__name__)


def asyncio_exception_handler(_, context: dict):
    """Handles all asyncio exceptions.
    Asyncio exception handler as specified in:
    https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.set_exception_handler

    Args:
        _: The loop object.
        context (dict): Contains
    """
    exception = context.get("exception")

    if exception:
        exc_type = type(exception)
        exc_value = exception
        exc_traceback = context.get("traceback")

        logger.error(
            "Unhandled error.",
            exc_info=(exc_type, exc_value, exc_traceback)
        )
