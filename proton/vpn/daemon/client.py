#!/usr/bin/env python3
import asyncio
from dbus_fast.aio import MessageBus
from dbus_fast import BusType


async def main():
    # Connect to the same bus type as the service
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

    # Get a proxy object for the service
    introspection = await bus.introspect('me.proton.VPN', '/me/proton/VPN')
    obj = bus.get_proxy_object(
        'me.proton.VPN', '/me/proton/VPN', introspection)

    # Get the interface (should match the one we exported)
    vpn_interface = obj.get_interface('me.proton.VPN')

    try:
        response = await vpn_interface.call_set_config()
        print("Response from service:", response)
    except Exception as e:
        print("Error calling service:", e)

    try:
        response = await vpn_interface.call_clear_config()
        print("Response from service:", response)
    except Exception as e:
        print("Error calling service:", e)

if __name__ == '__main__':
    asyncio.run(main())
