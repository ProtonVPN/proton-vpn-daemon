import asyncio
from dbus_fast.aio import MessageBus
from dbus_fast.service import (ServiceInterface, method, dbus_property, signal)
from dbus_fast import Variant, BusType

# Define a service interface


class VPNInterface(ServiceInterface):
    def __init__(self):
        super().__init__('me.proton.VPN')

    @method()
    async def set_config(self) -> 's':
        print("Called set_config()!")
        return "Called set_config()!"

    @method()
    async def clear_config(self) -> 's':
        print("Called clear_config()!")
        return "Called clear_config()!"


async def main():
    # Connect to the session bus (replace BusType.SESSION with BusType.SYSTEM if needed)
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

    # Request a well-known name on the bus (similar to owning a service name)
    name = await bus.request_name('me.proton.VPN')

    # Export our interface at a particular object path.
    interface = VPNInterface()
    bus.export('/me/proton/VPN', interface)

    print("Service is running. Press Ctrl+C to exit.")
    # Run forever


def run_forever():
    loop = asyncio.new_event_loop()
    loop.run_until_complete(main())
    loop.run_forever()


if __name__ == '__main__':
    try:
        run_forever()
    except KeyboardInterrupt:
        print("Service stopped.")
