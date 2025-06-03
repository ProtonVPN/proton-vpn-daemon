1. `sudo nano /usr/lib/systemd/system/me.proton.VPN.service`
    1. Paste
        ```
        [Unit]
        Description=Proton VPN Daemon
        After=network.target

        [Service]
        Type=dbus
        BusName=me.proton.VPN
        ExecStart=/usr/bin/proton-vpn-daemon
        Restart=always
        TimeoutStartSec=30

        [Install]
        WantedBy=multi-user.target
        ```

2. `sudo nano /etc/dbus-1/system.d/me.proton.VPN.conf`
    - Paste
    ```
    <!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
    "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
    <busconfig>
        <!-- Grant permission for the user running your service -->
        <policy context="default">
            <allow own="me.proton.VPN"/>

            <allow send_destination="me.proton.VPN"/>
            <allow receive_sender="me.proton.VPN"/>
            <allow send_interface="org.freedesktop.DBus.Introspectable"/>
            <allow receive_interface="org.freedesktop.DBus.Introspectable"/>
        </policy>
    </busconfig>
    ```

3. `sudo systemctl daemon-reload && sudo systemctl start me.proton.VPN.service && sudo systemctl enable me.proton.VPN.service && sudo systemctl status me.proton.VPN.service`


### For testing
1. Start service in background `/venv/bin/proton-vpn-daemon/`

5. Create a file called `client.py` and run it
```
import asyncio
from proton.vpn.daemon.split_tunneling.config import SplitTunnelingConfig
from proton.vpn.daemon.split_tunneling import SplitTunnelingService


async def main():
    sp_service = await SplitTunnelingService.init()

    sample_config = SplitTunnelingConfig("standard", ["some_path"], ["192.123.1.1"])

    uid = 1001

    await sp_service.set_config(sample_config, uid)
    print("Config set")

    config_from_daemon = await sp_service.get_config(uid)
    print("Received config:", config_from_daemon)

    await sp_service.clear_config(uid)
    print("Config cleared")

if __name__ == "__main__":
    asyncio.run(main())
```