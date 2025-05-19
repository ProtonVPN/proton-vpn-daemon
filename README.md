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
            <!-- Allow everybody to own the bus name -->
            <allow own="me.proton.VPN"/>

            <!-- Allow sending to and receiving from this name -->
            <allow send_destination="me.proton.VPN"/>
            <allow receive_sender="me.proton.VPN"/>

            <!-- Allow introspection: this lets clients like d-feet query the object -->
            <allow send_interface="org.freedesktop.DBus.Introspectable"/>
            <<allow receive_interface="org.freedesktop.DBus.Introspectable"/>
        </policy>
    </busconfig>
    ```

3. `sudo systemctl daemon-reload && sudo systemctl start me.proton.VPN.service && sudo systemctl enable me.proton.VPN.service && sudo systemctl status me.proton.VPN.service`