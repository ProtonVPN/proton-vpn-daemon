from unittest.mock import AsyncMock
from proton.vpn.daemon.split_tunneling.apps.process_monitor import ProcessMonitor
from proton.vpn.daemon.split_tunneling.split_tunneling import SplitTunnelingService

import pytest

from proton.vpn.core.settings import SplitTunnelingConfig


@pytest.mark.asyncio
async def test_get_config_returns_existing_config():
    config_by_uid = {
        1000: SplitTunnelingConfig(app_paths=["/my/app"])
    }
    sut = SplitTunnelingService(
        config_by_uid=config_by_uid,
        process_monitor=AsyncMock(spec=ProcessMonitor)
    )

    assert(sut.get_config(1000) == config_by_uid[1000])


def test_get_config_returns_none_if_config_was_not_set():
    sut = SplitTunnelingService(process_monitor=AsyncMock(spec=ProcessMonitor))
    assert(sut.get_config(1000) == None)


@pytest.mark.asyncio
async def test_set_config_restarts_process_monitor_if_config_contains_app_paths():
    process_monitor = AsyncMock(spec=ProcessMonitor)
    sut = SplitTunnelingService(process_monitor=process_monitor)

    config = SplitTunnelingConfig(app_paths=["/my/app"])
    await sut.set_config(1000, config)

    process_monitor.restart.assert_awaited_once()



@pytest.mark.parametrize("app_paths", [
    [],
    [""]
])
@pytest.mark.asyncio
async def test_set_config_stops_process_monitor_if_config_does_not_contain_valid_app_paths(
        app_paths
):
    process_monitor = AsyncMock(spec=ProcessMonitor)
    sut = SplitTunnelingService(process_monitor=process_monitor)

    config = SplitTunnelingConfig(app_paths=app_paths)
    await sut.set_config(1000, config)

    process_monitor.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_clear_config_restarts_process_monitor_if_any_remaining_config_contains_app_paths():
    config_by_uid = {
        1000: SplitTunnelingConfig(app_paths=["/my/app1"]),
        1001: SplitTunnelingConfig(app_paths=["/my/app2"])
    }
    process_monitor = AsyncMock(spec=ProcessMonitor)
    sut = SplitTunnelingService(
        config_by_uid=config_by_uid,
        process_monitor=process_monitor
    )

    await sut.clear_config(1000)

    process_monitor.restart.assert_awaited_once()

@pytest.mark.asyncio
async def test_clear_config_stops_process_monitor_if_no_remaining_config_contains_app_paths():
    config_by_uid = {
        1000: SplitTunnelingConfig(app_paths=["/my/app1"]),
        1001: SplitTunnelingConfig(app_paths=[])
    }
    process_monitor = AsyncMock(spec=ProcessMonitor)
    sut = SplitTunnelingService(
        config_by_uid=config_by_uid,
        process_monitor=process_monitor
    )

    await sut.clear_config(1000)

    process_monitor.stop.assert_awaited_once()
