from unittest.mock import AsyncMock
from proton.vpn.daemon.split_tunneling.apps.service import AppBasedSplitTunnelingService as AppService
from proton.vpn.daemon.split_tunneling.split_tunneling import SplitTunnelingService

import pytest

from proton.vpn.core.settings import SplitTunnelingConfig


@pytest.mark.asyncio
async def test_get_config_returns_existing_config():
    config_by_uid = {
        1000: SplitTunnelingConfig()
    }
    sut = SplitTunnelingService(
        config_by_uid=config_by_uid,
        app_service=AsyncMock(spec=AppService)
    )

    assert(sut.get_config(1000) == config_by_uid[1000])


def test_get_config_returns_none_if_config_was_not_set():
    sut = SplitTunnelingService(app_service=AsyncMock(spec=AppService))
    assert(sut.get_config(1000) == None)


@pytest.mark.asyncio
async def test_set_config_starts_app_service_if_app_based_config():
    app_service = AsyncMock(spec=AppService)
    sut = SplitTunnelingService(app_service=app_service)

    config = SplitTunnelingConfig(app_paths=["/usr/bin/app"])
    await sut.set_config(1000, config)

    app_service.start.assert_called_once_with({1000: config})

@pytest.mark.asyncio
async def test_set_config_stops_app_service_if_not_app_based_config():
    app_service = AsyncMock(spec=AppService)
    sut = SplitTunnelingService(app_service=app_service)

    config = SplitTunnelingConfig(app_paths=[])
    await sut.set_config(1000, config)

    app_service.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_clear_config_starts_app_service_if_remaining_app_based_config():
    config_by_uid = {
        1000: SplitTunnelingConfig(app_paths=["/usr/bin/app"]),
        1001: SplitTunnelingConfig(app_paths=["/usr/bin/app2"])
    }
    app_service = AsyncMock(spec=AppService)
    sut = SplitTunnelingService(
        config_by_uid=config_by_uid,
        app_service=app_service
    )

    await sut.clear_config(1000)

    app_service.start.assert_called_once_with({1001: SplitTunnelingConfig(app_paths=["/usr/bin/app2"])})

@pytest.mark.asyncio
async def test_clear_config_stops_app_service_if_no_remaining_app_based_config():
    config_by_uid = {
        1000: SplitTunnelingConfig(app_paths=["/usr/bin/app"])
    }
    app_service = AsyncMock(spec=AppService)
    sut = SplitTunnelingService(
        config_by_uid=config_by_uid,
        app_service=app_service
    )

    await sut.clear_config(1000)

    app_service.stop.assert_called_once()