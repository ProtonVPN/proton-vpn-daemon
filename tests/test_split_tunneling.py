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
async def test_set_config_restarts_app_service():
    app_service = AsyncMock(spec=AppService)
    sut = SplitTunnelingService(app_service=app_service)

    config = SplitTunnelingConfig()
    await sut.set_config(1000, config)

    app_service.restart.assert_awaited_once()


@pytest.mark.asyncio
async def test_clear_config_restarts_app_service():
    config_by_uid = {
        1000: SplitTunnelingConfig()
    }
    app_service = AsyncMock(spec=AppService)
    sut = SplitTunnelingService(
        config_by_uid=config_by_uid,
        app_service=app_service
    )

    await sut.clear_config(1000)

    app_service.restart.assert_awaited_once()
