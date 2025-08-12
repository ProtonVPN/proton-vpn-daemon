from unittest.mock import Mock
import pytest


from proton.vpn.daemon.split_tunneling.apps.process_monitor import ProcessMonitor
from proton.vpn.core.settings import SplitTunnelingConfig, SplitTunnelingMode


@pytest.mark.asyncio
async def test_start_updates_config_but_reuses_background_task_if_already_started():
    sut = ProcessMonitor(bpf=Mock())

    try:
        config1 = {1000: SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE, app_paths=["/my/app"])}
        background_task = sut.start(
            config_by_uid=config1,
            process_match_callback=Mock()
        )
        config2 = {1000: SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE, app_paths=["/my/app2"])}
        assert background_task == sut.start(
            config_by_uid=config2,
            process_match_callback=Mock()
        )
        assert sut.config_by_uid == config2
    finally:
        await sut.stop()
