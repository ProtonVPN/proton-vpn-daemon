from proton.vpn.core.settings import SplitTunnelingConfig, SplitTunnelingMode
from proton.vpn.daemon.split_tunneling.apps.utils import get_removed_config_app_paths_by_uid


def test__get_removed_config_app_paths_by_uid__returns_removed_app_path():
    new_config_by_uid = { 1000: SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE, app_paths=["/snap/bin/brave"], ip_ranges=[]) }
    old_config_by_uid = { 1000: SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE, app_paths=["/snap/bin/firefox"], ip_ranges=[]) }

    result = get_removed_config_app_paths_by_uid(new_config_by_uid, old_config_by_uid)

    assert result == { 1000: {"/snap/bin/firefox"}}


def test__get_removed_config_app_paths_by_uid__does_not_return_removed_app__when_there_was_no_previous_config():
    new_config_by_uid = { 1000: SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE, app_paths=["/snap/bin/brave"], ip_ranges=[]) }
    old_config_by_uid = None

    result = get_removed_config_app_paths_by_uid(new_config_by_uid, old_config_by_uid)

    assert result == {}


def test__get_removed_config_app_paths_by_uid__returns_empty_dict__when_app_paths_did_not_change():
    new_config_by_uid = { 1000: SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE, app_paths=["/snap/bin/firefox"], ip_ranges=[]) }
    old_config_by_uid = { 1000: SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE, app_paths=["/snap/bin/firefox"], ip_ranges=[]) }

    result = get_removed_config_app_paths_by_uid(new_config_by_uid, old_config_by_uid)

    assert result == {}
