from proton.vpn.core.settings import SplitTunnelingConfig, SplitTunnelingMode

from proton.vpn.daemon.split_tunneling.apps.process_matcher import Process, ProcessMatcher


def test_check_process_does_not_return_matches_when_there_is_not_config_for_process_uid():
    process = Process(uid=1000, pid=1234, ppid=1233, exe="/usr/bin/foo")
    config_by_uid = {}

    matches = ProcessMatcher.check_process(process, config_by_uid)

    assert not matches


def test_check_process_returns_match_when_process_is_vpn_client_and_st_mode_is_include():
    process = Process(uid=1000, pid=1234, ppid=1233, exe="/usr/bin/protonvpn-app")
    config_by_uid = {1000: SplitTunnelingConfig(mode=SplitTunnelingMode.INCLUDE)}

    matches = ProcessMatcher.check_process(process, config_by_uid)

    assert matches == set([ProcessMatcher.VPN_APP_BIN])


def test_check_process_returns_match_when_process_path_matches_config():
    app_path = "/usr/bin/foo"
    process = Process(uid=1000, pid=1234, ppid=1233, exe=app_path)
    config_by_uid = {1000: SplitTunnelingConfig(mode=SplitTunnelingMode.INCLUDE, app_paths=[app_path])}

    matches = ProcessMatcher.check_process(process, config_by_uid)

    assert matches == set([app_path])


def test_check_process_returns_empty_set_when_there_are_no_config_matches():
    process = Process(uid=1000, pid=1234, ppid=1233, exe="/usr/bin/foo")
    config_by_uid = {1000: SplitTunnelingConfig(mode=SplitTunnelingMode.INCLUDE, app_paths=["/usr/bin/bar"])}

    matches = ProcessMatcher.check_process(process, config_by_uid)

    assert matches == set()

