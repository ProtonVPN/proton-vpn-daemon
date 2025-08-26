from unittest.mock import Mock
import pytest

from bcc import BPF


from proton.vpn.daemon.split_tunneling.apps.process_monitor import PerfBufferEventType, ProcessMonitor
from proton.vpn.core.settings import SplitTunnelingConfig, SplitTunnelingMode

from proton.vpn.daemon.split_tunneling.apps.process_matcher import Process, ProcessMatcher


@pytest.mark.asyncio
async def test_start_updates_config_but_reuses_background_task_if_already_started():
    sut = ProcessMonitor(process_event_callback=Mock(), bpf=Mock(spec=BPF))

    try:
        config1 = {1000: SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE, app_paths=["/my/app"])}
        background_task = sut.start(
            config_by_uid=config1
        )
        config2 = {1000: SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE, app_paths=["/my/app2"])}
        assert background_task == sut.start(
            config_by_uid=config2
        )
        assert sut.config_by_uid == config2
    finally:
        await sut.stop()


def test_check_for_config_matches_notifies_callback_on_exec_event():
    process_event_callback = Mock()
    app_path = "/usr/bin/foo"
    config_by_uid = {
        1000: SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE, app_paths=[app_path])
    }
    process_matcher = Mock(spec=ProcessMatcher)
    matched_config_paths = set([app_path])
    process_matcher.check_process.return_value = matched_config_paths

    sut = ProcessMonitor(process_event_callback, config_by_uid=config_by_uid, bpf=Mock(spec=BPF), process_matcher=process_matcher)

    process = Process(uid=1000, pid=1234, ppid=1, exe=app_path)
    sut.check_for_config_matches(event=PerfBufferEventType.EXEC, process=process)

    process_event_callback.assert_called_once_with(
        Process(
            uid=process.uid,
            pid=process.pid,
            ppid=process.ppid,
            exe=process.exe,
            matched_config_paths=matched_config_paths  # matches reported by process_matcher were added to the process
        ),
        SplitTunnelingMode.EXCLUDE
    )


def test_check_for_config_matches_propagates_parent_process_matches_to_child_process_on_clone_event():
    process_event_callback = Mock()
    app_path = "/usr/bin/foo"
    config_by_uid = {
        1000: SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE, app_paths=[app_path])
    }

    # Parent process already being tracked with a config path match
    parent_process = Process(uid=1000, pid=1234, ppid=0, exe=app_path, matched_config_paths=set([app_path]))
    tracked_procs = {parent_process.pid: parent_process}
    sut = ProcessMonitor(process_event_callback, config_by_uid=config_by_uid, bpf=Mock(spec=BPF), tracked_procs=tracked_procs)

    # Child process is cloned from the parent
    child_process = Process(uid=1000, pid=1235, ppid=parent_process.pid, exe="/usr/bin/bar")
    sut.check_for_config_matches(event=PerfBufferEventType.CLONE, process=child_process)

    process_event_callback.assert_called_once_with(
        Process(
            uid=child_process.uid,
            pid=child_process.pid,
            ppid=child_process.ppid,
            exe=child_process.exe,
            matched_config_paths=parent_process.matched_config_paths  # parent process matches are propagated to the child process
        ),
        SplitTunnelingMode.EXCLUDE
    )

def test_check_for_config_matches_notifies_callback_on_exit_event():
    process_event_callback = Mock()
    app_path = "/usr/bin/foo"
    config_by_uid = {
        1000: SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE, app_paths=[app_path])
    }
    process = Process(uid=1000, pid=1235, ppid=1234, exe=app_path, matched_config_paths=set([app_path]), running=True)

    sut = ProcessMonitor(
        process_event_callback=process_event_callback,
        config_by_uid=config_by_uid,
        tracked_procs={process.pid: process},
        bpf=Mock(spec=BPF)
    )

    sut.check_for_config_matches(event=PerfBufferEventType.EXIT, process=process)

    process_event_callback.assert_called_once_with(
        Process(
            uid=process.uid,
            pid=process.pid,
            ppid=process.ppid,
            exe=process.exe,
            matched_config_paths=process.matched_config_paths,
            running=False),  # process flagged as not running
        SplitTunnelingMode.EXCLUDE
    )
