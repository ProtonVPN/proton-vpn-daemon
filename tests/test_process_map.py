import json
from pathlib import Path
import pytest

from proton.vpn.daemon.split_tunneling.apps.process_matcher import Process
from proton.vpn.daemon.split_tunneling.apps.process_map import ProcessMap

process_dump_path = Path(__file__).parent / 'data' / 'processes.json'


def test_get_process_trees():
    process_map = ProcessMap.load(process_dump_path)

    process_trees = process_map.get_process_trees()
    
    assert len(process_trees) == 1

    root = process_trees[0]

    assert root.process == Process(
        uid=1000,
        pid=1,
        ppid=0,
        exe="/root",
        matched_config_paths=set(),
        running=True
    )
    assert len(root.children) == 2

    assert root.children[0].process == Process(
        uid=1000,
        pid=2,
        ppid=1,
        exe="/root/child1",
        matched_config_paths=set(),
        running=True
    )
    assert root.children[0].children == []

    assert root.children[1].process == Process(
        uid=1000,
        pid=3,
        ppid=1,
        exe="/root/child2",
        matched_config_paths=set(),
        running=True
    )

    assert len(root.children[1].children) == 1

    assert root.children[1].children[0].process == Process(
        uid=1000,
        pid=4,
        ppid=3,
        exe="/root/child2/child1",
        matched_config_paths=set(),
        running=True
    )

    assert len(root.children[1].children[0].children) == 0
