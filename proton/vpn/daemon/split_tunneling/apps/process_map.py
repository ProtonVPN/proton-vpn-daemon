"""
Copyright (c) 2025 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton VPN is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
import json
from tempfile import NamedTemporaryFile
from typing import TextIO
from proton.vpn.daemon.split_tunneling.apps.process_matcher import Process


@dataclass
class ProcessTreeNode:
    """Used to generate the process tree"""
    process: Process
    children: list[ProcessTreeNode] = field(default_factory=list)


class ProcessMap:
    """Utility class to dump tracked processes to disk for debugging purposes."""

    def __init__(self, processes: dict[int, Process]):
        self.processes = processes

    def dump(self) -> str:
        """
        Dumps the dict containing tracked processes to a temporary file.
        :returns: the path to the generated dump file.
        """
        with NamedTemporaryFile(prefix="process-dump-", mode="w", delete=False) as file:
            json.dump(
                [asdict(process) for process in self.processes.values()],
                file,
                indent=4,
                default=list  # to write python sets as json lists - json doesn't have sets
            )
            return file.name

    @staticmethod
    def load(path: str) -> ProcessMap:
        """
        Loads the process dump from the given path.
        :returns: the processes indexed by pid.
        """
        with open(path, encoding="utf8") as file:
            return ProcessMap(processes={
                process["pid"]: Process(
                    uid=process["uid"],
                    pid=process["pid"],
                    ppid=process["ppid"],
                    exe=process["exe"],
                    matched_config_paths=set(process["matched_config_paths"]),
                    running=process["running"]
                )
                for process in json.load(file)
            })

    def _get_root_processes(self) -> list[Process]:
        """
        :returns: the list of root processes.
        """
        return [
            process for process in self.processes.values()
            if process.ppid not in self.processes
        ]

    def _get_process_children(self, parent: Process) -> list[Process]:
        """
        :param parent: process to get the children from.
        :returns: the direct children of the parent process.
        """
        return [
            process for process in self.processes.values()
            if process.ppid == parent.pid
        ]

    def _get_process_tree(self, process: Process) -> ProcessTreeNode:
        """
        :param process: top process to generate its tree.
        :returns: the process tree of the specified top process.
        """
        return ProcessTreeNode(
            process=process,
            children=[
                self._get_process_tree(process=child)
                for child in self._get_process_children(process)
            ]
        )

    def get_process_trees(self) -> list[ProcessTreeNode]:
        """
        :returns: all process trees.
        """
        return [
            self._get_process_tree(process) for process in self._get_root_processes()
        ]

    def dump_process_tree(self, node: ProcessTreeNode, output_file: TextIO, nested_level: int):
        """
        Dumps a process tree to a file.
        :param node: the top tree node.
        :output_file: the file to dump the tree to.
        :nested_level: amount of indentation to dump the node with.
        """
        tabs = "\t" * nested_level
        output_file.write(f"{tabs}{node.process}\n")
        nested_level += 1
        for child in node.children:
            self.dump_process_tree(child, output_file, nested_level)

    def dump_process_trees(self) -> str:
        """
        Dumps all trees of processes to a temp file.
        :returns: the dump file path.
        """
        with NamedTemporaryFile(prefix="process-tree-", mode="w", delete=False) as file:
            process_trees = self.get_process_trees()
            for tree in process_trees:
                self.dump_process_tree(node=tree, output_file=file, nested_level=0)

            return file.name
