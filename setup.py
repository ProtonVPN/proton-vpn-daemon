#!/usr/bin/env python

from setuptools import setup, find_namespace_packages
import re

VERSIONS = 'versions.yml'
VERSION = re.search(r'version: (\S+)', open(VERSIONS, encoding='utf-8')
                    .readline()).group(1)

setup(
    name="proton-vpn-daemon",
    version=VERSION,
    description="Proton VPN Daemon",
    author="Proton AG",
    author_email="opensource@proton.me",
    url="https://github.com/ProtonVPN/proton-vpn-daemon",
    install_requires=[
        "dbus-fast",
        "systemd-python",
        "proton-vpn-api-core",
        "psutil",
        "packaging",
    ],
    extras_require={
        "development": [
            "wheel",
            "flake8",
            "pylint",
            "pytest",
            "pytest-asyncio",
            "pytest-cov",
        ]
    },
    packages=find_namespace_packages(include=["proton.vpn.daemon*"]),
    package_data={'': ['*.bpf.c']},
    include_package_data=True,
    python_requires=">=3.9",
    license="GPLv3",
    platforms="Linux",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python",
        "Topic :: Security",
    ],
    entry_points={
        "proton_loader_split_tunneling": [
            "split_tunneling_service = proton.vpn.daemon.split_tunneling:SplitTunnelingDbusClient",  # noqa: E501
        ],
    }
)
