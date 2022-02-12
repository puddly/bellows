"""Setup module for bellows"""

raise RuntimeError(
    "\n" * 10
    + "#######################################################################################\n"
    + "This branch is obsolete!  Please test https://github.com/zigpy/zigpy-cli/pull/2 instead\n"
    + "#######################################################################################\n"
    + "\n" * 10
)

from setuptools import find_packages, setup

import bellows

setup(
    name="bellows",
    version=bellows.__version__,
    description="Library implementing EZSP",
    url="http://github.com/zigpy/bellows",
    author="Russell Cloran",
    author_email="rcloran@gmail.com",
    license="GPL-3.0",
    packages=find_packages(exclude=["tests", "tests.*"]),
    entry_points={"console_scripts": ["bellows=bellows.cli.main:main"]},
    install_requires=[
        "click",
        "click-log>=0.2.1",
        "dataclasses;python_version<'3.7'",
        "pure_pcapy3==1.0.1",
        "pyserial-asyncio",
        "voluptuous",
        "zigpy>=0.34.0",
    ],
    dependency_links=["https://codeload.github.com/rcloran/pure-pcapy-3/zip/master"],
    tests_require=["asynctest", "pytest", "pytest-asyncio"],
)
