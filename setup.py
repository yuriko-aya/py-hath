#!/usr/bin/env python3
"""
Setup script for Hentai@Home Python Client
"""

from setuptools import setup, find_packages

with open("requirements.txt", "r") as f:
    requirements = f.read().splitlines()

setup(
    name="hentai-at-home-python",
    version="1.6.4-py",
    description="Python implementation of Hentai@Home client",
    author="E-Hentai.org",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "hath-python=main:main",
        ],
    },
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
