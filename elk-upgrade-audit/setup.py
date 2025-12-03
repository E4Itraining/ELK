#!/usr/bin/env python3
"""
Setup script for ELK Upgrade Audit Tool
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="elk-upgrade-audit",
    version="1.0.0",
    description="Outil d'audit et de pilotage des upgrades de clusters Elasticsearch",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="E4Itraining",
    python_requires=">=3.8",
    packages=find_packages(),
    py_modules=["elk_upgrade_audit"],
    install_requires=[
        "elasticsearch>=8.0.0,<9.0.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "elk-audit=elk_upgrade_audit:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Systems Administration",
        "Topic :: Database :: Database Engines/Servers",
    ],
    keywords="elasticsearch, elk, upgrade, audit, cluster, migration",
)
