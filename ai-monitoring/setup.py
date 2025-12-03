#!/usr/bin/env python3
"""
AI Monitoring & Observability Platform - Setup
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = ""
if readme_path.exists():
    long_description = readme_path.read_text()

setup(
    name="ai-monitoring",
    version="1.0.0",
    author="AI Monitoring Team",
    author_email="ai-monitoring@example.com",
    description="Comprehensive AI Monitoring & Observability Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/ai-monitoring",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Monitoring",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    python_requires=">=3.8",
    install_requires=[
        "elasticsearch>=8.0.0,<9.0.0",
        "pyyaml>=6.0",
        "psutil>=5.9.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "flake8>=6.0.0",
        ],
        "rich": [
            "rich>=13.0.0",
            "click>=8.0.0",
        ],
        "providers": [
            "openai>=1.0.0",
            "anthropic>=0.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ai-monitoring=ai_monitoring:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["config/*.yaml", "templates/*.json", "dashboards/*.ndjson"],
    },
)
