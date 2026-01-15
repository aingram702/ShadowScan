#!/usr/bin/env python3
"""
ShadowScan Setup Script
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="shadowscan",
    version="1.0.0",
    author="aingram702",
    author_email="aingram702@pm.me",
    description="Advanced Shodan Intelligence Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/aingram702/ShadowScan",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet",
    ],
    python_requires=">=3.7",
    install_requires=[
        "shodan>=1.28.0",
        "requests>=2.28.0",
    ],
    entry_points={
        "console_scripts": [
            "shadowscan=shadowscan.app:main",
        ],
    },
    include_package_data=True,
    keywords="shodan security reconnaissance osint scanner",
)
