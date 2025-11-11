#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SurveillanceRecon - Advanced CCTV/IoT Security Assessment Framework
Setup script for installation
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_file(filename):
    filepath = os.path.join(os.path.dirname(__file__), filename)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    return ''

setup(
    name='surveillance-recon',
    version='1.0.0',
    description='Advanced CCTV/IoT security assessment and penetration testing framework',
    long_description=read_file('README.md'),
    long_description_content_type='text/markdown',
    author='SecOps Research Team',
    author_email='secops@research.local',
    url='https://github.com/yourusername/surveillance-recon',
    license='Educational/Research Use Only',
    packages=find_packages(),
    include_package_data=True,
    python_requires='>=3.8',
    install_requires=[
        'requests>=2.31.0',
        'beautifulsoup4>=4.12.0',
        'cryptography>=41.0.0',
        'lxml>=4.9.0',
        'urllib3>=2.0.0',
        'PySocks>=1.7.1',
    ],
    entry_points={
        'console_scripts': [
            'surveillance-recon=surveillance_recon.cli:main',
            'srecon=surveillance_recon.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'Topic :: System :: Networking :: Monitoring',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
    keywords='security penetration-testing cctv iot dvr nvr surveillance reconnaissance',
    project_urls={
        'Bug Reports': 'https://github.com/yourusername/surveillance-recon/issues',
        'Source': 'https://github.com/yourusername/surveillance-recon',
        'Documentation': 'https://github.com/yourusername/surveillance-recon#readme',
    },
)
