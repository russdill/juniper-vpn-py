#! /usr/bin/env python3

from setuptools import setup

setup(
    name='juniper-vpn',
    version=1,
    packages=['junipervpn'],
    url='https://github.com/chrisdiamand/juniper-vpn-py',
    project_urls={
        "Bug Tracker": 'https://github.com/chrisdiamand/juniper-vpn-py/issues',
        "Source Code": 'https://github.com/chrisdiamand/juniper-vpn-py',
    },
    license='COPYING',
    description='An openconnect wrapper to connect to Juniper VPNs',
    long_description="",
    python_requires='>= 3.4',
    install_requires=[
        'netifaces',
        'pyasn1',
        'pyasn1-modules',
        'mechanize',
    ],
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        # https://pypi.org/classifiers/
        "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2.1)"
        "Operating System :: POSIX :: Linux",
        "Topic :: System :: Networking",
        "Intended Audience :: End Users/Desktop",
    ],
    entry_points={
        'console_scripts': [
            'juniper-vpn.py = junipervpn.vpn:main',
            'tncc.py = junipervpn.tncc:main',
        ],
    },
)

# vim :set tabstop=4 shiftwidth=4 textwidth=80 expandtab
