# Retained for tools that do not yet read pyproject.toml.
from setuptools import setup, find_packages
from os import path


here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

install_reqs = [
    "aionetiface",
    "namebump",
    "sidewire",
    "ecdsa",
]
setup(
    version="4.0.12",
    name="warpgate",
    description="Any peer, any NAT — one-shot Python NAT traversal: 8-plugin cascade, IPv4 + IPv6, multi-NIC, zero infrastructure to run.",
    keywords=(
        "NAT traversal, hole punching, TCP hole punching, UDP hole punching, "
        "simultaneous open, STUN, TURN, ICE, UPnP, NAT-PMP, PCP, "
        "P2P, peer-to-peer, decentralized, rendezvous, WebRTC alternative, "
        "asyncio, async networking, IPv6, multi-NIC, cross-platform, "
        "Windows XP, self-hosted, serverless networking"
    ),
    long_description_content_type="text/markdown",
    long_description=long_description,
    url="https://www.warpgate.io/",
    author="Matthew Roberts",
    author_email="matthew@roberts.pm",
    license="public domain",
    package_dir={"": "src"},
    packages=find_packages(where="src", exclude=("tests", "docs")),
    include_package_data=True,
    python_requires=">=3.5",
    install_requires=install_reqs,
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
    ],
)
