# setup.py
from setuptools import setup, find_packages
import os
import sys

#if sys.platform != 'linux':
#    sys.exit("FrameHunter only supports Linux")

# Read the version from __init__.py
version = None
init_path = os.path.join(os.path.dirname(__file__), 'framehunter', '__init__.py')
with open(init_path, 'r') as f:
    for line in f:
        if line.startswith('__version__'):
            version = line.split('=')[1].strip().strip("'").strip('"')
            break

if version is None:
    raise RuntimeError("Failed to read version from __init__.py")

setup(
    name="framehunter",
    version=version,
    description="A tool for analyzing and visualizing stack frames in ELF binaries",
    author="HyeonSeung Kim",
    author_email="dmskhs0912@gmail.com",
    url="https://github.com/dmskhs0912/FrameHunter",
    packages=find_packages(),
    install_requires=[
        "capstone",
        "pyelftools"
    ],
    entry_points={
        "console_scripts": [
            "framehunter=main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires='>=3.6',
)