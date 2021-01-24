#!/usr/bin/env python

"""The setup script."""

from setuptools import find_packages, setup

with open("requirements.txt", "r") as f:
    setup_requirements = [x for x in map(str.strip, f.read().split("\n")) if x != ""]

with open("README.rst") as readme_file:
    readme = readme_file.read()

setup(
    author="Dominik Muhs",
    author_email="dmuhs@protonmail.ch",
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Utilities",
        "Typing :: Typed",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    description="Just deployed a blockchain node? Have some tea.",
    install_requires=setup_requirements,
    license="MIT license",
    long_description=readme,
    include_package_data=True,
    keywords="teatime",
    name="teatime",
    packages=find_packages(exclude=["tests"]),
    setup_requires=setup_requirements,
    test_suite="tests",
    url="https://github.com/dmuhs/teatime",
    version="0.3.1",
    zip_safe=False,
)
