#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = ["requests~=2.23.0", "loguru~=0.5.1"]
setup_requirements = ['pytest-runner', ]
test_requirements = ['pytest>=3', ]

setup(
    author="Dominik Muhs",
    author_email='dmuhs@protonmail.ch',
    python_requires='>=3.5',
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
        "Programming Language :: Python :: 3.8",
    ],
    description="A library for toasting blockchain nodes.",
    install_requires=requirements,
    license="MIT license",
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    keywords='toaster',
    name='toaster',
    packages=find_packages(include=['toaster', 'toaster.*']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/dmuhs/toaster',
    version='0.1.0',
    zip_safe=False,
)
