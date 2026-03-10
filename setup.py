from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt") as f:
    requirements = [
        line.strip()
        for line in f
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="shadowmap",
    version="1.0.0",
    author="D0m0x61",
    description=(
        "OSINT & Cyber Intelligence CLI — passive infrastructure "
        "mapping, CVE prioritization, and credential leak detection."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/D0m0x61/ShadowMap",
    packages=find_packages(exclude=["tests*", "examples*"]),
    install_requires=requirements,
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "shadowmap=shadowmap.cli:run",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Internet",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
    ],
    keywords="osint cyber threat-intelligence cve shodan abuseipdb security",
)
