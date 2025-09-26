from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="securerune",
    version="0.1.0",
    author="able",
    description="A compact utility aiming to cover and demonstrate every security and encryption algorithm",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
        "pycryptodome>=3.18.0",
        "argon2-cffi>=23.0.0",
        "click>=8.0.0",
    ],
    entry_points={
        "console_scripts": [
            "securerune=securerune.cli:main",
        ],
    },
)