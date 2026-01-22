# setup.py
from setuptools import setup, find_packages
import os

# Автоматически читаем README.md для long_description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Автоматически находим все пакеты
packages = find_packages()

print(f"Найдены пакеты: {packages}")

setup(
    name="elfparser",
    version="0.1.0",
    author="Uneld",
    description="ELF BSS section inspector with DWARF parsing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=packages,  # Автоматически найдет все пакеты
    python_requires=">=3.10",
    install_requires=[
        "pyelftools",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    # Опционально: точка входа для CLI
    # entry_points={
    #     'console_scripts': [
    #         'elfparser=elfparser.cli:main',
    #     ],
    # },
)