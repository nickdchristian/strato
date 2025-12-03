from setuptools import setup, find_packages

setup(
    name="stratum",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.42.2",
        "typer>=0.20.0",
        "rich>=14.2.0",
    ],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "stm=stratum.main:app",
        ],
    },
)