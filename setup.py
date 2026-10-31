from setuptools import setup, find_packages

setup(
    name="mattersploit",
    version="1.0.0",
    description="Matter/Thread Offensive Security Framework",
    author="MatterSploit Team",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],
    entry_points={"console_scripts": ["mattersploit=mattersploit.cli:main"]},
)
