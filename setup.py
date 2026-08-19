from setuptools import setup, find_packages

setup(
    name="kl-lang",
    version="8.0.0",
    description="The Deterministic Binary Wire & Execution Protocol for AI Agents and Systems",
    author="Karthik Lanka",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "kl = kl.cli:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Compilers",
    ],
)
