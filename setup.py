from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="sast-vuln-scanner",
    version="3.0.5",
    author="Wali Muhammad",
    description="Next-Gen AI-Powered Universal SAST Agent — automated code security audits.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/walimuhamad185/SAST-VULN-SCANNER",
    packages=find_packages(exclude=("tests",)),
    py_modules=["sast_agent"],
    entry_points={
        "console_scripts": [
            "sast-agent=sast_agent.cli:main",
            "sast=sast_agent.cli:main",
        ],
    },
    python_requires=">=3.8",
    extras_require={
        "ai": ["openai>=1.0.0"],
        "pdf": ["weasyprint"],
        "yaml": ["pyyaml"],
        "all": ["openai>=1.0.0", "weasyprint", "pyyaml"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
    ],
)
