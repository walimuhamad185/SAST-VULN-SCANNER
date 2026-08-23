"""
sast_agent/__init__.py
=======================
Next-Gen AI-Powered Universal SAST Agent — package entry.

A modular, AST-aware static application security testing (SAST) engine that
performs context-sensitive data-flow analysis across multiple programming
languages to detect real, high-severity vulnerabilities with minimal false
positives. Operating entirely on localhost for strict data privacy.
"""

__version__ = "3.0.1"
__author__ = "Wali Muhammad"
__all__ = ["scanner", "rules", "taint", "reporters", "ai_filter", "autofix",
           "config_loader", "baseline", "notify", "pdf_export"]
