"""Unified analyzer tool adapters (Foundry, Slither, optional fuzzers).

Each adapter reports a ToolStatus; orchestration never marks timeout/unsupported as pass.
"""
from .base import ToolResult, ToolStatus, probe_all

__all__ = ["ToolResult", "ToolStatus", "probe_all"]
