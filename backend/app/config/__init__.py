"""
Config package.

Exposes the application :class:`Config` used by the Flask factory.
"""

from .settings import Config, get_config

__all__ = ["Config", "get_config"]
