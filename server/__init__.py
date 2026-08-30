"""Reference cockpit server package.

Import concrete APIs from ``server.app``. Keeping package initialization lazy
avoids importing ``server.app`` twice when launched with ``python -m``.
"""
