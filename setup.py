import re
from pathlib import Path

from setuptools import setup


def get_version():
    content = Path("valigetta/__init__.py").read_text()
    match = re.search(r'__version__ = ["\'](.+?)["\']', content)
    if not match:
        raise RuntimeError("Cannot find __version__ in valigetta/__init__.py")
    return match.group(1)


setup(
    setup_cfg=True,
    version=get_version(),
)
