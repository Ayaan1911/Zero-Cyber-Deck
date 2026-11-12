"""Create a directory link for tests: real symlink if permitted, else a Windows junction. Returns False if neither works."""
import os
import subprocess
import sys


def make_dir_link(link, target) -> bool:
    link, target = str(link), str(target)
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    if sys.platform == "win32":
        r = subprocess.run(["cmd", "/c", "mklink", "/J", link, target], capture_output=True, text=True)
        return r.returncode == 0
    return False


def make_file_symlink(link, target) -> bool:
    try:
        os.symlink(str(target), str(link))
        return True
    except (OSError, NotImplementedError):
        return False
