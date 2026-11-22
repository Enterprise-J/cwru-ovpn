import hashlib
import os
import stat
import sys
from pathlib import Path


def tree_digest(root, excluded):
    def raise_walk_error(error):
        raise error

    digest = hashlib.sha256()
    for base, directories, files in os.walk(root, onerror=raise_walk_error, followlinks=False):
        if Path(base) == root:
            directories[:] = [name for name in directories if name not in excluded]
            files = [name for name in files if name not in excluded]
        directories.sort()
        for name in sorted(directories + files):
            path = Path(base, name)
            mode = path.lstat().st_mode
            if stat.S_ISREG(mode):
                content = hashlib.sha256(path.read_bytes()).digest()
                kind = b"x" if mode & 0o111 else b"f"
            elif stat.S_ISLNK(mode):
                content = os.fsencode(os.readlink(path))
                kind = b"l"
            elif stat.S_ISDIR(mode):
                content = b""
                kind = b"d"
            else:
                raise ValueError(f"Unsupported source entry {path}")
            for field in (os.fsencode(path.relative_to(root)), kind, content):
                digest.update(len(field).to_bytes(8, "big"))
                digest.update(field)
    return digest.hexdigest()


print(tree_digest(Path(sys.argv[1]).resolve(strict=True), set(sys.argv[2:])))
