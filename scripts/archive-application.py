import gzip
import os
import stat
import sys
import tarfile
from pathlib import Path


def archive_application(bundle, output, epoch):
    with output.open("wb") as destination:
        with gzip.GzipFile(filename="", fileobj=destination, mode="wb", mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for path in [bundle, *sorted(bundle.rglob("*"))]:
                    mode = path.lstat().st_mode
                    entry = tarfile.TarInfo(path.relative_to(bundle.parent).as_posix())
                    entry.mtime = epoch
                    entry.uname = "root"
                    entry.gname = "wheel"
                    if stat.S_ISDIR(mode):
                        entry.type = tarfile.DIRTYPE
                        entry.mode = 0o755
                        archive.addfile(entry)
                    elif stat.S_ISREG(mode):
                        entry.mode = 0o755 if mode & 0o111 else 0o644
                        with path.open("rb") as source:
                            entry.size = os.fstat(source.fileno()).st_size
                            archive.addfile(entry, source)
                    else:
                        raise ValueError(f"Unexpected bundle entry {path}")


archive_application(Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3]))
