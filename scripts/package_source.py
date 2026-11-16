"""Build a portable source ZIP without model data, credentials or environments."""
from pathlib import Path
import os
import re
import zipfile

ROOT=Path(__file__).resolve().parents[1]
EXCLUDED={".local_ai",".venv","__pycache__",".pytest_cache",".git",".private","work","uploads","captures"}


def package(destination=None):
    destination=Path(destination) if destination else ROOT.parent/"PacketScope_Dashboard_V1.zip"
    files=[]
    configured=os.environ.get("GEMINI_API_KEY","").encode()
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative=path.relative_to(ROOT)
        if EXCLUDED.intersection(relative.parts) or path.suffix in (".pyc",".dpapi",".key",".pem",".zip",".part"):
            continue
        if path.name=="secrets.toml" or path.name.startswith(".env") or path.resolve()==destination.resolve():
            continue
        raw=path.read_bytes()
        if (configured and configured in raw) or re.search(rb"(?:AQ\.[A-Za-z0-9_-]{30,}|AIza[A-Za-z0-9_-]{30,})",raw):
            raise RuntimeError(f"Possible credential detected in {relative}; archive was not written.")
        files.append(path)
    partial=destination.with_suffix(".zip.part")
    with zipfile.ZipFile(partial,"w",zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(files):
            bundle.write(path,Path("traffic_dashboard")/path.relative_to(ROOT))
    with zipfile.ZipFile(partial) as bundle:
        if bundle.testzip() is not None:
            raise RuntimeError("Archive verification failed.")
    partial.replace(destination)
    return destination,len(files)


if __name__=="__main__":
    path,count=package()
    print(f"Verified source archive: {count} files, {path.stat().st_size:,} bytes.")
