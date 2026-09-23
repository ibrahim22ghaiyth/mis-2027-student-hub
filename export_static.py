import json
import shutil
from pathlib import Path

from server import UPLOADS, connection, filtered_public


ROOT = Path(__file__).resolve().parent
OUT = ROOT / "static-site"


def copy_file(source: Path, target: Path) -> None:
    if not source.exists() or not source.is_file():
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    for item in (ROOT / "web").iterdir():
        target = OUT / item.name
        if item.is_dir():
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)

    index = (OUT / "index.html").read_text(encoding="utf-8")
    index = index.replace(
        '<script defer src="/app.js?v=20260924e-student-hub-v5"></script>',
        '<script>window.MIS_STATIC_DEPLOY=true;</script>\n  <script defer src="/app.js?v=20260924e-student-hub-v5"></script>',
    )
    (OUT / "index.html").write_text(index, encoding="utf-8")
    shutil.copy2(OUT / "index.html", OUT / "404.html")
    write_text(OUT / ".nojekyll", "")

    with connection() as c:
        public = filtered_public(c)
        write_text(OUT / "api" / "public", json.dumps(public, ensure_ascii=False, separators=(",", ":")))

        lectures = c.execute("SELECT id,file_path FROM lectures WHERE file_path<>''").fetchall()
        explanations = c.execute("SELECT id,file_path FROM explanations WHERE file_path<>''").fetchall()

    for row in lectures:
        source = UPLOADS / row["file_path"]
        copy_file(source, OUT / "api" / "files" / str(row["id"]))

    for row in explanations:
        source = UPLOADS / row["file_path"]
        copy_file(source, OUT / "api" / "explanation-files" / str(row["id"]))
        copy_file(source, OUT / "api" / "explanation-preview" / str(row["id"]))

    print(f"Static site exported to {OUT}")


if __name__ == "__main__":
    main()
