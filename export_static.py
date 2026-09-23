import json
import os
import shutil
from pathlib import Path

from server import UPLOADS, connection, filtered_public


ROOT = Path(__file__).resolve().parent
OUT = Path(os.getenv("STATIC_OUT_DIR", str(ROOT / "static-site"))).resolve()
BASE_PATH = "/" + os.getenv("STATIC_BASE_PATH", "").strip("/") if os.getenv("STATIC_BASE_PATH", "").strip("/") else ""


def copy_file(source: Path, target: Path) -> None:
    if not source.exists() or not source.is_file():
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def prefix_absolute_paths(path: Path) -> None:
    if not BASE_PATH:
        return
    text = path.read_text(encoding="utf-8")
    replacements = {
        'href="/': f'href="{BASE_PATH}/',
        'src="/': f'src="{BASE_PATH}/',
        "url(/": f"url({BASE_PATH}/",
        "'/api/": f"'{BASE_PATH}/api/",
        '"/api/': f'"{BASE_PATH}/api/',
        "`/api/": f"`{BASE_PATH}/api/",
        "'/api/public'": f"'{BASE_PATH}/api/public'",
        '"/api/public"': f'"{BASE_PATH}/api/public"',
        "openWindow('/')": f"openWindow('{BASE_PATH}/')",
        "urls=['/'": f"urls=['{BASE_PATH}/'",
        "scope:'/'}": f"scope:'{BASE_PATH}/'}}",
        "register('/service-worker.js'": f"register('{BASE_PATH}/service-worker.js'",
        "caches.match('/index.html')": f"caches.match('{BASE_PATH}/index.html')",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    if path.name == "service-worker.js":
        text = text.replace("['/','/index.html'", f"['{BASE_PATH}/','{BASE_PATH}/index.html'")
        for asset in ("styles.css", "app.js", "manifest.webmanifest", "favicon.svg", "mis-logo.png", "icon-192.png", "icon-512.png"):
            text = text.replace(f"'/{asset}", f"'{BASE_PATH}/{asset}")
    if path.name == "manifest.webmanifest":
        data = json.loads(text)
        data["id"] = f"{BASE_PATH}/"
        data["start_url"] = f"{BASE_PATH}/"
        data["scope"] = f"{BASE_PATH}/"
        for icon in data.get("icons", []):
            src = icon.get("src", "")
            if src.startswith("/"):
                icon["src"] = f"{BASE_PATH}{src}"
        text = json.dumps(data, ensure_ascii=False, indent=2)
    path.write_text(text, encoding="utf-8")


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

    for name in ("index.html", "404.html", "app.js", "service-worker.js", "manifest.webmanifest", "styles.css"):
        prefix_absolute_paths(OUT / name)

    print(f"Static site exported to {OUT}")


if __name__ == "__main__":
    main()
