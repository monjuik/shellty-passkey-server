"""Build one release archive using VERSION, GOOS and GOARCH from the environment."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def go(*args):
    return subprocess.check_output(["go", *args], cwd=ROOT, text=True)


def runtime_modules():
    # go list emits a stream of JSON objects, one per package.
    data = go("list", "-deps", "-json", "./cmd/web")
    decoder = json.JSONDecoder()
    modules = {}
    while data.strip():
        package, end = decoder.raw_decode(data.lstrip())
        data = data.lstrip()[end:]
        module = package.get("Module", {})
        if module and not module.get("Main"):
            if module.get("Replace"):
                raise RuntimeError("Release dependencies must not use module replacements")
            modules[module["Path"]] = module
    return modules


def copy_licenses(destination):
    destination.mkdir()
    goroot = Path(go("env", "GOROOT").strip())
    # Homebrew keeps the license next to libexec rather than inside GOROOT.
    go_license = next((p for p in (goroot / "LICENSE", goroot.parent / "LICENSE") if p.is_file()), None)
    if go_license is None:
        raise RuntimeError("Go toolchain license not found")
    shutil.copyfile(go_license, destination / "GO-LICENSE")
    shutil.copyfile(ROOT / "assets/static/PICO-LICENSE.md", destination / "PICO-LICENSE.md")
    inventory = ["Runtime module licenses and notices", ""]
    for name, module in sorted(runtime_modules().items()):
        source = Path(module["Dir"])
        target = destination / (name + "@" + module["Version"])
        found = []
        for path in sorted(source.rglob("*")):
            if path.is_file() and re.match(r"^(licen[cs]e|copying|notice|copyright)([._-]|$)", path.name, re.I):
                relative = path.relative_to(source)
                output = target / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, output)
                found.append(relative.as_posix())
        if not found:
            raise RuntimeError(f"No license or notice found for {name}")
        inventory.append(f"{name}@{module['Version']}: {', '.join(found)}")
    (destination / "INDEX.txt").write_text("\n".join(inventory) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-version", action="store_true", help="Execute the built binary (native builds only)")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    version, goos, goarch = (os.environ[key] for key in ("VERSION", "GOOS", "GOARCH"))
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        parser.error("VERSION must be a stable semantic version without v")
    if goos not in ("linux", "darwin", "windows") or goarch not in ("amd64", "arm64"):
        parser.error("Unsupported release platform")
    os.environ["CGO_ENABLED"] = "0"
    name = f"shellty-passkey-server_{version}_{goos}_{goarch}"
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / (name + (".zip" if goos == "windows" else ".tar.gz"))
    if archive.exists():
        parser.error(f"Archive already exists: {archive}")
    with tempfile.TemporaryDirectory(prefix="shellty-release-") as temporary:
        package = Path(temporary) / name
        package.mkdir()
        binary = package / ("passkey-server.exe" if goos == "windows" else "passkey-server")
        go("build", "-trimpath", f"-ldflags=-s -w -X github.com/monjuik/shellty-passkey-server/app.version={version}", "-o", str(binary), "./cmd/web")
        if args.verify_version:
            result = subprocess.run([str(binary), "--version"], capture_output=True, text=True, check=True)
            if result.stdout.strip() != f"passkey-server {version}" or result.stderr:
                raise RuntimeError("Built binary reports an unexpected version")
        for filename in ("README.md", "LICENSE", "config.example.json"):
            shutil.copyfile(ROOT / filename, package / filename)
        shutil.copytree(ROOT / "docs", package / "docs")
        copy_licenses(package / "licenses")
        if goos == "windows":
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
                for path in sorted(package.rglob("*")):
                    if path.is_file():
                        output.write(path, path.relative_to(package.parent))
        else:
            binary.chmod(0o755)
            with tarfile.open(archive, "w:gz") as output:
                output.add(package, arcname=name)
    print(archive)


if __name__ == "__main__":
    main()
