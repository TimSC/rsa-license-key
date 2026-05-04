#!/usr/bin/env python3
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent


def run_tool(workdir, tool, input_text="", args=(), expect_success=True):
    proc = subprocess.run(
        [str(ROOT_DIR / tool), *args],
        input=input_text,
        text=True,
        cwd=workdir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if expect_success and proc.returncode != 0:
        raise AssertionError(
            f"{tool} failed with exit code {proc.returncode}\n{proc.stdout}"
        )
    if not expect_success and proc.returncode == 0:
        raise AssertionError(f"{tool} unexpectedly succeeded\n{proc.stdout}")
    return proc


def assert_file_exists(path):
    if not path.is_file():
        raise AssertionError(f"missing expected file: {path}")


def assert_file_absent(path):
    if path.exists():
        raise AssertionError(f"unexpected file exists: {path}")


def test_ed25519_flow(tmp_root):
    workdir = tmp_root / "ed25519"
    workdir.mkdir()

    run_tool(workdir, "genmasterpair", "masterpass\n")
    run_tool(workdir, "gensecondarypair", "masterpass\nsecondarypass\n")
    run_tool(workdir, "genlicense", "secondarypass\nLicensed to BOB\n")
    run_tool(workdir, "genxmllicense", "secondarypass\n")

    verify = run_tool(workdir, "verifylicense")
    if "Secondary Ed25519 Key OK" not in verify.stdout:
        raise AssertionError(verify.stdout)
    if "License Ed25519 Signature OK" not in verify.stdout:
        raise AssertionError(verify.stdout)

    verify_xml = run_tool(workdir, "verifyxmllicense")
    if "Info Ed25519 signature ret:1" not in verify_xml.stdout:
        raise AssertionError(verify_xml.stdout)
    if "Key Ed25519 signature ret:1" not in verify_xml.stdout:
        raise AssertionError(verify_xml.stdout)

    assert_file_exists(workdir / "master-ed25519-privkey-enc.txt")
    assert_file_exists(workdir / "master-ed25519-privkey-enc.txt.salt")
    assert_file_exists(workdir / "secondary-ed25519-privkey-enc.txt")
    assert_file_exists(workdir / "secondary-ed25519-privkey-enc.txt.salt")
    assert_file_exists(workdir / "license-ed25519-sig.txt")
    assert_file_absent(workdir / "master-privkey-enc.txt")
    assert_file_absent(workdir / "license-sig.txt")


def test_rsa_flow(tmp_root):
    workdir = tmp_root / "rsa"
    workdir.mkdir()

    run_tool(workdir, "genmasterpair", "masterpass\n", args=("--rsa",))
    run_tool(workdir, "gensecondarypair", "masterpass\nsecondarypass\n")
    run_tool(workdir, "genlicense", "secondarypass\nLicensed to BOB\n")
    run_tool(workdir, "genxmllicense", "secondarypass\n")

    verify = run_tool(workdir, "verifylicense")
    if "Secondary RSA-PSS Key OK" not in verify.stdout:
        raise AssertionError(verify.stdout)
    if "License RSA-PSS Signature OK" not in verify.stdout:
        raise AssertionError(verify.stdout)

    verify_xml = run_tool(workdir, "verifyxmllicense")
    if "Info RSA-PSS signature ret:1" not in verify_xml.stdout:
        raise AssertionError(verify_xml.stdout)
    if "Key RSA-PSS signature ret:1" not in verify_xml.stdout:
        raise AssertionError(verify_xml.stdout)

    assert_file_exists(workdir / "master-privkey-enc.txt")
    assert_file_exists(workdir / "master-privkey-enc.txt.salt")
    assert_file_exists(workdir / "secondary-privkey-enc.txt")
    assert_file_exists(workdir / "secondary-privkey-enc.txt.salt")
    assert_file_exists(workdir / "license-sig.txt")
    assert_file_absent(workdir / "master-ed25519-privkey-enc.txt")
    assert_file_absent(workdir / "license-ed25519-sig.txt")


def test_tampered_private_key_fails(tmp_root):
    workdir = tmp_root / "tamper"
    workdir.mkdir()

    run_tool(workdir, "genmasterpair", "masterpass\n")
    run_tool(workdir, "gensecondarypair", "masterpass\nsecondarypass\n")

    with (workdir / "secondary-ed25519-privkey-enc.txt").open("a") as key_file:
        key_file.write("AA")

    proc = run_tool(
        workdir,
        "genlicense",
        "secondarypass\nLicensed to BOB\n",
        expect_success=False,
    )
    if "MAC not valid" not in proc.stdout:
        raise AssertionError(proc.stdout)


def main():
    tmp_root = Path(tempfile.mkdtemp(prefix="rsa-license-key-tests."))
    try:
        test_ed25519_flow(tmp_root)
        test_rsa_flow(tmp_root)
        test_tampered_private_key_fails(tmp_root)
    finally:
        shutil.rmtree(tmp_root)

    print("basic tests passed")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as err:
        print(err, file=sys.stderr)
        sys.exit(1)
