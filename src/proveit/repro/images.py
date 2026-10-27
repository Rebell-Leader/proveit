"""Sandbox images: a build toolchain, then curl built with AddressSanitizer and UBSan at one release.

Each image is a saved Sandboxes checkpoint found again by tag, so a release is built once and every report against
it starts from the same immutable filesystem. Builds are the only runs with networking on: they download Debian
packages and curl's release tarball. Report PoCs run from these images with networking off (see stage.py).
"""

from __future__ import annotations

import datetime as dt
import re

from proveit.grounding.extract import extract
from proveit.grounding.repo import Repo
from proveit.repro.sandbox import Sandboxes

BASE_IMAGE = "gcc:14"  # public Sandboxes image: Debian trixie with GCC 14, Python 3 and common -dev packages
TOOLCHAIN_TAG = "proveit-toolchain-v2"
PACKAGES = ("cmake ninja-build libssl-dev zlib1g-dev libnghttp2-dev libssh2-1-dev libpsl-dev libidn2-dev "
            "libzstd-dev libbrotli-dev openssl")
SANITIZE = "-fsanitize=address,undefined -fno-omit-frame-pointer"

# curl is built with CMake, not autotools: this sandbox breaks autoconf's `cat confdefs.h - <<EOF` conftest writes
# ("cat: write error: Bad file descriptor"), so ./configure always fails here. CMake does not use shell heredocs.
# The image's own curl and libcurl headers are purged, so a PoC can only build against the sanitized curl under test.
# cc-curl compiles one C file against it: cc-curl -o poc poc.c  (AddressSanitizer and UBSan already on).
INSTALL_TOOLCHAIN = f"""set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends {PACKAGES} > /tmp/apt.log 2>&1 || {{ tail -40 /tmp/apt.log; exit 1; }}
apt-get purge -y -qq curl 'libcurl*-dev' > /tmp/purge.log 2>&1 || true
rm -rf /var/lib/apt/lists/*
printf '%s\\n' '#!/bin/sh' \\
  'exec cc "$@" -I/opt/curl/include -g -O0 {SANITIZE} $(/opt/curl/bin/curl-config --static-libs) {SANITIZE}' \\
  > /usr/local/bin/cc-curl
chmod +x /usr/local/bin/cc-curl
cmake --version | head -1
"""

# Release tarballs carry CMakeLists.txt. One recipe builds every release with CMake support (curl 7.x onward).
BUILD_CURL = """set -e
mkdir -p /src && cd /src
wget -q -O curl.tar.gz "https://curl.se/download/curl-{v}.tar.gz" \\
  || wget -q -O curl.tar.gz "https://github.com/curl/curl/releases/download/{tag}/curl-{v}.tar.gz"
tar xzf curl.tar.gz && rm curl.tar.gz && mv curl-{v} curl && cd curl
cmake -G Ninja -B build -DCMAKE_INSTALL_PREFIX=/opt/curl -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=ON \\
  -DCURL_USE_OPENSSL=ON -DCURL_DISABLE_LDAP=ON -DBUILD_TESTING=OFF \\
  -DCMAKE_C_FLAGS="-g -O1 {san}" -DCMAKE_EXE_LINKER_FLAGS="{san}" > /tmp/cmake.log 2>&1 \\
  || {{ tail -60 /tmp/cmake.log; exit 1; }}
cmake --build build -j"$(nproc)" > /tmp/build.log 2>&1 || {{ tail -80 /tmp/build.log; exit 1; }}
cmake --install build > /tmp/install.log 2>&1 || {{ tail -40 /tmp/install.log; exit 1; }}
/opt/curl/bin/curl --version | head -1
"""

# What a PoC script can rely on. Kept in one place: the harness prompt describes exactly this.
RUN_ENV = """export PATH=/opt/curl/bin:$PATH
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:symbolize=1 UBSAN_OPTIONS=print_stacktrace=1
"""


def version_of(tag: str) -> str:
    return tag.removeprefix("curl-").replace("_", ".")


def curl_tag(tag: str) -> str:
    return f"proveit-curl-asan-{version_of(tag)}"


# A version named as the one that fixes the bug ("fixed in 8.1.0", "patched in curl 8.2.0") is not the release to
# test: testing it would run the patched code and miss the flaw.
_FIXED_IN = re.compile(r"(?:fixed|patched|resolved|addressed|corrected)\s+(?:in|by|with)\s+(?:curl\s+)?v?(\d+\.\d+(?:\.\d+)?)", re.I)


def target_release(repo: Repo, report: dict) -> str | None:
    """The release to reproduce against: the newest curl version the report names that was out when it was
    submitted (reporters name the version they ran), excluding any version the report calls the fix; else the
    latest release before the submission date."""
    submitted = report.get("submitted_at") or dt.datetime.now(dt.UTC).isoformat()
    dates = dict(repo.release_tags())
    text = f"{report.get('title', '')}\n{report.get('body', '')}"
    ex = extract(report.get("title", ""), report.get("body", ""))
    fixed = {repo.tag_for_version(v) for v in _FIXED_IN.findall(text)}
    named = [t for t in (repo.tag_for_version(v) for v in ex.versions)
             if t and t not in fixed and dates.get(t, "9") <= submitted]
    if named:
        return max(named, key=lambda t: tuple(int(x) for x in re.findall(r"\d+", t)))
    return repo.latest_release_before(submitted)


def toolchain(sb: Sandboxes, log=print) -> str:
    found = sb.image_by_tag(TOOLCHAIN_TAG)
    if found:
        return found
    base = sb.image_by_tag(BASE_IMAGE)
    if not base:
        raise RuntimeError(f"the public image {BASE_IMAGE} is not available to this project")
    log("installing the build toolchain (networking on)")
    r = sb.run(base, INSTALL_TOOLCHAIN, networking=True, disposable=False, timeout=900)
    if not r.ok or not r.result_image:
        raise RuntimeError(f"toolchain setup failed in operation {r.operation}: {(r.stdout + r.stderr)[-1500:]}")
    sb.tag(r.result_image, TOOLCHAIN_TAG)
    return r.result_image


def curl_image(sb: Sandboxes, tag: str, log=print) -> str:
    """The image with curl `tag` built under ASan/UBSan at /opt/curl and its source at /src/curl."""
    name = curl_tag(tag)
    found = sb.image_by_tag(name)
    if found:
        return found
    base = toolchain(sb, log)
    log(f"building {tag} with AddressSanitizer and UBSan (networking on, about 3 minutes)")
    r = sb.run(base, BUILD_CURL.format(v=version_of(tag), tag=tag, san=SANITIZE), networking=True,
               disposable=False, timeout=1800)
    if not r.ok or not r.result_image:
        raise RuntimeError(f"building {tag} failed in operation {r.operation}: {(r.stdout + r.stderr)[-1500:]}")
    sb.tag(r.result_image, name)
    return r.result_image
