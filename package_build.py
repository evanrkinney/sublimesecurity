# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#!/usr/bin/env python3
"""Wrapper around ``soarapps package build`` that injects a legacy-spawn
entry-point shim into the .tgz so SOAR builds still using the pre-SDK-3.x
spawn (``BaseConnector.__subclasses__()[0]``) can launch the app. New SOAR
builds use ``main_module: src.app:app`` from the manifest directly and
ignore the shim.
"""

import os
import re
import sys
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path

from soar_sdk.cli.cli import app as cli_app  # noqa: E402

_LEGACY_SHIM_SOURCE = '''\
"""Legacy-spawn entry point for SOAR builds predating SDK 3.x dispatch.

Splunk SOAR's legacy ``spawn3`` launcher imports this file, then locates the
connector class via ``BaseConnector.__subclasses__()[0]`` and instantiates it.
Newer SOAR builds dispatch directly through the manifest's ``main_module``
field (``src.app:app``) and never touch this module.

This shim:

  1. Inserts the app install directory onto ``sys.path`` so ``src.app`` is
     importable.
  2. Defines a ``BaseConnector`` subclass BEFORE importing the SDK app, so
     ``__subclasses__()[0]`` returns this class (not ``soar_sdk``'s internal
     ``ActionsManager``) — Python orders ``__subclasses__()`` by class-creation
     time on CPython.
  3. Imports the SDK App instance so all ``@app.action()`` decorators run and
     register their handlers on the App's actions_manager.
  4. Delegates ``_handle_action`` (the legacy spawn entry call) to
     ``App.handle()``, which runs the full SDK 3.x action lifecycle including
     credential decryption, params validation, and result serialization.
"""

import os
import sys


_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


try:
    # Real SOAR runtime provides this.
    from phantom.base_connector import BaseConnector
except ImportError:
    # Dev fallback only — the SDK ships a stub.
    from soar_sdk.shims.phantom.base_connector import BaseConnector


class SublimeSecurityConnector(BaseConnector):
    """Legacy spawn adapter for Sublime Security.

    Defined before the SDK import so that ``BaseConnector.__subclasses__()[0]``
    resolves to us, not to ``soar_sdk.actions_manager.ActionsManager``.
    """

    def _handle_action(self, in_json, handle=None):
        # ``_SDK_APP`` is bound at module load time, after this class is defined.
        return _SDK_APP.handle(in_json, handle)


# Import the SDK app LAST: this registers actions on the App's
# actions_manager and exposes the App instance the shim delegates to.
from src.app import app as _SDK_APP  # noqa: E402
'''


def _shim_filename_from_manifest(manifest_bytes: bytes) -> str:
    import json

    m = json.loads(manifest_bytes)
    return f"{m['package_name']}_connector.py"


def _inject_legacy_shim(tgz_path: Path) -> None:
    """Add the legacy-spawn shim into the .tgz at the package root.

    The SDK's ``soarapps package build`` only packages ``src/``, logos,
    templates, README/LICENSE/NOTICE, release_notes, and wheels — it does not
    include arbitrary top-level Python files. We post-process the .tgz to add
    our shim at ``<App Name>/<package_name>_connector.py``.
    """
    if not tgz_path.exists():
        raise SystemExit(f"Expected built package at {tgz_path}, not found.")

    with tarfile.open(tgz_path, "r:gz") as src_tar:
        members = src_tar.getmembers()
        top_dirs = sorted({m.name.split("/", 1)[0] for m in members if "/" in m.name})
        if not top_dirs:
            raise SystemExit(
                f"Could not detect app root inside {tgz_path}. Members: "
                f"{[m.name for m in members[:5]]}..."
            )
        if len(top_dirs) > 1:
            raise SystemExit(f"Multiple top-level dirs found in {tgz_path}: {top_dirs}")
        app_root = top_dirs[0]

        manifest_member = src_tar.getmember(f"{app_root}/manifest.json")
        manifest_fh = src_tar.extractfile(manifest_member)
        if manifest_fh is None:
            raise SystemExit("Could not read manifest.json from existing tarball.")
        manifest_bytes = manifest_fh.read()

        shim_filename = _shim_filename_from_manifest(manifest_bytes)
        shim_path_in_tar = f"{app_root}/{shim_filename}"

        if any(m.name == shim_path_in_tar for m in members):
            print(f"  (shim already present at {shim_path_in_tar}; skipping inject)")
            return

        shim_bytes = _LEGACY_SHIM_SOURCE.encode("utf-8")

        tmp_fd, tmp_name = tempfile.mkstemp(suffix=".tgz", dir=str(tgz_path.parent))
        os.close(tmp_fd)
        tmp_path = Path(tmp_name)

        try:
            with tarfile.open(tmp_path, "w:gz") as out_tar:
                for m in members:
                    if m.isfile():
                        data = src_tar.extractfile(m)
                        out_tar.addfile(m, data)
                    else:
                        out_tar.addfile(m)

                info = tarfile.TarInfo(shim_path_in_tar)
                info.size = len(shim_bytes)
                info.mode = 0o644
                out_tar.addfile(info, BytesIO(shim_bytes))

            tmp_path.replace(tgz_path)
        except Exception:
            try:
                tmp_path.unlink()
            except OSError:
                pass
            raise

    print(
        f"  Injected legacy-spawn shim → {shim_path_in_tar} ({len(shim_bytes)} bytes)"
    )


def _output_path_from_argv() -> Path | None:
    argv = sys.argv
    for i, arg in enumerate(argv):
        if arg in ("-o", "--output-file") and i + 1 < len(argv):
            return Path(argv[i + 1]).resolve()
        m = re.match(r"^--output-file=(.+)$", arg)
        if m:
            return Path(m.group(1)).resolve()
    return None


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Keep the committed artifact name stable across rebuilds.
        sys.argv.extend(["package", "build", "-o", "sublimesecurity.tgz"])

    output_path_hint = _output_path_from_argv()
    is_build = "build" in sys.argv

    cli_exit_code = 0
    try:
        cli_app()
    except SystemExit as e:
        cli_exit_code = int(e.code) if e.code is not None else 0

    if cli_exit_code != 0 or not is_build:
        sys.exit(cli_exit_code)

    if output_path_hint and output_path_hint.exists():
        produced = output_path_hint
    else:
        candidates = sorted(
            Path.cwd().glob("*.tgz"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not candidates:
            print("WARNING: could not find produced .tgz to inject legacy shim into.")
            sys.exit(0)
        produced = candidates[0]

    print(f"Post-build: injecting legacy-spawn shim into {produced.name}...")
    _inject_legacy_shim(produced)
    sys.exit(0)
