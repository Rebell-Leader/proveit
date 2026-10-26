"""Hugging Face Space entry point: ProveIt's FastAPI app (judge mode and live mode) on port 7860.

Nemotron runs on Nebius Token Factory, not on this Space's GPU. A minimal Gradio page is mounted at /gradio because
the Space uses the Gradio SDK. The web server starts first so judge mode is up within seconds; curl's history is
cloned in the background, and live mode reports "warming up" until it is ready.
"""

import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path


def log(message: str) -> None:
    print(f"[proveit] {message}", flush=True)


ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("PROVEIT_FETCH", "1")
os.environ.setdefault("PROVEIT_DAILY_BUDGET", "1.00")
CURL = ROOT / "vendor" / "curl"

import spaces  # noqa: E402  (before gradio, as the spaces package requires)
import gradio as gr  # noqa: E402
import uvicorn  # noqa: E402

log("importing the app")
from proveit.web.app import app as proveit_app  # noqa: E402


def prepare_curl() -> None:
    """Clone curl into a temporary directory and move it into place only when complete."""
    if (CURL / ".git").exists():
        log("curl checkout already present")
        return
    partial = CURL.with_name("curl.partial")
    shutil.rmtree(partial, ignore_errors=True)
    partial.parent.mkdir(parents=True, exist_ok=True)
    log("cloning curl (full history, about 140 MB)")
    result = subprocess.run(["git", "clone", "--quiet", "https://github.com/curl/curl.git", str(partial)])
    if result.returncode != 0:
        log(f"clone failed with exit code {result.returncode}; live mode stays off")
        return
    partial.rename(CURL)
    log("curl checkout ready; live mode is on")


@spaces.GPU(duration=10)
def unused_gpu_hook() -> str:
    """ZeroGPU Spaces must declare a GPU function. ProveIt never calls it: Nemotron runs on Token Factory."""
    return "unused"


# ZeroGPU registers GPU functions from inside gr.Blocks.launch(). We serve with uvicorn instead of launch(), so run the
# same startup report here; without it the Space stops with "No @spaces.GPU function detected during startup".
_zero = getattr(spaces, "zero", None)
if _zero is not None and hasattr(_zero, "startup"):
    log("ZeroGPU startup report")
    _zero.startup()
    log("ZeroGPU startup report done")

threading.Thread(target=prepare_curl, daemon=True).start()

with gr.Blocks(title="ProveIt") as demo:
    gr.Markdown("ProveIt is served at the root of this Space: [open it](/).")

app = gr.mount_gradio_app(proveit_app, demo, path="/gradio")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "7860"))
    log(f"serving on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
