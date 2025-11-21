"""Desktop wrapper that hosts the Flask web app inside a native window via pywebview."""

from __future__ import annotations

import os
import threading
import time
import urllib.request

import webview

from .webapp import run as run_webapp


DEFAULT_HOST = os.getenv("BACNET_UI_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.getenv("BACNET_UI_PORT", "8000"))
SERVER_START_TIMEOUT = float(os.getenv("BACNET_UI_WAIT", "30"))
DEFAULT_TITLE = os.getenv("BACNET_UI_TITLE", "Triton Edge Data Gateway")


def _wait_for_server(url: str, timeout: float) -> bool:
  """Poll the Flask server until it responds or the timeout elapses."""
  deadline = time.time() + timeout
  while time.time() < deadline:
    try:
      with urllib.request.urlopen(url, timeout=2):
        return True
    except Exception:
      time.sleep(0.5)
  return False


def main() -> None:
  host = DEFAULT_HOST
  port = DEFAULT_PORT
  url = f"http://{host}:{port}"

  # Run the Flask app on a background thread so the GUI can share the same process.
  server_thread = threading.Thread(target=run_webapp, kwargs={"host": host, "port": port}, daemon=True)
  server_thread.start()

  if not _wait_for_server(url, SERVER_START_TIMEOUT):
    raise RuntimeError(f"Web UI did not start within {SERVER_START_TIMEOUT} seconds at {url}")

  webview.create_window(DEFAULT_TITLE, url)
  webview.start()


if __name__ == "__main__":
  main()
