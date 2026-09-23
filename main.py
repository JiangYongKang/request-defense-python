"""FastAPI service with the local, reproducible request-defense layer.

Startup policy (see defense.factory.add_defense_safely):
* env ``REQUEST_DEFENSE_CONFIG`` (default: ``defense_config.json``) points at
  the JSON config. If that file is absent, safe defaults are used.
* If the file exists but is invalid, the service starts in fail-safe mode:
  a CRITICAL alarm is raised, rate limiting stays ON and blocking rules are
  empty (protection is never silently switched off).
* Set ``REQUEST_DEFENSE_STRICT=1`` to fail fast instead.
"""

import logging
import os

from fastapi import FastAPI

from defense.config import DEFAULT_CONFIG_PATH
from defense.factory import add_defense_safely

logging.basicConfig(
    level=os.environ.get("DEFENSE_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

app = FastAPI(title="request-defense-python")

_CONFIG_PATH = os.environ.get("REQUEST_DEFENSE_CONFIG", DEFAULT_CONFIG_PATH)
# Policy:
#   * missing config file      -> safe defaults (rate limiting ON, no rules)
#   * present but invalid file -> CRITICAL alarm + safe defaults (service
#     stays up; protection is never silently switched off)
#   * REQUEST_DEFENSE_STRICT=1 -> fail fast instead (hardened deployments)
defense_config, _config_error = add_defense_safely(
    app,
    _CONFIG_PATH,
    strict=os.environ.get("REQUEST_DEFENSE_STRICT", "0") == "1",
)


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/health")
def health():
    return {"status": "ok"}
