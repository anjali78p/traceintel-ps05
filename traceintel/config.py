import copy
from pathlib import Path
import yaml

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config.yaml"


def _merge(base, over):
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def load_config(path=None, overrides=None):
    with open(path or DEFAULT_PATH, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if overrides:
        cfg = _merge(copy.deepcopy(cfg), overrides)
    return cfg
