# Trusted analysis sample. The demo never parses this YAML input.
import yaml


def read_settings(text):
    return yaml.load(text, Loader=yaml.Loader)
