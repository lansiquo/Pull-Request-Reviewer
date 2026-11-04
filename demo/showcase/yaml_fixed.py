# Trusted analysis sample. The demo never parses this YAML input.
import yaml


def read_settings(text):
    if not isinstance(text, str) or len(text) > 4096:
        raise ValueError('Settings must be a small text document')
    settings = yaml.safe_load(text)
    if not isinstance(settings, dict) or set(settings) != {'name', 'retries'}:
        raise ValueError('Expected only name and retries')
    if not isinstance(settings['name'], str) or not 1 <= len(settings['name']) <= 80:
        raise ValueError('Name must be 1-80 characters')
    if type(settings['retries']) is not int or not 0 <= settings['retries'] <= 5:
        raise ValueError('Retries must be an integer from 0 to 5')
    return settings
