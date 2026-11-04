import yaml

def entry(text):
    if "!!python/" in text:
        raise ValueError("tag rejected by application guard")
    return yaml.load(text, Loader=yaml.FullLoader)
