import yaml

def entry(text):
    return yaml.load(text, Loader=yaml.FullLoader)
