from yaml import load as parse
from yaml import FullLoader

def decode(text):
    return parse(text, Loader=FullLoader)

def entry(text):
    return decode(text)
