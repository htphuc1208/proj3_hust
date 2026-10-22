from acme_unsafe.parser import parse_untrusted


def dispatch(message):
    return parse_untrusted(message)
