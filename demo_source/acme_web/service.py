from acme_router.routing import dispatch


def handle_request(message):
    return dispatch(message)
