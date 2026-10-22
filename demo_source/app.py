from acme_web.service import handle_request


def main():
    return handle_request("untrusted-data")


if __name__ == "__main__":
    main()
