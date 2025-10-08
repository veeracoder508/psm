import socket


def host_ip():
    try:
        # Get the hostname of the local machine
        hostname = socket.gethostname()

        # Get the IP address associated with the hostname
        ip_address = socket.gethostbyname(hostname)

        return {'hostname':hostname,'localIP':ip_address}

    except socket.error as e:
        return f"An unexpected error occurred: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"