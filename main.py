from config.utils import install_requirements

if __name__ == "__main__":
    install_requirements()
    from server.server import server
    server(None)
