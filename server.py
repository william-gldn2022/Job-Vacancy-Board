from waitress import serve
from JVB import create_app
if __name__ == "__main__":
    serve(create_app(), host="0.0.0.0", port=5000)