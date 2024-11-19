import os, dotenv
dotenv.load_dotenv()

DATABASE_CONFIG = {
    'user': os.getenv('db_user'),
    'password': os.getenv('db_password'),
    'host': os.getenv('db_host'),
    'port': os.getenv('db_port'),
    'db': os.getenv('db')
}



