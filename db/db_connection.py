from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy_utils import database_exists, create_database

def get_engine(config: dict):
    keys = ['user', 'host', 'port', 'db', 'password']
    for key in keys:
        if key not in config.keys():
            raise Exception('bad config')
    else:
        user, password, host, port, db = (config['user'], config['password'],
                                           config['host'], config['port'], config['db'])
    
    url = f'postgresql://{user}:{password}@{host}:{port}/{db}'
    if not database_exists(url):
        create_database(url)
    engine = create_engine(url, pool_size=10, echo=False)
    return engine

def get_session(engine):
    session = sessionmaker(bind=engine)
    return session()

def initialize_database():
    from db.schema import Base
    from config.settings import DATABASE_CONFIG
    
    engine = get_engine(DATABASE_CONFIG)
    Base.metadata.create_all(engine)

    return get_session(engine)
