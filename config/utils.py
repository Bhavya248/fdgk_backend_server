import os, sys, subprocess, bcrypt, json, time, threading,enum
from collections import defaultdict

class json_encoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, enum.Enum):
            return obj.name
        return json.JSONEncoder.default(self, obj)
    
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def check_and_install(package):
    try:
        __import__(package)
    except ImportError:
        install(package)

def install_requirements():
    path = os.getcwd() + "/config/requirements.txt"
    with open(path, encoding='utf-8') as f:
        packages = f.read().splitlines()

    for package in packages:
        if '==' in package:
            package_name = package.split('==')[0]
        elif '>=' in package:
            package_name = package.split('>=')[0]
        elif '>' in package:
            package_name = package.split('>')[0]
        elif '<=' in package:
            package_name = package.split('<=')[0]
        elif '<' in package:
            package_name = package.split('<')[0]
        else:
            package_name = package

        check_and_install(package_name)


def get_hash_for_password(password:str):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_hash_for_password(password:str, hash:str):
    return bcrypt.checkpw(password.encode('utf-8'), hash.encode('utf-8'))

def create_response(code, status, message, data=None):
    response = {
        "status": status,
        "code": code,
        "message": message
    }
    if data:
        response["data"] = data
    return json.dumps(response, cls=json_encoder)

class RateLimiter:
    def manage_limiter(self):
        while True:
            time.sleep(self.duration)
            self.ts = time.time()
            with self.lock:
                for rns_id in list(self.requests.keys()):
                    self.requests[rns_id] = [t for t in self.requests[rns_id] if t > self.ts - self.duration]
                    if not self.requests[rns_id]:
                        del self.requests[rns_id]

    def __init__(self, name, _calls, _duration):  # duration in seconds
        self.__name__ = name
        self.calls = _calls
        self.duration = _duration
        self.ts = time.time()
        self.requests = defaultdict(list)
        self.lock = threading.Lock()
        _thread = threading.Thread(target=self.manage_limiter, daemon=True)
        _thread.start()

    def handle_request(self, rns_id):
        with self.lock:
            self.requests[rns_id] = [t for t in self.requests[rns_id] if t > self.ts - self.duration]
            if len(self.requests[rns_id]) >= self.calls:
                return False
            else:
                self.requests[rns_id].append(self.ts)
                return True

RESPONSE_CODES = {'200':'RESULT_OK',
                '201': 'RESULT_CREATED',
                '204': 'RESULT_NO_CONTENT',
                '400': 'ERROR_BAD_REQUEST',
                '401': 'ERROR_UNAUTHORIZED',
                '403': 'ERROR_FORBIDDEN', 
                '404': 'ERROR_NOT_FOUND',
                '409': 'ERROR_CONFLICT',
                '429': 'TOO_MANY_REQUESTS',
                '500': 'ERROR_INTERNAL', 
                '503': 'ERROR_SERVICE_UNAVAILABLE',
                '0x00': 'ERROR_INVALID_IDENTITY', 
                '0x01': 'ERROR_INVALID_DATA', 
                '0x02': 'ERROR_INVALID_PARAMETERS', 
                '0x03': 'ERROR_MEMBER_NOT_FOUND', 
                '0x04': 'ERROR_DEVICE_NOT_FOUND', 
                '0x05': 'ERROR_INVITE_CODE_INVALID',
                '0x06': 'ERROR_INVITE_CODE_USED'}
