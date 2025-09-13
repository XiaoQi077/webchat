import os


class Config:
    # 基础配置
    SECRET_KEY = 'your-secret-key-here'  # 生产环境应使用更安全的密钥
    DATA_DIR = os.path.join(os.getcwd(), 'data')
    DATABASE_PATH = os.path.join(DATA_DIR, 'database.db')
    FILES_DIR = os.path.join(DATA_DIR, 'files')
    LOGS_DIR = os.path.join(DATA_DIR, 'logs')
    CERTS_DIR = os.path.join(DATA_DIR, 'certs')

    # 文件上传配置
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB最大文件大小
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}

    # SocketIO配置
    SOCKETIO_ASYNC_MODE = 'threading'