from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import json
from datetime import datetime, timedelta
import time
import logging
from logging.handlers import RotatingFileHandler

# 初始化应用
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['DATA_DIR'] = os.path.join(os.getcwd(), 'data')
app.config['DATABASE_PATH'] = os.path.join(app.config['DATA_DIR'], 'database.db')
app.config['FILES_DIR'] = os.path.join(app.config['DATA_DIR'], 'files')
app.config['LOGS_DIR'] = os.path.join(app.config['DATA_DIR'], 'logs')
app.config['CERTS_DIR'] = os.path.join(app.config['DATA_DIR'], 'certs')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB最大文件大小
app.config['MESSAGES_DIR'] = os.path.join(app.config['DATA_DIR'], 'messages')

# 初始化SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# 初始化登录管理
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 创建必要目录
os.makedirs(app.config['DATA_DIR'], exist_ok=True)
os.makedirs(app.config['FILES_DIR'], exist_ok=True)
os.makedirs(app.config['LOGS_DIR'], exist_ok=True)
os.makedirs(app.config['CERTS_DIR'], exist_ok=True)
os.makedirs(app.config['MESSAGES_DIR'], exist_ok=True)


# 设置日志
def setup_logging():
    # 公共聊天日志
    public_log = logging.getLogger('public_chat')
    public_log.setLevel(logging.INFO)
    public_handler = RotatingFileHandler(
        os.path.join(app.config['LOGS_DIR'], 'public_chat.log'),
        maxBytes=1024 * 1024,
        backupCount=10
    )
    public_log.addHandler(public_handler)

    # 私聊日志
    private_log = logging.getLogger('private_chat')
    private_log.setLevel(logging.INFO)
    private_handler = RotatingFileHandler(
        os.path.join(app.config['LOGS_DIR'], 'private_chat.log'),
        maxBytes=1024 * 1024,
        backupCount=10
    )
    private_log.addHandler(private_handler)

    # 文件下载日志
    download_log = logging.getLogger('file_download')
    download_log.setLevel(logging.INFO)
    download_handler = RotatingFileHandler(
        os.path.join(app.config['LOGS_DIR'], 'file_download.log'),
        maxBytes=1024 * 1024,
        backupCount=10
    )
    download_log.addHandler(download_handler)

    # 系统日志
    system_log = logging.getLogger('system')
    system_log.setLevel(logging.INFO)
    system_handler = RotatingFileHandler(
        os.path.join(app.config['LOGS_DIR'], 'system.log'),
        maxBytes=1024 * 1024,
        backupCount=10
    )
    system_log.addHandler(system_handler)


setup_logging()


# 用户类
class User(UserMixin):
    def __init__(self, id, username, is_admin=False, approved=False,
                 can_public_chat=True, can_private_chat=True, can_download=True, can_upload=True,
                 can_create_group=True, nickname=None, avatar=None):
        self.id = id
        self.username = username
        self.nickname = nickname or username
        self.avatar = avatar or '/static/images/default_avatar.png'
        self.is_admin = is_admin
        self.approved = approved
        self.can_public_chat = can_public_chat
        self.can_private_chat = can_private_chat
        self.can_download = can_download
        self.can_upload = can_upload
        self.can_create_group = can_create_group


# 存储在线用户和连接信息
online_users = {}  # {user_id: {'sid': sid, 'last_seen': timestamp, 'username': username}}
unread_messages = {}  # {user_id: {target_id: [message1, message2, ...]}}
unread_counts = {}  # {user_id: {target_type: {target_id: count}}}


# 数据库操作函数
def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE_PATH'])
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """初始化数据库"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # 创建用户表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            nickname TEXT,
            avatar TEXT DEFAULT '/static/images/default_avatar.png',
            is_admin BOOLEAN DEFAULT FALSE,
            approved BOOLEAN DEFAULT FALSE,
            can_public_chat BOOLEAN DEFAULT TRUE,
            can_private_chat BOOLEAN DEFAULT TRUE,
            can_download BOOLEAN DEFAULT TRUE,
            can_upload BOOLEAN DEFAULT TRUE,
            can_create_group BOOLEAN DEFAULT TRUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        # 检查并添加可能缺失的列
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]

        columns_to_add = [
            ('nickname', 'TEXT'),
            ('avatar', 'TEXT DEFAULT \'/static/images/default_avatar.png\''),
            ('can_create_group', 'BOOLEAN DEFAULT TRUE')
        ]

        for column_name, column_type in columns_to_add:
            if column_name not in columns:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {column_name} {column_type}")
                print(f"Added {column_name} column to users table")

        # 创建消息表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER,
            group_id INTEGER,
            content TEXT NOT NULL,
            message_type TEXT NOT NULL,
            read_status BOOLEAN DEFAULT FALSE,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id)
        )
        ''')

        # 创建群组表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            creator_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (creator_id) REFERENCES users (id)
        )
        ''')

        # 创建群组成员表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (group_id) REFERENCES groups (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')

        # 创建日志表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action_type TEXT NOT NULL,
            target TEXT,
            details TEXT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')

        # 检查并添加可能缺失的列
        cursor.execute("PRAGMA table_info(logs)")
        log_columns = [column[1] for column in cursor.fetchall()]

        if 'ip_address' not in log_columns:
            cursor.execute("ALTER TABLE logs ADD COLUMN ip_address TEXT")
            print("Added ip_address column to logs table")

        # 创建默认管理员账户
        admin_exists = cursor.execute(
            "SELECT id FROM users WHERE username = 'admin'"
        ).fetchone()

        if not admin_exists:
            cursor.execute(
                "INSERT INTO users (username, password_hash, is_admin, approved, nickname) VALUES (?, ?, ?, ?, ?)",
                ('admin', generate_password_hash('admin123'), True, True, 'Administrator')
            )
            print("Created default admin account: admin/admin123")

        conn.commit()
        conn.close()
        print("Database initialized successfully")

    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        import traceback
        traceback.print_exc()


# 初始化数据库
init_db()


@login_manager.user_loader
def load_user(user_id):
    """加载用户"""
    try:
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()
        conn.close()

        if user:
            # 安全地获取用户属性，处理可能不存在的字段
            nickname = user['nickname'] if 'nickname' in user.keys() else user['username']
            avatar = user['avatar'] if 'avatar' in user.keys() else '/static/images/default_avatar.png'
            can_create_group = user['can_create_group'] if 'can_create_group' in user.keys() else True

            return User(
                id=user['id'],
                username=user['username'],
                nickname=nickname,
                avatar=avatar,
                is_admin=user['is_admin'],
                approved=user['approved'],
                can_public_chat=user['can_public_chat'],
                can_private_chat=user['can_private_chat'],
                can_download=user['can_download'],
                can_upload=user['can_upload'],
                can_create_group=can_create_group
            )
        return None
    except Exception as e:
        print(f"Error loading user {user_id}: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


# 日志记录函数
def log_action(user_id, action_type, target=None, details=None):
    """记录用户操作日志"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # 获取用户名
        username = conn.execute(
            "SELECT username FROM users WHERE id = ?", (user_id,)
        ).fetchone()

        if username:
            username = username[0]
        else:
            username = "unknown"

        # 获取客户端IP
        ip_address = request.remote_addr if request else 'unknown'

        # 记录到数据库
        cursor.execute(
            "INSERT INTO logs (user_id, action_type, target, details, ip_address) VALUES (?, ?, ?, ?, ?)",
            (user_id, action_type, target, details, ip_address)
        )

        conn.commit()
        conn.close()

        # 记录到文件日志
        log_entry = f"{datetime.now()} - UserID:{user_id} - Username:{username} - {action_type} - Target:{target} - Details:{details} - IP:{ip_address}\n"

        # 根据操作类型选择日志文件
        if action_type in ['public_message', 'join_public_chat', 'leave_public_chat']:
            log_file = os.path.join(app.config['LOGS_DIR'], 'public_chat.log')
        elif action_type in ['private_message', 'start_private_chat']:
            log_file = os.path.join(app.config['LOGS_DIR'], 'private_chat.log')
        elif action_type in ['download_file', 'upload_file']:
            log_file = os.path.join(app.config['LOGS_DIR'], 'file_download.log')
        else:
            log_file = os.path.join(app.config['LOGS_DIR'], 'system.log')

        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry)

        # 输出到控制台
        console_msg = f"\033[1;36m[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {action_type.upper()} - User: {username} - IP: {ip_address}"
        if target:
            console_msg += f" - Target: {target}"
        if details:
            console_msg += f" - Details: {details}"
        console_msg += "\033[0m"

        print(console_msg)

    except Exception as e:
        print(f"Error logging action: {str(e)}")
        import traceback
        traceback.print_exc()


# 保存消息到文件
def save_message_to_file(message_data):
    """将消息保存到文件"""
    try:
        # 按日期创建文件
        date_str = datetime.now().strftime('%Y-%m-%d')
        message_file = os.path.join(app.config['MESSAGES_DIR'], f'messages_{date_str}.log')

        # 格式化消息
        message_type = message_data.get('type', 'unknown')
        sender_name = message_data.get('sender_name', 'unknown')
        content = message_data.get('content', '')
        timestamp = message_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        if message_type == 'private':
            receiver_id = message_data.get('receiver_id')
            log_entry = f"{timestamp} - [PRIVATE] {sender_name} -> User#{receiver_id}: {content}\n"
        elif message_type == 'group':
            group_id = message_data.get('group_id')
            log_entry = f"{timestamp} - [GROUP#{group_id}] {sender_name}: {content}\n"
        else:  # public
            log_entry = f"{timestamp} - [PUBLIC] {sender_name}: {content}\n"

        # 写入文件
        with open(message_file, 'a', encoding='utf-8') as f:
            f.write(log_entry)

    except Exception as e:
        print(f"Error saving message to file: {str(e)}")


# 更新未读消息计数
def update_unread_count(user_id, target_type, target_id, increment=True):
    """更新未读消息计数"""
    if user_id not in unread_counts:
        unread_counts[user_id] = {}

    if target_type not in unread_counts[user_id]:
        unread_counts[user_id][target_type] = {}

    if target_id not in unread_counts[user_id][target_type]:
        unread_counts[user_id][target_type][target_id] = 0

    if increment:
        unread_counts[user_id][target_type][target_id] += 1
    else:
        unread_counts[user_id][target_type][target_id] = 0

    # 发送更新给客户端
    if user_id in online_users:
        emit('unread_update', {
            'target_type': target_type,
            'target_id': target_id,
            'count': unread_counts[user_id][target_type][target_id]
        }, room='user_' + str(user_id))


# 路由定义
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            if user['approved']:
                user_obj = User(
                    id=user['id'],
                    username=user['username'],
                    nickname=user['nickname'] if 'nickname' in user.keys() else user['username'],
                    avatar=user['avatar'] if 'avatar' in user.keys() else '/static/images/default_avatar.png',
                    is_admin=user['is_admin'],
                    approved=user['approved'],
                    can_public_chat=user['can_public_chat'],
                    can_private_chat=user['can_private_chat'],
                    can_download=user['can_download'],
                    can_upload=user['can_upload'],
                    can_create_group=user['can_create_group'] if 'can_create_group' in user.keys() else True
                )
                login_user(user_obj)
                log_action(user['id'], 'login')
                return redirect(url_for('chat'))
            else:
                flash('您的账户尚未通过管理员审核')
        else:
            flash('用户名或密码错误')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    log_action(current_user.id, 'logout')
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('密码确认不匹配')
            return render_template('register.html')

        conn = get_db_connection()

        # 检查用户名是否已存在
        existing_user = conn.execute(
            'SELECT id FROM users WHERE username = ?', (username,)
        ).fetchone()

        if existing_user:
            flash('用户名已存在')
            conn.close()
            return render_template('register.html')

        # 创建新用户
        conn.execute(
            'INSERT INTO users (username, password_hash, approved) VALUES (?, ?, ?)',
            (username, generate_password_hash(password), False)
        )
        conn.commit()
        conn.close()

        flash('注册成功，请等待管理员审核')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/chat')
@login_required
def chat():
    # 获取用户列表
    conn = get_db_connection()
    users = conn.execute(
        'SELECT id, username, nickname, avatar FROM users WHERE approved = 1 ORDER BY username'
    ).fetchall()

    # 获取群组列表
    groups = conn.execute(
        'SELECT g.id, g.name, g.creator_id, u.username as creator_name FROM groups g JOIN users u ON g.creator_id = u.id ORDER BY g.name'
    ).fetchall()

    # 获取用户加入的群组
    user_groups = []
    if current_user.is_authenticated:
        user_groups = conn.execute(
            'SELECT g.id, g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.user_id = ?',
            (current_user.id,)
        ).fetchall()

    conn.close()

    # 获取在线用户列表
    online_user_ids = list(online_users.keys())

    # 获取未读消息计数
    unread_data = unread_counts.get(current_user.id, {})

    return render_template('chat.html',
                           users=users,
                           groups=groups,
                           user_groups=user_groups,
                           online_user_ids=online_user_ids,
                           unread_counts=unread_data)


@app.route('/get_chat_history')
@login_required
def get_chat_history():
    """获取聊天历史记录"""
    chat_type = request.args.get('type', 'public')
    target_id = request.args.get('target_id')

    conn = get_db_connection()

    if chat_type == 'public':
        messages = conn.execute(
            'SELECT m.*, u.username as sender_name FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.message_type = "public" ORDER BY m.timestamp DESC LIMIT 50'
        ).fetchall()
    elif chat_type == 'private':
        messages = conn.execute(
            'SELECT m.*, u.username as sender_name FROM messages m JOIN users u ON m.sender_id = u.id WHERE ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)) AND m.message_type = "private" ORDER BY m.timestamp DESC LIMIT 50',
            (current_user.id, target_id, target_id, current_user.id)
        ).fetchall()
    elif chat_type == 'group':
        messages = conn.execute(
            'SELECT m.*, u.username as sender_name FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.group_id = ? AND m.message_type = "group" ORDER BY m.timestamp DESC LIMIT 50',
            (target_id,)
        ).fetchall()

    conn.close()

    # 转换为字典列表
    messages_list = []
    for msg in reversed(messages):  # 反转顺序，最新的在后面
        messages_list.append({
            'id': msg['id'],
            'sender_id': msg['sender_id'],
            'sender_name': msg['sender_name'],
            'content': msg['content'],
            'timestamp': msg['timestamp'],
            'type': msg['message_type'],
            'read_status': msg['read_status'] if 'read_status' in msg.keys() else False
        })

    return jsonify({'success': True, 'messages': messages_list})


@app.route('/mark_as_read')
@login_required
def mark_as_read():
    """标记消息为已读"""
    chat_type = request.args.get('type', 'public')
    target_id = request.args.get('target_id')

    conn = get_db_connection()

    if chat_type == 'private':
        # 标记私聊消息为已读
        conn.execute(
            'UPDATE messages SET read_status = 1 WHERE receiver_id = ? AND sender_id = ? AND message_type = "private"',
            (current_user.id, target_id)
        )
    elif chat_type == 'group':
        # 标记群组消息为已读
        conn.execute(
            'UPDATE messages SET read_status = 1 WHERE group_id = ? AND message_type = "group"',
            (target_id,)
        )

    conn.commit()
    conn.close()

    # 更新未读计数
    if current_user.id in unread_counts and chat_type in unread_counts[current_user.id]:
        if target_id in unread_counts[current_user.id][chat_type]:
            unread_counts[current_user.id][chat_type][target_id] = 0
            # 发送更新给客户端
            emit('unread_update', {
                'target_type': chat_type,
                'target_id': target_id,
                'count': 0
            }, room='user_' + str(current_user.id))

    return jsonify({'success': True})


@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('您没有管理员权限')
        return redirect(url_for('chat'))

    conn = get_db_connection()

    # 获取用户列表
    users = conn.execute(
        'SELECT id, username, nickname, is_admin, approved, can_public_chat, can_private_chat, can_download, can_upload, can_create_group FROM users ORDER BY username'
    ).fetchall()

    # 获取待审核用户
    pending_users = conn.execute(
        'SELECT id, username, created_at FROM users WHERE approved = 0 ORDER BY created_at'
    ).fetchall()

    # 获取统计信息
    user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    online_count = len(online_users)
    message_count = conn.execute('SELECT COUNT(*) FROM messages').fetchone()[0]

    # 获取日志记录
    logs = conn.execute(
        'SELECT l.*, u.username FROM logs l JOIN users u ON l.user_id = u.id ORDER BY l.timestamp DESC LIMIT 100'
    ).fetchall()

    # 获取文件列表
    files = []
    if os.path.exists(app.config['FILES_DIR']):
        files = os.listdir(app.config['FILES_DIR'])

    # 获取群组列表
    groups = conn.execute(
        'SELECT g.*, u.username as creator_name FROM groups g JOIN users u ON g.creator_id = u.id ORDER BY g.name'
    ).fetchall()

    conn.close()

    return render_template('admin.html',
                           users=users,
                           pending_users=pending_users,
                           user_count=user_count,
                           online_count=online_count,
                           message_count=message_count,
                           file_count=len(files),
                           logs=logs,
                           groups=groups)


@app.route('/admin/update_user', methods=['POST'])
@login_required
def update_user():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': '没有权限'})

    user_id = request.form.get('user_id')
    field = request.form.get('field')
    value = request.form.get('value')

    # 允许的字段列表
    allowed_fields = ['approved', 'is_admin', 'can_public_chat', 'can_private_chat', 'can_download', 'can_upload',
                      'can_create_group']

    if field not in allowed_fields:
        return jsonify({'success': False, 'message': '无效字段'})

    conn = get_db_connection()

    # 处理布尔值
    if value in ['true', 'false']:
        value = 1 if value == 'true' else 0

    conn.execute(
        f'UPDATE users SET {field} = ? WHERE id = ?',
        (value, user_id)
    )
    conn.commit()

    # 获取用户名
    username = conn.execute(
        'SELECT username FROM users WHERE id = ?', (user_id,)
    ).fetchone()['username']

    conn.close()

    log_action(current_user.id, 'update_user', f'{username}.{field}', value)

    return jsonify({'success': True})


@app.route('/admin/update_user_profile', methods=['POST'])
@login_required
def update_user_profile():
    """管理员更新用户资料"""
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': '没有权限'})

    user_id = request.form.get('user_id')
    nickname = request.form.get('nickname')
    avatar = request.form.get('avatar')

    conn = get_db_connection()

    # 检查昵称是否已存在（排除当前用户）
    existing_user = conn.execute(
        'SELECT id FROM users WHERE nickname = ? AND id != ?',
        (nickname, user_id)
    ).fetchone()

    if existing_user:
        conn.close()
        return jsonify({'success': False, 'message': '昵称已存在'})

    # 更新用户资料
    conn.execute(
        'UPDATE users SET nickname = ?, avatar = ? WHERE id = ?',
        (nickname, avatar, user_id)
    )
    conn.commit()

    # 获取用户名
    username = conn.execute(
        'SELECT username FROM users WHERE id = ?', (user_id,)
    ).fetchone()['username']

    conn.close()

    log_action(current_user.id, 'update_user_profile', f'{username}', f'nickname: {nickname}, avatar: {avatar}')

    return jsonify({'success': True, 'message': '用户资料已更新'})


@app.route('/files')
@login_required
def file_list():
    if not current_user.can_download:
        flash('您没有文件下载权限')
        return redirect(url_for('chat'))

    files = []
    if os.path.exists(app.config['FILES_DIR']):
        files = os.listdir(app.config['FILES_DIR'])

    return render_template('file_list.html', files=files)


@app.route('/download/<filename>')
@login_required
def download_file(filename):
    """下载文件"""
    try:
        if not current_user.can_download:
            log_action(current_user.id, 'download_denied', filename, 'Permission denied')
            return "没有下载权限", 403

        file_path = os.path.join(app.config['FILES_DIR'], filename)
        if os.path.exists(file_path):
            log_action(current_user.id, 'download_file', filename, f'Size: {os.path.getsize(file_path)} bytes')
            return send_file(file_path, as_attachment=True)
        else:
            log_action(current_user.id, 'download_failed', filename, 'File not found')
            flash('文件不存在')
            return redirect(url_for('file_list'))

    except Exception as e:
        print(f"Error downloading file {filename}: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('下载文件时发生错误')
        return redirect(url_for('file_list'))


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    """上传文件"""
    try:
        if not current_user.can_upload:
            log_action(current_user.id, 'upload_denied', None, 'Permission denied')
            flash('您没有文件上传权限')
            return redirect(url_for('chat'))

        if request.method == 'POST':
            if 'file' not in request.files:
                flash('没有选择文件')
                return redirect(request.url)

            file = request.files['file']
            if file.filename == '':
                flash('没有选择文件')
                return redirect(request.url)

            # 取消文件格式限制
            if file:
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['FILES_DIR'], filename)
                file.save(file_path)

                log_action(current_user.id, 'upload_file', filename, f'Size: {os.path.getsize(file_path)} bytes')
                flash('文件上传成功')
                return redirect(url_for('file_list'))

        return render_template('upload.html')

    except Exception as e:
        print(f"Error uploading file: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('上传文件时发生错误')
        return redirect(url_for('file_list'))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """用户设置页面"""
    try:
        conn = get_db_connection()

        if request.method == 'POST':
            nickname = request.form.get('nickname')
            avatar = request.form.get('avatar')

            # 检查昵称是否已存在（排除自己）
            if nickname:
                existing_user = conn.execute(
                    'SELECT id FROM users WHERE nickname = ? AND id != ?',
                    (nickname, current_user.id)
                ).fetchone()

                if existing_user:
                    flash('昵称已存在，请选择其他昵称')
                    return redirect(url_for('settings'))

            # 更新用户信息
            conn.execute(
                'UPDATE users SET nickname = ?, avatar = ? WHERE id = ?',
                (nickname, avatar, current_user.id)
            )
            conn.commit()

            log_action(current_user.id, 'update_profile', f'nickname: {nickname}, avatar: {avatar}')
            flash('设置已保存')
            return redirect(url_for('settings'))

        # 获取当前用户信息
        user = conn.execute(
            'SELECT * FROM users WHERE id = ?', (current_user.id,)
        ).fetchone()

        conn.close()

        return render_template('settings.html', user=user)

    except Exception as e:
        print(f"Error in settings: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('保存设置时发生错误')
        return redirect(url_for('settings'))


@app.route('/create_group', methods=['POST'])
@login_required
def create_group():
    """创建群组"""
    if not current_user.can_create_group:
        return jsonify({'success': False, 'message': '您没有创建群组的权限'})

    group_name = request.form.get('group_name')

    if not group_name:
        return jsonify({'success': False, 'message': '群组名称不能为空'})

    conn = get_db_connection()

    # 检查群组名称是否已存在
    existing_group = conn.execute(
        'SELECT id FROM groups WHERE name = ?', (group_name,)
    ).fetchone()

    if existing_group:
        conn.close()
        return jsonify({'success': False, 'message': '群组名称已存在'})

    # 创建群组
    conn.execute(
        'INSERT INTO groups (name, creator_id) VALUES (?, ?)',
        (group_name, current_user.id)
    )

    # 获取新创建的群组ID
    group_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

    # 将创建者添加到群组
    conn.execute(
        'INSERT INTO group_members (group_id, user_id) VALUES (?, ?)',
        (group_id, current_user.id)
    )

    conn.commit()
    conn.close()

    log_action(current_user.id, 'create_group', group_name)

    return jsonify({'success': True, 'message': '群组创建成功', 'group_id': group_id})


@app.route('/join_group/<int:group_id>')
@login_required
def join_group(group_id):
    """加入群组"""
    conn = get_db_connection()

    # 检查用户是否已经在群组中
    existing_member = conn.execute(
        'SELECT id FROM group_members WHERE group_id = ? AND user_id = ?',
        (group_id, current_user.id)
    ).fetchone()

    if not existing_member:
        # 加入群组
        conn.execute(
            'INSERT INTO group_members (group_id, user_id) VALUES (?, ?)',
            (group_id, current_user.id)
        )
        conn.commit()

        log_action(current_user.id, 'join_group', f'Group#{group_id}')
        flash('已加入群组')
    else:
        flash('您已经在该群组中')

    conn.close()

    return redirect(url_for('chat'))


@app.route('/search')
@login_required
def search():
    return render_template('search.html')


@app.route('/get_unread_messages')
@login_required
def get_unread_messages():
    """获取当前用户的未读消息"""
    user_id = current_user.id
    if user_id in unread_messages:
        messages = unread_messages[user_id]
        # 清空未读消息
        unread_messages[user_id] = {}
        return jsonify({'success': True, 'messages': messages})
    return jsonify({'success': True, 'messages': {}})


# SocketIO事件处理
@socketio.on('connect')
def handle_connect(auth=None):
    """处理客户端连接事件"""
    try:
        if current_user.is_authenticated:
            join_room('user_' + str(current_user.id))

            # 更新在线用户列表
            online_users[current_user.id] = {
                'sid': request.sid,
                'last_seen': time.time(),
                'username': current_user.username
            }

            # 发送未读消息给用户
            if current_user.id in unread_messages and unread_messages[current_user.id]:
                for target_type, target_messages in unread_messages[current_user.id].items():
                    for target_id, messages in target_messages.items():
                        for msg in messages:
                            emit('new_message', msg, room='user_' + str(current_user.id))
                # 清空未读消息
                unread_messages[current_user.id] = {}

            # 广播用户上线通知
            emit('user_online', {
                'user_id': current_user.id,
                'username': current_user.username
            }, broadcast=True)

            log_action(current_user.id, 'connect')

            # 输出控制台日志
            print(f"\033[1;32m[CONNECT] User {current_user.username} connected from {request.remote_addr}\033[0m")
        else:
            # 未认证用户连接，拒绝连接
            return False
    except Exception as e:
        print(f"Error in handle_connect: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


@socketio.on('disconnect')
def handle_disconnect():
    """处理客户端断开连接事件"""
    try:
        if current_user.is_authenticated:
            # 从在线用户列表中移除
            if current_user.id in online_users:
                del online_users[current_user.id]

            # 广播用户离线通知
            emit('user_offline', {
                'user_id': current_user.id,
                'username': current_user.username
            }, broadcast=True)

            log_action(current_user.id, 'disconnect')

            # 输出控制台日志
            print(f"\033[1;31m[DISCONNECT] User {current_user.username} disconnected\033[0m")
    except Exception as e:
        print(f"Error in handle_disconnect: {str(e)}")
        import traceback
        traceback.print_exc()


@socketio.on('send_message')
def handle_send_message(data):
    message_type = data.get('type', 'public')
    content = data.get('content', '')
    target_id = data.get('target_id')

    if not content.strip():
        return

    conn = get_db_connection()

    # 保存消息到数据库
    if message_type == 'public':
        if not current_user.can_public_chat:
            emit('error', {'message': '您没有公共聊天权限'})
            return

        conn.execute(
            'INSERT INTO messages (sender_id, content, message_type) VALUES (?, ?, ?)',
            (current_user.id, content, 'public')
        )
        conn.commit()

        # 获取消息ID
        message_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

        # 构建消息对象
        message_data = {
            'id': message_id,
            'sender_id': current_user.id,
            'sender_name': current_user.username,
            'content': content,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': 'public'
        }

        # 广播公共消息
        emit('new_message', message_data, broadcast=True)

        # 保存消息到文件
        save_message_to_file(message_data)

        # 输出到控制台（显眼格式）
        print(f"\033[1;33m[PUBLIC] {current_user.username}: {content}\033[0m")

        log_action(current_user.id, 'public_message', content)

    elif message_type == 'private':
        if not current_user.can_private_chat:
            emit('error', {'message': '您没有私聊权限'})
            return

        conn.execute(
            'INSERT INTO messages (sender_id, receiver_id, content, message_type) VALUES (?, ?, ?, ?)',
            (current_user.id, target_id, content, 'private')
        )
        conn.commit()

        # 获取消息ID
        message_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

        # 构建消息对象
        message_data = {
            'id': message_id,
            'sender_id': current_user.id,
            'sender_name': current_user.username,
            'receiver_id': target_id,
            'content': content,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': 'private'
        }

        # 检查接收者是否在线
        if target_id in online_users:
            # 如果接收者在线，直接发送消息
            emit('new_message', message_data, room='user_' + str(target_id))
        else:
            # 如果接收者不在线，存储为未读消息
            if target_id not in unread_messages:
                unread_messages[target_id] = {}
            if 'private' not in unread_messages[target_id]:
                unread_messages[target_id]['private'] = {}
            if current_user.id not in unread_messages[target_id]['private']:
                unread_messages[target_id]['private'][current_user.id] = []

            unread_messages[target_id]['private'][current_user.id].append(message_data)

            # 更新未读计数
            update_unread_count(target_id, 'private', current_user.id)

        # 也发送给自己
        emit('new_message', message_data, room='user_' + str(current_user.id))

        # 保存消息到文件
        save_message_to_file(message_data)

        # 输出到控制台（显眼格式）
        print(f"\033[1;35m[PRIVATE] {current_user.username} -> User#{target_id}: {content}\033[0m")

        log_action(current_user.id, 'private_message', f'to_user_{target_id}', content)

    elif message_type == 'group':
        if not current_user.can_public_chat:  # 使用公共聊天权限作为群聊权限
            emit('error', {'message': '您没有群聊权限'})
            return

        conn.execute(
            'INSERT INTO messages (sender_id, group_id, content, message_type) VALUES (?, ?, ?, ?)',
            (current_user.id, target_id, content, 'group')
        )
        conn.commit()

        # 获取消息ID
        message_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

        # 构建消息对象
        message_data = {
            'id': message_id,
            'sender_id': current_user.id,
            'sender_name': current_user.username,
            'group_id': target_id,
            'content': content,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': 'group'
        }

        # 获取群组成员
        members = conn.execute(
            'SELECT user_id FROM group_members WHERE group_id = ?',
            (target_id,)
        ).fetchall()

        # 发送消息给所有在线群组成员
        for member in members:
            member_id = member['user_id']
            if member_id == current_user.id:
                # 也发送给自己
                emit('new_message', message_data, room='user_' + str(member_id))
            elif member_id in online_users:
                # 如果成员在线，直接发送消息
                emit('new_message', message_data, room='user_' + str(member_id))
            else:
                # 存储为未读消息
                if member_id not in unread_messages:
                    unread_messages[member_id] = {}
                if 'group' not in unread_messages[member_id]:
                    unread_messages[member_id]['group'] = {}
                if target_id not in unread_messages[member_id]['group']:
                    unread_messages[member_id]['group'][target_id] = []

                unread_messages[member_id]['group'][target_id].append(message_data)

                # 更新未读计数
                update_unread_count(member_id, 'group', target_id)

        # 保存消息到文件
        save_message_to_file(message_data)

        # 输出到控制台（显眼格式）
        print(f"\033[1;34m[GROUP#{target_id}] {current_user.username}: {content}\033[0m")

        log_action(current_user.id, 'group_message', f'group_{target_id}', content)

    conn.close()


if __name__ == '__main__':
    # 生成自签名SSL证书（如果不存在）
    cert_file = os.path.join(app.config['CERTS_DIR'], 'cert.pem')
    key_file = os.path.join(app.config['CERTS_DIR'], 'key.pem')

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        # 生成私钥
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # 生成自签名证书
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WebChatRoom"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        # 保存证书和私钥
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    # 启动应用
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=False,
        ssl_context=(cert_file, key_file)
    )