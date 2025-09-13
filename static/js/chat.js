document.addEventListener('DOMContentLoaded', function() {
    // 连接到SocketIO服务器
    const socket = io();

    // 获取DOM元素
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const messagesContainer = document.getElementById('messages-container');
    const chatHeader = document.getElementById('chat-header');

    // 当前聊天类型和目标
    let currentChatType = 'public';
    let currentTargetId = null;
    let currentTargetName = null;
    let currentConversationId = 'public';

    // 存储会话状态
    const chatSessions = {
        'public': {
            messages: [],
            unread: 0
        }
    };

    // 全局函数供HTML调用
    window.selectUserHandler = function(userId, userName) {
        selectUser(userId, userName);
    };

    window.selectPublicChatHandler = function() {
        selectPublicChat();
    };

    window.selectGroupHandler = function(groupId, groupName) {
        selectGroup(groupId, groupName);
    };

    // 连接到服务器
    socket.on('connect', function() {
        console.log('Connected to server');
    });

    // 断开连接
    socket.on('disconnect', function() {
        console.log('Disconnected from server');
    });

    // 接收新消息
    socket.on('new_message', function(data) {
        const conversationId = getConversationId(data.type, data.receiver_id || data.group_id);

        // 添加到会话记录
        if (!chatSessions[conversationId]) {
            chatSessions[conversationId] = {
                messages: [],
                unread: 0
            };
        }

        chatSessions[conversationId].messages.push(data);

        // 如果当前正在查看这个会话，直接显示消息
        if (currentConversationId === conversationId) {
            addMessageToChat(data);
            // 标记消息为已读
            markConversationAsRead(conversationId);
        } else {
            // 否则增加未读计数
            chatSessions[conversationId].unread++;
            updateUnreadBadge(conversationId, chatSessions[conversationId].unread);
        }
    });

    // 消息已读状态更新
    socket.on('message_read_status', function(data) {
        // 更新消息已读状态
        updateMessageReadStatus(data);
    });

    // 用户连接通知
    socket.on('user_online', function(data) {
        addSystemMessage(`用户 ${data.username} 已上线`);
        updateUserStatus(data.user_id, true);
    });

    // 用户断开通知
    socket.on('user_offline', function(data) {
        addSystemMessage(`用户 ${data.username} 已下线`);
        updateUserStatus(data.user_id, false);
    });

    // 错误处理
    socket.on('error', function(data) {
        alert(data.message);
    });

    // 获取会话ID
    function getConversationId(chatType, targetId) {
        if (chatType === 'public') {
            return 'public';
        } else if (chatType === 'private') {
            return `private_${targetId}`;
        } else if (chatType === 'group') {
            return `group_${targetId}`;
        }
        return null;
    }

    // 发送消息
    function sendMessage() {
        const content = messageInput.value.trim();
        if (content === '') return;

        socket.emit('send_message', {
            type: currentChatType,
            content: content,
            target_id: currentTargetId
        });

        messageInput.value = '';
    }

    // 添加消息到聊天窗口
    function addMessageToChat(message) {
        const messageElement = document.createElement('div');
        messageElement.className = `message ${message.type === 'private' ? 'private' : 'public'} fade-in`;

        if (message.sender_id === current_user_id) {
            messageElement.classList.add('self');
        } else {
            messageElement.classList.add('other');
        }

        messageElement.dataset.messageId = message.id;

        const senderSpan = document.createElement('span');
        senderSpan.className = 'message-sender';
        senderSpan.textContent = message.sender_name;

        const timeSpan = document.createElement('span');
        timeSpan.className = 'message-time';
        timeSpan.textContent = message.timestamp;

        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';
        contentDiv.textContent = message.content;

        messageElement.appendChild(senderSpan);
        messageElement.appendChild(timeSpan);
        messageElement.appendChild(contentDiv);

        // 添加已读状态
        if (message.type === 'private' && message.sender_id === current_user_id) {
            const statusDiv = document.createElement('div');
            statusDiv.className = 'message-status';
            statusDiv.textContent = message.is_read ? '已读' : '未读';
            messageElement.appendChild(statusDiv);
        }

        messagesContainer.appendChild(messageElement);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    // 添加系统消息
    function addSystemMessage(content) {
        const messageElement = document.createElement('div');
        messageElement.className = 'message system-message';

        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';
        contentDiv.textContent = content;
        contentDiv.style.fontStyle = 'italic';
        contentDiv.style.color = '#999';

        messageElement.appendChild(contentDiv);
        messagesContainer.appendChild(messageElement);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    // 选择用户聊天
    function selectUser(userId, userName) {
        // 移除所有active类
        const userItems = document.querySelectorAll('.user-item');
        userItems.forEach(item => item.classList.remove('active'));

        // 添加active类到当前选择的用户
        const selectedUser = document.querySelector(`.user-item[data-user-id="${userId}"]`);
        if (selectedUser) {
            selectedUser.classList.add('active');
        }

        // 更新当前聊天状态
        currentChatType = 'private';
        currentTargetId = userId;
        currentTargetName = userName;
        currentConversationId = getConversationId('private', userId);
        chatHeader.textContent = `与 ${userName} 的私聊`;

        // 更新输入框状态
        messageInput.disabled = !current_user_can_private_chat;
        sendButton.disabled = !current_user_can_private_chat;

        // 清空消息容器
        messagesContainer.innerHTML = '';
        addSystemMessage(`开始与 ${userName} 的私聊`);

        // 加载历史消息
        loadHistoryMessages();

        // 标记会话为已读
        markConversationAsRead(currentConversationId);
    }

    // 选择公共聊天
    function selectPublicChat() {
        // 移除所有active类
        const userItems = document.querySelectorAll('.user-item');
        userItems.forEach(item => item.classList.remove('active'));

        // 添加active类到公共聊天
        const publicChat = document.querySelector('.user-item[data-chat-type="public"]');
        if (publicChat) {
            publicChat.classList.add('active');
        }

        // 更新当前聊天状态
        currentChatType = 'public';
        currentTargetId = null;
        currentTargetName = null;
        currentConversationId = 'public';
        chatHeader.textContent = '公共聊天室';

        // 更新输入框状态
        messageInput.disabled = !current_user_can_public_chat;
        sendButton.disabled = !current_user_can_public_chat;

        // 清空消息容器
        messagesContainer.innerHTML = '';
        addSystemMessage('欢迎来到公共聊天室');

        // 加载历史消息
        loadHistoryMessages();
    }

    // 选择群组聊天
    function selectGroup(groupId, groupName) {
        // 移除所有active类
        const userItems = document.querySelectorAll('.user-item');
        userItems.forEach(item => item.classList.remove('active'));

        // 添加active类到当前选择的群组
        const selectedGroup = document.querySelector(`.user-item[data-group-id="${groupId}"]`);
        if (selectedGroup) {
            selectedGroup.classList.add('active');
        }

        // 更新当前聊天状态
        currentChatType = 'group';
        currentTargetId = groupId;
        currentTargetName = groupName;
        currentConversationId = getConversationId('group', groupId);
        chatHeader.textContent = `群组: ${groupName}`;

        // 更新输入框状态
        messageInput.disabled = !current_user_can_public_chat; // 使用公共聊天权限作为群聊权限
        sendButton.disabled = !current_user_can_public_chat;

        // 清空消息容器
        messagesContainer.innerHTML = '';
        addSystemMessage(`欢迎来到群组 ${groupName}`);

        // 加载历史消息
        loadHistoryMessages();

        // 标记会话为已读
        markConversationAsRead(currentConversationId);
    }

    // 更新用户在线状态
    function updateUserStatus(userId, isOnline) {
        const userItem = document.querySelector(`.user-item[data-user-id="${userId}"]`);
        if (userItem) {
            const statusIndicator = userItem.querySelector('.status-indicator');
            if (statusIndicator) {
                if (isOnline) {
                    statusIndicator.classList.add('online');
                    statusIndicator.classList.remove('offline');
                } else {
                    statusIndicator.classList.remove('online');
                    statusIndicator.classList.add('offline');
                }
            }
        }
    }

    // 加载历史消息
    function loadHistoryMessages() {
        fetch(`/get_chat_history?type=${currentChatType}&target_id=${currentTargetId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success && data.messages.length > 0) {
                    data.messages.forEach(msg => {
                        addMessageToChat(msg);
                    });
                }
            })
            .catch(error => {
                console.error('Error loading chat history:', error);
            });
    }

    // 标记会话为已读
    function markConversationAsRead(conversationId) {
        // 清除未读计数
        if (chatSessions[conversationId]) {
            chatSessions[conversationId].unread = 0;
            updateUnreadBadge(conversationId, 0);
        }

        // 发送已读状态到服务器
        fetch('/mark_as_read', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                conversation_id: conversationId
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                console.log('Conversation marked as read');
            }
        })
        .catch(error => {
            console.error('Error marking conversation as read:', error);
        });
    }

    // 更新消息已读状态
    function updateMessageReadStatus(data) {
        // 更新UI中的消息已读状态
        const messages = document.querySelectorAll('.message');
        messages.forEach(msg => {
            if (msg.dataset.messageId) {
                const statusElement = msg.querySelector('.message-status');
                if (statusElement) {
                    statusElement.textContent = '已读';
                }
            }
        });
    }

    // 更新未读消息徽章
    function updateUnreadBadge(conversationId, count) {
        // 移除现有的徽章
        const existingBadges = document.querySelectorAll(`.unread-badge[data-conversation="${conversationId}"]`);
        existingBadges.forEach(badge => badge.remove());

        if (count > 0) {
            // 找到对应的会话项
            let targetElement = null;

            if (conversationId === 'public') {
                targetElement = document.querySelector('.user-item[data-chat-type="public"]');
            } else if (conversationId.startsWith('private_')) {
                const targetId = conversationId.split('_')[1];
                targetElement = document.querySelector(`.user-item[data-user-id="${targetId}"]`);
            } else if (conversationId.startsWith('group_')) {
                const groupId = conversationId.split('_')[1];
                targetElement = document.querySelector(`.user-item[data-group-id="${groupId}"]`);
            }

            if (targetElement) {
                const badge = document.createElement('div');
                badge.className = 'unread-badge';
                badge.dataset.conversation = conversationId;
                badge.textContent = count > 99 ? '99+' : count;
                targetElement.appendChild(badge);
            }
        }
    }

    // 绑定事件监听器
    sendButton.addEventListener('click', sendMessage);
    messageInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });

    // 初始化公共聊天
    selectPublicChat();

    // 获取未读消息
    fetch('/get_unread_messages')
        .then(response => response.json())
        .then(data => {
            if (data.success && data.messages.length > 0) {
                data.messages.forEach(msg => {
                    addMessageToChat(msg);
                });
                addSystemMessage('以上是您不在线时收到的消息');
            }
        });

    // 创建群组表单处理
    const createGroupForm = document.getElementById('create-group-form');
    if (createGroupForm) {
        createGroupForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const groupName = document.getElementById('group-name').value;

            fetch('/create_group', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `group_name=${encodeURIComponent(groupName)}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('群组创建成功');
                    window.location.reload();
                } else {
                    alert(data.message);
                }
            })
            .catch(error => {
                console.error('Error creating group:', error);
                alert('创建群组时发生错误');
            });
        });
    }

    // 移动端侧边栏切换
    const sidebarToggle = document.createElement('button');
    sidebarToggle.className = 'sidebar-toggle';
    sidebarToggle.innerHTML = '☰';
    sidebarToggle.style.position = 'absolute';
    sidebarToggle.style.top = '10px';
    sidebarToggle.style.left = '10px';
    sidebarToggle.style.zIndex = '100';
    sidebarToggle.style.display = 'none';

    document.body.appendChild(sidebarToggle);

    // 检查是否是移动设备
    function checkMobile() {
        return window.innerWidth <= 768;
    }

    // 初始化移动端界面
    function initMobileUI() {
        const isMobile = checkMobile();

        if (isMobile) {
            sidebarToggle.style.display = 'block';
            document.querySelector('.user-list-sidebar').style.display = 'none';
        } else {
            sidebarToggle.style.display = 'none';
            document.querySelector('.user-list-sidebar').style.display = 'flex';
        }
    }

    // 切换侧边栏显示
    sidebarToggle.addEventListener('click', function() {
        const sidebar = document.querySelector('.user-list-sidebar');
        if (sidebar.style.display === 'none') {
            sidebar.style.display = 'flex';
        } else {
            sidebar.style.display = 'none';
        }
    });

    // 监听窗口大小变化
    window.addEventListener('resize', initMobileUI);

    // 初始化界面
    initMobileUI();
});