document.addEventListener('DOMContentLoaded', function() {
    // 切换开关处理
    const toggleSwitches = document.querySelectorAll('.toggle-switch input');

    toggleSwitches.forEach(switchInput => {
        switchInput.addEventListener('change', function() {
            const userId = this.getAttribute('data-user-id');
            const field = this.getAttribute('data-field');
            const value = this.checked;

            // 发送AJAX请求更新用户权限
            const formData = new FormData();
            formData.append('user_id', userId);
            formData.append('field', field);
            formData.append('value', value);

            fetch('/admin/update_user', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (!data.success) {
                    alert(data.message);
                    this.checked = !value; // 恢复之前的状态
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('更新失败');
                this.checked = !value; // 恢复之前的状态
            });
        });
    });

    // 批准用户注册
    const approveButtons = document.querySelectorAll('.approve-btn');

    approveButtons.forEach(button => {
        button.addEventListener('click', function() {
            const userId = this.getAttribute('data-user-id');

            // 发送AJAX请求批准用户
            const formData = new FormData();
            formData.append('user_id', userId);
            formData.append('field', 'approved');
            formData.append('value', true);

            fetch('/admin/update_user', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // 移除待审核用户行
                    const userRow = document.getElementById(`pending-user-${userId}`);
                    if (userRow) {
                        userRow.remove();
                    }

                    // 显示成功消息
                    alert('用户已批准');
                } else {
                    alert(data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('批准失败');
            });
        });
    });
});