class FileManager {
    constructor() {
        this.currentPath = '/';
        this.token = null;
        this.apiBase = '/admin/files';
    }

    setToken(token) {
        this.token = token;
    }

    async request(endpoint, options = {}) {
        const headers = {
            'Authorization': 'Bearer ' + this.token,
            ...options.headers
        };

        const url = endpoint.startsWith('http') ? endpoint : this.apiBase + endpoint;
        const response = await fetch(url, { ...options, headers });
        if (!response.ok) {
            throw new Error('HTTP ' + response.status + ': ' + response.statusText);
        }
        return response.json();
    }

    async listDirectory(path) {
        if (path) {
            this.currentPath = path;
        }
        try {
            const result = await this.request('/list?path=' + encodeURIComponent(this.currentPath));
            this.render(result.data || []);
            this.updateBreadcrumb(this.currentPath);
        } catch (error) {
            this.showError('Failed to list directory: ' + error.message);
        }
    }

    async readFile(path) {
        const result = await this.request('/read' + path);
        return result.data;
    }

    async deleteFile(path) {
        return this.request('/delete' + path, { method: 'DELETE' });
    }

    async createDirectory(path) {
        return this.request('/mkdir', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: path })
        });
    }

    async uploadFile(file, destPath) {
        const formData = new FormData();
        formData.append('file', file);
        
        const url = this.apiBase + '/upload?path=' + encodeURIComponent(destPath);
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + this.token },
            body: formData
        });
        return response.json();
    }

    async searchFiles(query, path) {
        return this.request('/search?query=' + encodeURIComponent(query) + '&path=' + encodeURIComponent(path || '/'));
    }

    updateBreadcrumb(path) {
        const breadcrumb = document.getElementById('breadcrumb');
        const parts = path.split('/').filter(Boolean);
        let html = '<a href="#" data-path="/">/</a>';
        let currentPath = '';
        
        for (const part of parts) {
            currentPath += '/' + part;
            html += ' / <a href="#" data-path="' + currentPath + '">' + part + '</a>';
        }
        
        breadcrumb.innerHTML = html;
        
        breadcrumb.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                this.listDirectory(link.dataset.path);
            });
        });
    }

    render(files) {
        const container = document.getElementById('file-container');
        
        if (!files || files.length === 0) {
            container.innerHTML = '<div class="empty-state">No files found</div>';
            return;
        }

        let html = '<ul class="file-list">';
        
        for (const file of files) {
            const icon = file.is_directory ? '📁' : this.getFileIcon(file.name);
            const escapedName = this.escapeHtml(file.name);
            const escapedPath = this.currentPath === '/' 
                ? '/' + file.name 
                : this.currentPath + '/' + file.name;
            
            html += '<li class="file-list-item" data-path="' + escapedPath + '" data-is-dir="' + file.is_directory + '">';
            html += '<span class="file-icon">' + icon + '</span>';
            html += '<span class="file-name">' + escapedName + '</span>';
            html += '<span class="file-meta">' + (file.modified || '-') + '</span>';
            html += '</li>';
        }
        
        html += '</ul>';
        container.innerHTML = html;
        
        container.querySelectorAll('.file-list-item').forEach(item => {
            item.addEventListener('click', () => {
                const isDir = item.dataset.isDir === 'true';
                const path = item.dataset.path;
                if (isDir) {
                    this.listDirectory(path);
                } else {
                    this.showFilePreview(path);
                }
            });
        });
    }

    showFilePreview(path) {
        alert('Preview: ' + path);
    }

    getFileIcon(name) {
        const ext = name.split('.').pop();
        if (!ext) return '📄';
        ext = ext.toLowerCase();
        const icons = {
            'js': '📜', 'ts': '📘', 'py': '🐍', 'rs': '🦀',
            'html': '🌐', 'css': '🎨', 'json': '📋', 'md': '📝',
            'txt': '📄', 'png': '🖼️', 'jpg': '🖼️', 'gif': '🖼️',
            'pdf': '📕', 'zip': '📦', 'tar': '📦'
        };
        return icons[ext] || '📄';
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showError(message) {
        const container = document.getElementById('file-container');
        container.innerHTML = '<div class="empty-state" style="color: red;">' + this.escapeHtml(message) + '</div>';
    }

    showUploadModal() {
        document.getElementById('upload-modal').style.display = 'flex';
    }

    hideUploadModal() {
        document.getElementById('upload-modal').style.display = 'none';
        document.getElementById('file-input').value = '';
    }

    async handleUpload() {
        const fileInput = document.getElementById('file-input');
        const file = fileInput.files[0];
        if (!file) return;

        try {
            await this.uploadFile(file, this.currentPath);
            this.hideUploadModal();
            this.listDirectory(this.currentPath);
        } catch (error) {
            alert('Upload failed: ' + error.message);
        }
    }

    showNewFolderModal() {
        document.getElementById('newfolder-modal').style.display = 'flex';
        document.getElementById('newfolder-name').value = '';
        document.getElementById('newfolder-name').focus();
    }

    hideNewFolderModal() {
        document.getElementById('newfolder-modal').style.display = 'none';
    }

    async handleNewFolder() {
        const input = document.getElementById('newfolder-name');
        const name = input.value.trim();
        if (!name) return;

        const path = this.currentPath === '/' 
            ? '/' + name 
            : this.currentPath + '/' + name;

        try {
            await this.createDirectory(path);
            this.hideNewFolderModal();
            this.listDirectory(this.currentPath);
        } catch (error) {
            alert('Create directory failed: ' + error.message);
        }
    }
}

const fileManager = new FileManager();

document.addEventListener('DOMContentLoaded', function() {
    const token = localStorage.getItem('admin_token');
    if (token) {
        fileManager.setToken(token);
        document.getElementById('login-screen').style.display = 'none';
        document.getElementById('main-ui').style.display = 'block';
        fileManager.listDirectory('/');
    } else {
        document.getElementById('login-screen').style.display = 'flex';
        document.getElementById('main-ui').style.display = 'none';
    }

    document.getElementById('login-form').addEventListener('submit', function(e) {
        e.preventDefault();
        const token = document.getElementById('token-input').value;
        localStorage.setItem('admin_token', token);
        fileManager.setToken(token);
        document.getElementById('login-screen').style.display = 'none';
        document.getElementById('main-ui').style.display = 'block';
        fileManager.listDirectory('/');
    });

    document.getElementById('logout-btn').addEventListener('click', function() {
        localStorage.removeItem('admin_token');
        location.reload();
    });

    document.getElementById('refresh-btn').addEventListener('click', function() {
        fileManager.listDirectory(fileManager.currentPath);
    });

    document.getElementById('new-folder-btn').addEventListener('click', function() {
        fileManager.showNewFolderModal();
    });

    document.getElementById('upload-btn').addEventListener('click', function() {
        fileManager.showUploadModal();
    });

    document.getElementById('upload-cancel-btn').addEventListener('click', function() {
        fileManager.hideUploadModal();
    });

    document.getElementById('upload-confirm-btn').addEventListener('click', function() {
        fileManager.handleUpload();
    });

    document.getElementById('newfolder-cancel-btn').addEventListener('click', function() {
        fileManager.hideNewFolderModal();
    });

    document.getElementById('newfolder-create-btn').addEventListener('click', function() {
        fileManager.handleNewFolder();
    });

    document.getElementById('upload-modal').addEventListener('click', function(e) {
        if (e.target === this) {
            fileManager.hideUploadModal();
        }
    });

    document.getElementById('newfolder-modal').addEventListener('click', function(e) {
        if (e.target === this) {
            fileManager.hideNewFolderModal();
        }
    });
});
