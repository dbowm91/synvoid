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
            const icon = file.is_directory ? this.getFileIconSvg('folder') : this.getFileIcon(file.name);
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
        if (!ext) return this.getFileIconSvg('generic');
        ext = ext.toLowerCase();
        const iconMap = {
            'js': 'js', 'ts': 'ts', 'tsx': 'ts', 'jsx': 'ts',
            'py': 'py', 'rs': 'rs',
            'html': 'html', 'htm': 'html', 'css': 'css', 'scss': 'css', 'sass': 'css', 'less': 'css',
            'json': 'data', 'yaml': 'data', 'yml': 'data', 'toml': 'data',
            'md': 'text', 'txt': 'text',
            'png': 'image', 'jpg': 'image', 'jpeg': 'image', 'gif': 'image', 'svg': 'image', 'webp': 'image', 'ico': 'image',
            'pdf': 'pdf', 'zip': 'archive', 'tar': 'archive', 'gz': 'archive', '7z': 'archive'
        };
        return this.getFileIconSvg(iconMap[ext] || 'generic');
    }

    getFileIconSvg(type) {
        const icons = {
            folder: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>',
            generic: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14,2 14,8 20,8"/></svg>',
            js: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9v6M15 9v6M9 15h6"/></svg>',
            ts: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9v6M15 9v6M9 15h6"/></svg>',
            py: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>',
            rs: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>',
            html: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16,18 22,12 16,6"/><polyline points="8,6 2,12 8,18"/></svg>',
            css: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>',
            data: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8M8 17h8"/></svg>',
            text: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14,2 14,8 20,8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
            image: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21,15 16,10 5,21"/></svg>',
            pdf: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14,2 14,8 20,8"/><path d="M9 15v-2h2a1 1 0 010 2H9zM9 11h2"/></svg>',
            archive: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/><path d="M12 11v6M9 14h6"/></svg>'
        };
        return icons[type] || icons.generic;
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
