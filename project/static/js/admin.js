/**
 * Admin Dashboard JavaScript Functionality
 * Provides enhanced UI interactions and security features
 */

// Admin Dashboard Main Object
const AdminDashboard = {
    // Configuration
    config: {
        apiBaseUrl: '/api/admin',
        csrfToken: document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '',
        sessionTimeout: 30 * 60 * 1000, // 30 minutes
        autoRefreshInterval: 30000, // 30 seconds
        maxFailedAttempts: 3,
        lockoutDuration: 15 * 60 * 1000, // 15 minutes
        maxRetries: 3,
        retryDelay: 1000,
        maxRequestsPerMinute: 50 // Rate limiting
    },

    // Rate limiting
    requestQueue: [],
    requestCount: 0,
    requestResetTime: Date.now() + 60000, // Reset every minute

    // State management
    state: {
        failedAttempts: 0,
        isLocked: false,
        lastActivity: Date.now(),
        autoRefreshTimer: null,
        sessionTimer: null
    },

    // Initialize admin dashboard
    init: function() {
        console.log('Initializing Admin Dashboard...');
        
        // Get CSRF token
        this.getCsrfToken();
        
        // Setup event listeners
        this.setupEventListeners();
        
        // Start session monitoring
        this.startSessionMonitoring();
        
        // Start auto refresh for certain pages
        this.startAutoRefresh();
        
        // Initialize tooltips and popovers
        this.initializeBootstrapComponents();
        
        // Setup form validation
        this.setupFormValidation();
        
        console.log('Admin Dashboard initialized successfully');
    },

    // Get CSRF token from meta tag
    getCsrfToken: function() {
        const csrfMeta = document.querySelector('meta[name="csrf-token"]');
        this.config.csrfToken = csrfMeta ? csrfMeta.content : null;
        
        if (!this.config.csrfToken) {
            console.warn('CSRF token not found. Some operations may fail.');
        }
    },

    // Setup event listeners
    setupEventListeners: function() {
        // Sidebar toggle
        const sidebarToggle = document.getElementById('sidebarToggle');
        const mobileSidebarToggle = document.getElementById('mobileSidebarToggle');
        const sidebar = document.getElementById('sidebar');

        if (sidebarToggle) {
            sidebarToggle.addEventListener('click', () => {
                sidebar.classList.remove('show');
            });
        }

        if (mobileSidebarToggle) {
            mobileSidebarToggle.addEventListener('click', () => {
                sidebar.classList.add('show');
            });
        }

        // Auto-hide alerts after 5 seconds
        const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
        alerts.forEach(alert => {
            setTimeout(() => {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }, 5000);
        });

        // Activity tracking
        document.addEventListener('click', () => this.updateActivity());
        document.addEventListener('keypress', () => this.updateActivity());
        document.addEventListener('scroll', () => this.updateActivity());

        // Form submissions
        document.addEventListener('submit', (e) => {
            if (e.target.matches('form[data-admin-form]')) {
                e.preventDefault();
                this.handleFormSubmit(e.target);
            }
        });

        // Delete confirmations
        document.addEventListener('click', (e) => {
            if (e.target.matches('[data-admin-delete]')) {
                e.preventDefault();
                this.handleDeleteAction(e.target);
            }
        });

        // AJAX actions
        document.addEventListener('click', (e) => {
            if (e.target.matches('[data-admin-action]')) {
                e.preventDefault();
                this.handleAdminAction(e.target);
            }
        });
    },

    // Initialize Bootstrap components
    initializeBootstrapComponents: function() {
        // Initialize tooltips
        const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        tooltips.forEach(tooltip => {
            new bootstrap.Tooltip(tooltip);
        });

        // Initialize popovers
        const popovers = document.querySelectorAll('[data-bs-toggle="popover"]');
        popovers.forEach(popover => {
            new bootstrap.Popover(popover);
        });

        // Initialize dropdowns
        const dropdowns = document.querySelectorAll('[data-bs-toggle="dropdown"]');
        dropdowns.forEach(dropdown => {
            new bootstrap.Dropdown(dropdown);
        });
    },

    // Setup form validation
    setupFormValidation: function() {
        const forms = document.querySelectorAll('form[data-validate]');
        
        forms.forEach(form => {
            form.addEventListener('submit', (e) => {
                if (!this.validateForm(form)) {
                    e.preventDefault();
                    e.stopPropagation();
                }
            });
        });
    },

    // Validate form
    validateForm: function(form) {
        let isValid = true;
        const requiredFields = form.querySelectorAll('[required]');
        
        requiredFields.forEach(field => {
            if (!field.value.trim()) {
                this.showFieldError(field, 'This field is required');
                isValid = false;
            } else {
                this.clearFieldError(field);
            }
        });

        // Email validation
        const emailFields = form.querySelectorAll('input[type="email"]');
        emailFields.forEach(field => {
            if (field.value && !this.isValidEmail(field.value)) {
                this.showFieldError(field, 'Please enter a valid email address');
                isValid = false;
            }
        });

        return isValid;
    },

    // Show field error
    showFieldError: function(field, message) {
        field.classList.add('is-invalid');
        
        let errorElement = field.parentElement.querySelector('.invalid-feedback');
        if (!errorElement) {
            errorElement = document.createElement('div');
            errorElement.className = 'invalid-feedback';
            field.parentElement.appendChild(errorElement);
        }
        
        errorElement.textContent = message;
    },

    // Clear field error
    clearFieldError: function(field) {
        field.classList.remove('is-invalid');
        const errorElement = field.parentElement.querySelector('.invalid-feedback');
        if (errorElement) {
            errorElement.remove();
        }
    },

    // Email validation
    isValidEmail: function(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    },

    // Handle form submission
    handleFormSubmit: function(form) {
        if (!this.validateForm(form)) {
            return;
        }

        const formData = new FormData(form);
        const submitButton = form.querySelector('button[type="submit"]');
        const originalText = submitButton.textContent;

        // Disable submit button
        submitButton.disabled = true;
        submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';

        // Add CSRF token
        if (this.config.csrfToken) {
            formData.append('csrf_token', this.config.csrfToken);
        }

        fetch(form.action, {
            method: form.method,
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                this.showNotification('success', data.message || 'Operation completed successfully');
                if (data.redirect) {
                    setTimeout(() => window.location.href = data.redirect, 1500);
                }
            } else {
                this.showNotification('error', data.message || 'Operation failed');
            }
        })
        .catch(error => {
            console.error('Form submission error:', error);
            this.showNotification('error', 'An error occurred. Please try again.');
        })
        .finally(() => {
            submitButton.disabled = false;
            submitButton.textContent = originalText;
        });
    },

    // Handle delete action
    handleDeleteAction: function(element) {
        const title = element.dataset.title || 'this item';
        const message = element.dataset.message || `Are you sure you want to delete ${title}? This action cannot be undone.`;
        
        if (confirm(message)) {
            this.performAjaxAction(element.href, 'DELETE', element.dataset);
        }
    },

    // Handle admin action
    handleAdminAction: function(element) {
        const action = element.dataset.action;
        const method = element.dataset.method || 'POST';
        
        this.performAjaxAction(element.href, method, element.dataset);
    },

    // Perform AJAX action
    performAjaxAction: function(url, method, data) {
        const formData = new FormData();
        
        // Add CSRF token
        if (this.config.csrfToken) {
            formData.append('csrf_token', this.config.csrfToken);
        }

        // Add additional data
        Object.keys(data).forEach(key => {
            if (key !== 'action' && key !== 'method' && key !== 'title' && key !== 'message') {
                formData.append(key, data[key]);
            }
        });

        fetch(url, {
            method: method,
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(result => {
            if (result.success) {
                this.showNotification('success', result.message || 'Action completed successfully');
                if (result.redirect) {
                    setTimeout(() => window.location.href = result.redirect, 1500);
                } else {
                    // Reload current page after successful action
                    setTimeout(() => location.reload(), 1500);
                }
            } else {
                this.showNotification('error', result.message || 'Action failed');
            }
        })
        .catch(error => {
            console.error('AJAX action error:', error);
            this.showNotification('error', 'An error occurred. Please try again.');
        });
    },

    // Show notification
    showNotification: function(type, message) {
        const notificationContainer = document.getElementById('notification-container') || this.createNotificationContainer();
        
        const notification = document.createElement('div');
        notification.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show`;
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        notificationContainer.appendChild(notification);
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(notification);
            bsAlert.close();
        }, 5000);
    },

    // Create notification container
    createNotificationContainer: function() {
        const container = document.createElement('div');
        container.id = 'notification-container';
        container.className = 'notification-container';
        document.body.appendChild(container);
        return container;
    },

    // Update activity timestamp
    updateActivity: function() {
        this.state.lastActivity = Date.now();
        this.resetSessionTimer();
    },

    // Start session monitoring
    startSessionMonitoring: function() {
        this.resetSessionTimer();
        
        // Check session every minute
        setInterval(() => {
            this.checkSessionTimeout();
        }, 60000);
    },

    // Reset session timer
    resetSessionTimer: function() {
        if (this.state.sessionTimer) {
            clearTimeout(this.state.sessionTimer);
        }
        
        this.state.sessionTimer = setTimeout(() => {
            this.handleSessionTimeout();
        }, this.config.sessionTimeout);
    },

    // Check session timeout
    checkSessionTimeout: function() {
        const timeSinceLastActivity = Date.now() - this.state.lastActivity;
        
        if (timeSinceLastActivity > this.config.sessionTimeout) {
            this.handleSessionTimeout();
        } else if (timeSinceLastActivity > this.config.sessionTimeout * 0.8) {
            // Show warning when 80% of timeout reached
            this.showSessionWarning();
        }
    },

    // Handle session timeout
    handleSessionTimeout: function() {
        this.showNotification('warning', 'Your session has expired due to inactivity. Please refresh the page.');
        
        // Disable admin actions
        const adminElements = document.querySelectorAll('[data-admin-action], [data-admin-delete], form[data-admin-form]');
        adminElements.forEach(element => {
            element.disabled = true;
            element.style.opacity = '0.5';
        });
    },

    // Show session warning
    showSessionWarning: function() {
        const timeRemaining = Math.ceil((this.config.sessionTimeout - (Date.now() - this.state.lastActivity)) / 60000);
        this.showNotification('warning', `Your session will expire in ${timeRemaining} minutes due to inactivity.`);
    },

    // Start auto refresh
    startAutoRefresh: function() {
        const currentPath = window.location.pathname;
        
        // Only auto-refresh on specific pages
        const autoRefreshPages = [
            '/admin/dashboard',
            '/admin/analytics',
            '/admin/audit-logs'
        ];
        
        if (autoRefreshPages.some(page => currentPath.includes(page))) {
            this.state.autoRefreshTimer = setInterval(() => {
                this.refreshCurrentPage();
            }, this.config.autoRefreshInterval);
        }
    },

    // Refresh current page
    refreshCurrentPage: function() {
        // Only refresh if user is active
        if (Date.now() - this.state.lastActivity < 300000) { // Last 5 minutes
            location.reload();
        }
    },

    // Utility function to escape HTML
    escapeHtml: function(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    // Utility function to format dates
    formatDate: function(date) {
        return new Intl.DateTimeFormat('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        }).format(new Date(date));
    },

    // Utility function to format numbers
    formatNumber: function(number) {
        return new Intl.NumberFormat().format(number);
    }
};

    // API Methods
    api: {
        // Rate limiting check
        checkRateLimit() {
            const now = Date.now();
            if (now > this.requestResetTime) {
                this.requestCount = 0;
                this.requestResetTime = now + 60000;
            }
            
            if (this.requestCount >= this.config.maxRequestsPerMinute) {
                throw new Error('Rate limit exceeded. Please wait a moment before making more requests.');
            }
            
            this.requestCount++;
            return true;
        },

        // Make authenticated API request with rate limiting and security
        async request(endpoint, options = {}) {
            try {
                // Check rate limit
                this.checkRateLimit();
                
                const url = `${this.config.apiBaseUrl}/${endpoint}`;
                const headers = {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': this.config.csrfToken,
                    'X-Requested-With': 'XMLHttpRequest' // CSRF protection
                };
                
                // Add retry logic
                let retries = 0;
                const maxRetries = this.config.maxRetries;
                
                while (retries < maxRetries) {
                    try {
                        const response = await fetch(url, {
                            ...options,
                            headers: {
                                ...headers,
                                ...options.headers
                            }
                        });
                        
                        if (response.status === 429) {
                            // Rate limited
                            throw new Error('Too many requests. Please slow down.');
                        }
                        
                        if (response.status === 403) {
                            // CSRF or permission error
                            console.error('Permission denied or CSRF token invalid');
                            throw new Error('Permission denied');
                        }
                        
                        if (!response.ok) {
                            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                        }
                        
                        return await response.json();
                        
                    } catch (error) {
                        retries++;
                        if (retries >= maxRetries) {
                            throw error;
                        }
                        
                        // Exponential backoff
                        await new Promise(resolve => setTimeout(resolve, this.config.retryDelay * Math.pow(2, retries)));
                    }
                }
                
            } catch (error) {
                console.error('API request failed:', error);
                this.showNotification(error.message || 'API request failed', 'error');
                throw error;
            }
        }
    },

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    AdminDashboard.init();
});

// Add CSS for notification container
const style = document.createElement('style');
style.textContent = `
    .notification-container {
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 9999;
        max-width: 400px;
    }
    
    .notification-container .alert {
        margin-bottom: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        animation: slideInRight 0.3s ease;
    }
    
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
`;
document.head.appendChild(style);