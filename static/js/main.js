/**
 * Main Application Entry Point - Simplified Version (Task 8)
 * 
 * This is a simplified version that works without the broken module system.
 * Provides basic chat functionality for the HTML interface.
 */

class SimpleChatApplication {
    constructor() {
        this.sessionId = null;
        this.isConnected = false;
        this.isLoading = false;
        this.elements = {};
        
        console.log('SimpleChatApplication created');
        this.init();
    }
    
    async init() {
        try {
            console.log('Initializing SimpleChatApplication...');
            
            // Wait for DOM to be ready
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => this.init());
                return;
            }
            
            this.cacheElements();
            this.setupEventListeners();
            this.updateStatus('Ready');
            
            console.log('SimpleChatApplication initialized successfully');
            
        } catch (error) {
            console.error('Failed to initialize SimpleChatApplication:', error);
            this.showError('Failed to initialize the application. Please refresh the page.');
        }
    }
    
    cacheElements() {
        this.elements = {
            chatForm: document.getElementById('chatForm'),
            messageInput: document.getElementById('messageInput'), 
            sendButton: document.getElementById('sendButton'),
            messagesList: document.getElementById('messagesList'),
            statusText: document.getElementById('statusText'),
            connectionStatus: document.getElementById('connectionStatus')
        };
        
        // Log which elements were found
        Object.entries(this.elements).forEach(([name, element]) => {
            if (element) {
                console.log(`✅ Found element: ${name}`);
            } else {
                console.log(`⚠️ Element not found: ${name}`);
            }
        });
    }
    
    setupEventListeners() {
        // Chat form submission
        if (this.elements.chatForm) {
            this.elements.chatForm.addEventListener('submit', (e) => this.handleFormSubmit(e));
            console.log('✅ Form submit handler attached');
        }
        
        // Input enhancements
        if (this.elements.messageInput) {
            this.elements.messageInput.addEventListener('keydown', (e) => this.handleKeydown(e));
        }
        
        // Window events
        window.addEventListener('beforeunload', () => this.handleBeforeUnload());
    }
    
    async handleFormSubmit(event) {
        event.preventDefault();
        
        if (!this.elements.messageInput) {
            console.error('Message input not found');
            return;
        }
        
        const message = this.elements.messageInput.value.trim();
        if (!message) {
            return;
        }
        
        if (this.isLoading) {
            this.showWarning('Please wait for the current response to complete.');
            return;
        }
        
        try {
            this.setLoading(true);
            
            // Add user message to UI
            this.addMessage('user', message);
            
            // Clear input
            this.elements.messageInput.value = '';
            
            // Send message to backend
            const response = await this.sendMessage(message);
            
            // Add AI response to UI
            this.addMessage('assistant', response);
            
        } catch (error) {
            console.error('Error sending message:', error);
            this.showError(`Failed to send message: ${error.message}`);
            
            // Restore message to input on error
            if (!this.elements.messageInput.value) {
                this.elements.messageInput.value = message;
            }
        } finally {
            this.setLoading(false);
        }
    }
    
    async sendMessage(message) {
        const requestData = {
            message: message,
            session_id: this.sessionId
        };
        
        const response = await fetch('/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        // Store session ID for future requests
        if (data.session_id) {
            this.sessionId = data.session_id;
        }
        
        return data.response || 'No response received';
    }
    
    addMessage(role, content) {
        if (!this.elements.messagesList) {
            console.error('Messages list not found');
            return;
        }
        
        const messageDiv = document.createElement('div');
        messageDiv.className = `message message--${role}`;
        
        const timestamp = new Date().toLocaleTimeString();
        
        messageDiv.innerHTML = `
            <div class="message__avatar">${role === 'user' ? '👤' : '🤖'}</div>
            <div class="message__content">
                <div class="message__text">${this.escapeHtml(content)}</div>
                <div class="message__timestamp">${timestamp}</div>
            </div>
        `;
        
        this.elements.messagesList.appendChild(messageDiv);
        
        // Auto-scroll to bottom
        this.elements.messagesList.scrollTop = this.elements.messagesList.scrollHeight;
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    handleKeydown(event) {
        // Send message on Enter (without Shift)
        if (event.key === 'Enter' && !event.shiftKey) {
            event.preventDefault();
            if (this.elements.chatForm) {
                this.elements.chatForm.dispatchEvent(new Event('submit'));
            }
        }
        
        // Clear input on Escape
        if (event.key === 'Escape') {
            this.elements.messageInput.value = '';
        }
    }
    
    setLoading(loading) {
        this.isLoading = loading;
        
        if (this.elements.sendButton) {
            this.elements.sendButton.disabled = loading;
        }
        
        if (this.elements.messageInput) {
            this.elements.messageInput.disabled = loading;
        }
        
        this.updateStatus(loading ? 'Sending...' : 'Ready');
    }
    
    updateStatus(status) {
        if (this.elements.statusText) {
            this.elements.statusText.textContent = status;
        }
        console.log('Status:', status);
    }
    
    showError(message) {
        console.error('Application Error:', message);
        
        // Show error in UI if possible
        if (this.elements.messagesList) {
            const errorDiv = document.createElement('div');
            errorDiv.className = 'message message--error';
            errorDiv.innerHTML = `
                <div class="message__content">
                    <div class="message__text">Error: ${this.escapeHtml(message)}</div>
                </div>
            `;
            this.elements.messagesList.appendChild(errorDiv);
            this.elements.messagesList.scrollTop = this.elements.messagesList.scrollHeight;
        }
    }
    
    showWarning(message) {
        console.warn('Application Warning:', message);
        
        // Show warning in UI if possible
        if (this.elements.messagesList) {
            const warningDiv = document.createElement('div');
            warningDiv.className = 'message message--warning';
            warningDiv.innerHTML = `
                <div class="message__content">
                    <div class="message__text">⚠️ ${this.escapeHtml(message)}</div>
                </div>
            `;
            this.elements.messagesList.appendChild(warningDiv);
            this.elements.messagesList.scrollTop = this.elements.messagesList.scrollHeight;
        }
    }
    
    handleBeforeUnload() {
        // Clean up any pending requests
        console.log('Application shutting down...');
    }
    
    destroy() {
        // Clean up event listeners and resources
        console.log('SimpleChatApplication destroyed');
    }
}

// Initialize application when script loads
console.log('🚀 main.js loading...');

// Create and initialize the application
let chatApp = null;

if (typeof window !== 'undefined') {
    // Browser environment
    chatApp = new SimpleChatApplication();
    
    // Expose to global scope for debugging
    window.chatApp = chatApp;
} else {
    // Node.js environment (for testing)
    console.log('Running in Node.js environment');
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SimpleChatApplication;
}

console.log('✅ main.js loaded successfully');