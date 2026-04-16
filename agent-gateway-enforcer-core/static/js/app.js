// Agent Gateway Enforcer - Dashboard Application

class DashboardApp {
    constructor() {
        this.apiUrl = window.location.origin;
        this.ws = null;
        this.wsReconnectAttempts = 0;
        this.maxReconnectAttempts = 10;
        this.reconnectDelay = 1000;
        this.config = null;
        this.originalConfig = null;
        
        this.init();
    }

    init() {
        console.log('Initializing Dashboard App...');
        this.setupTabs();
        this.setupEventHandlers();
        this.connectWebSocket();
        this.loadInitialData();
        this.startPeriodicUpdates();
    }

    // Tab Navigation
    setupTabs() {
        const tabButtons = document.querySelectorAll('.tab-button');
        const tabContents = document.querySelectorAll('.tab-content');

        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const tabId = button.getAttribute('data-tab');
                
                // Update active states
                tabButtons.forEach(btn => btn.classList.remove('active'));
                tabContents.forEach(content => content.classList.remove('active'));
                
                button.classList.add('active');
                document.getElementById(tabId).classList.add('active');
                
                // Load tab-specific data
                this.onTabChange(tabId);
            });
        });
    }

    onTabChange(tabId) {
        switch(tabId) {
            case 'metrics':
                this.loadMetrics();
                break;
            case 'events':
                this.loadEvents();
                break;
            case 'config':
                this.loadConfig();
                break;
            case 'agents':
                this.loadAgents();
                break;
            case 'logs':
                // Logs are updated via WebSocket
                break;
        }
    }

    // Event Handlers
    setupEventHandlers() {
        // Metrics
        document.getElementById('refresh-metrics')?.addEventListener('click', () => {
            this.loadMetrics();
        });

        // Events
        document.getElementById('refresh-events')?.addEventListener('click', () => {
            this.loadEvents();
        });

        // Configuration
        document.getElementById('edit-config')?.addEventListener('click', () => {
            this.enableConfigEdit();
        });

        document.getElementById('save-config')?.addEventListener('click', () => {
            this.saveConfig();
        });

        document.getElementById('cancel-config')?.addEventListener('click', () => {
            this.cancelConfigEdit();
        });

        // Logs
        document.getElementById('clear-logs')?.addEventListener('click', () => {
            this.clearLogs();
        });
    }

    // WebSocket Connection
    connectWebSocket() {
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws`;
        
        console.log('Connecting to WebSocket:', wsUrl);
        
        try {
            this.ws = new WebSocket(wsUrl);
            
            this.ws.onopen = () => {
                console.log('WebSocket connected');
                this.wsReconnectAttempts = 0;
                this.updateWSStatus('connected');
                this.updateStatusIndicator('online');
            };
            
            this.ws.onmessage = (event) => {
                this.handleWebSocketMessage(event.data);
            };
            
            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateWSStatus('error');
            };
            
            this.ws.onclose = () => {
                console.log('WebSocket disconnected');
                this.updateWSStatus('disconnected');
                this.updateStatusIndicator('offline');
                this.scheduleReconnect();
            };
        } catch (error) {
            console.error('Failed to create WebSocket:', error);
            this.updateWSStatus('error');
            this.scheduleReconnect();
        }
    }

    scheduleReconnect() {
        if (this.wsReconnectAttempts < this.maxReconnectAttempts) {
            this.wsReconnectAttempts++;
            const delay = this.reconnectDelay * Math.pow(2, this.wsReconnectAttempts - 1);
            console.log(`Reconnecting in ${delay}ms (attempt ${this.wsReconnectAttempts}/${this.maxReconnectAttempts})`);
            setTimeout(() => this.connectWebSocket(), delay);
        } else {
            console.error('Max reconnection attempts reached');
        }
    }

    handleWebSocketMessage(data) {
        try {
            const message = JSON.parse(data);
            
            switch(message.type) {
                case 'Event':
                    this.handleEvent(message.data);
                    break;
                case 'Metrics':
                    this.handleMetrics(message.data);
                    break;
                case 'Status':
                    this.handleStatus(message.data);
                    break;
                case 'Pong':
                    // Heartbeat response
                    break;
                case 'Error':
                    console.error('WebSocket error:', message.data);
                    this.addLog('error', message.data);
                    break;
                default:
                    console.log('Unknown message type:', message.type);
            }
            
            this.updateLastUpdate();
        } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
        }
    }

    // API Calls
    async apiCall(endpoint, options = {}) {
        try {
            const response = await fetch(`${this.apiUrl}${endpoint}`, {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.error(`API call failed for ${endpoint}:`, error);
            this.addLog('error', `API call failed: ${error.message}`);
            throw error;
        }
    }

    async loadInitialData() {
        await this.loadStatus();
    }

    async loadStatus() {
        try {
            const data = await this.apiCall('/api/v1/status');
            this.updateStatus(data);
        } catch (error) {
            console.error('Failed to load status:', error);
        }
    }

    async loadMetrics() {
        try {
            const timeRange = document.getElementById('metrics-time-range')?.value;
            const endpoint = timeRange ? `/api/v1/metrics?time_range=${timeRange}` : '/api/v1/metrics';
            
            const data = await this.apiCall(endpoint);
            this.updateMetrics(data);
        } catch (error) {
            console.error('Failed to load metrics:', error);
        }
    }

    async loadEvents() {
        try {
            const filter = document.getElementById('event-filter')?.value || '';
            const limit = document.getElementById('event-limit')?.value || '50';
            
            let endpoint = '/api/v1/events?';
            if (filter) endpoint += `filter=${encodeURIComponent(filter)}&`;
            endpoint += `limit=${limit}`;
            
            const data = await this.apiCall(endpoint);
            this.updateEvents(data);
        } catch (error) {
            console.error('Failed to load events:', error);
        }
    }

    async loadConfig() {
        try {
            const data = await this.apiCall('/api/v1/config');
            this.config = data.config;
            this.originalConfig = JSON.parse(JSON.stringify(data.config));
            this.updateConfigDisplay();
        } catch (error) {
            console.error('Failed to load config:', error);
        }
    }

    async saveConfig() {
        try {
            const configText = document.getElementById('config-content').textContent;
            const newConfig = JSON.parse(configText);
            
            await this.apiCall('/api/v1/config', {
                method: 'PUT',
                body: JSON.stringify(newConfig)
            });
            
            this.config = newConfig;
            this.originalConfig = JSON.parse(JSON.stringify(newConfig));
            this.disableConfigEdit();
            this.addLog('info', 'Configuration saved successfully');
        } catch (error) {
            console.error('Failed to save config:', error);
            alert(`Failed to save configuration: ${error.message}`);
        }
    }

    async loadAgents() {
        // Placeholder for agent data
        const tbody = document.getElementById('agents-table-body');
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No agents connected</td></tr>';
    }

    // UI Updates
    updateStatus(data) {
        document.getElementById('system-status-value').textContent = data.status;
        document.getElementById('version-value').textContent = data.version;
        document.getElementById('uptime-value').textContent = this.formatUptime(data.uptime_seconds);
        document.getElementById('backend-value').textContent = data.backend;
        document.getElementById('active-connections').textContent = data.active_connections;
        document.getElementById('footer-version').textContent = data.version;
        
        if (data.status === 'running') {
            this.updateStatusIndicator('online');
        }
    }

    updateMetrics(data) {
        const container = document.getElementById('metrics-display');
        
        if (!data.metrics || Object.keys(data.metrics).length === 0) {
            container.innerHTML = '<p class="empty-state">No metrics available</p>';
            return;
        }
        
        container.innerHTML = '';
        
        // Display metrics
        for (const [key, value] of Object.entries(data.metrics)) {
            const metricEl = document.createElement('div');
            metricEl.className = 'metric-item';
            metricEl.innerHTML = `
                <div class="metric-label">${this.formatMetricName(key)}</div>
                <div class="metric-number">${this.formatMetricValue(value)}</div>
            `;
            container.appendChild(metricEl);
        }
        
        // Update metrics summary on dashboard
        this.updateMetricsSummary(data.metrics);
    }

    updateMetricsSummary(metrics) {
        const container = document.getElementById('metrics-summary');
        
        if (!metrics || Object.keys(metrics).length === 0) {
            container.innerHTML = '<p class="empty-state">No metrics available</p>';
            return;
        }
        
        container.innerHTML = '';
        
        // Show top 5 metrics
        const entries = Object.entries(metrics).slice(0, 5);
        entries.forEach(([key, value]) => {
            const stat = document.createElement('div');
            stat.className = 'stat';
            stat.innerHTML = `
                <span class="label">${this.formatMetricName(key)}:</span>
                <span class="value">${this.formatMetricValue(value)}</span>
            `;
            container.appendChild(stat);
        });
    }

    updateEvents(data) {
        const container = document.getElementById('events-display');
        
        if (!data.events || data.events.length === 0) {
            container.innerHTML = '<p class="empty-state">No events to display</p>';
            return;
        }
        
        container.innerHTML = '';
        
        data.events.forEach(event => {
            const eventEl = document.createElement('div');
            eventEl.className = 'event-item';
            eventEl.innerHTML = `
                <div class="event-time">${new Date(event.timestamp || Date.now()).toLocaleString()}</div>
                <div class="event-type">${event.event_type || 'Unknown'}</div>
                <div class="event-details">${event.description || JSON.stringify(event)}</div>
            `;
            container.appendChild(eventEl);
        });
        
        // Update recent events on dashboard
        this.updateRecentEvents(data.events.slice(0, 5));
    }

    updateRecentEvents(events) {
        const container = document.getElementById('recent-events');
        
        if (!events || events.length === 0) {
            container.innerHTML = '<p class="empty-state">No recent events</p>';
            return;
        }
        
        container.innerHTML = '';
        
        events.forEach(event => {
            const eventEl = document.createElement('div');
            eventEl.className = 'event-item';
            eventEl.innerHTML = `
                <div class="event-time">${new Date(event.timestamp || Date.now()).toLocaleTimeString()}</div>
                <div class="event-type">${event.event_type || 'Unknown'}</div>
            `;
            container.appendChild(eventEl);
        });
    }

    updateConfigDisplay() {
        const content = document.getElementById('config-content');
        if (this.config) {
            content.textContent = JSON.stringify(this.config, null, 2);
        }
    }

    enableConfigEdit() {
        const content = document.getElementById('config-content');
        content.contentEditable = true;
        content.classList.add('editable');
        
        document.getElementById('edit-config').disabled = true;
        document.getElementById('save-config').disabled = false;
        document.getElementById('cancel-config').disabled = false;
    }

    disableConfigEdit() {
        const content = document.getElementById('config-content');
        content.contentEditable = false;
        content.classList.remove('editable');
        
        document.getElementById('edit-config').disabled = false;
        document.getElementById('save-config').disabled = true;
        document.getElementById('cancel-config').disabled = true;
    }

    cancelConfigEdit() {
        this.config = JSON.parse(JSON.stringify(this.originalConfig));
        this.updateConfigDisplay();
        this.disableConfigEdit();
    }

    updateStatusIndicator(status) {
        const indicator = document.getElementById('status-indicator');
        const statusText = document.getElementById('status-text');
        
        indicator.className = `status-indicator ${status}`;
        
        switch(status) {
            case 'online':
                statusText.textContent = 'Online';
                break;
            case 'offline':
                statusText.textContent = 'Offline';
                break;
            default:
                statusText.textContent = 'Connecting...';
        }
    }

    updateWSStatus(status) {
        const wsStatus = document.getElementById('ws-status');
        
        switch(status) {
            case 'connected':
                wsStatus.textContent = 'Connected';
                wsStatus.className = 'connected';
                break;
            case 'disconnected':
                wsStatus.textContent = 'Disconnected';
                wsStatus.className = 'disconnected';
                break;
            case 'error':
                wsStatus.textContent = 'Error';
                wsStatus.className = 'disconnected';
                break;
        }
    }

    updateLastUpdate() {
        const lastUpdate = document.getElementById('last-update');
        lastUpdate.textContent = new Date().toLocaleTimeString();
    }

    // Event Handlers from WebSocket
    handleEvent(event) {
        this.addLog('info', `Event: ${JSON.stringify(event)}`);
        // Refresh events if on events tab
        const activeTab = document.querySelector('.tab-button.active');
        if (activeTab && activeTab.getAttribute('data-tab') === 'events') {
            this.loadEvents();
        }
    }

    handleMetrics(metrics) {
        // Update metrics if on metrics tab
        const activeTab = document.querySelector('.tab-button.active');
        if (activeTab && activeTab.getAttribute('data-tab') === 'metrics') {
            this.updateMetrics({ timestamp: new Date().toISOString(), metrics });
        }
    }

    handleStatus(status) {
        this.updateStatus(status);
    }

    // Logging
    addLog(level, message) {
        const container = document.getElementById('logs-display');
        
        // Remove empty state if present
        const emptyState = container.querySelector('.empty-state');
        if (emptyState) {
            container.innerHTML = '';
        }
        
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${level}`;
        logEntry.innerHTML = `
            <span class="log-time">[${new Date().toLocaleTimeString()}]</span>
            <span class="log-level">[${level.toUpperCase()}]</span>
            <span class="log-message">${message}</span>
        `;
        
        container.appendChild(logEntry);
        
        // Auto-scroll if enabled
        const autoScroll = document.getElementById('auto-scroll-logs');
        if (autoScroll && autoScroll.checked) {
            container.scrollTop = container.scrollHeight;
        }
        
        // Limit log entries
        const maxLogs = 1000;
        while (container.children.length > maxLogs) {
            container.removeChild(container.firstChild);
        }
    }

    clearLogs() {
        const container = document.getElementById('logs-display');
        container.innerHTML = '<p class="empty-state">Waiting for log messages...</p>';
    }

    // Utilities
    formatUptime(seconds) {
        if (seconds < 60) return `${seconds}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
        return `${Math.floor(seconds / 86400)}d`;
    }

    formatMetricName(name) {
        return name
            .split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    formatMetricValue(value) {
        if (typeof value === 'number') {
            return value.toLocaleString();
        }
        return String(value);
    }

    startPeriodicUpdates() {
        // Update status every 30 seconds
        setInterval(() => {
            this.loadStatus();
        }, 30000);
        
        // Send WebSocket ping every 30 seconds
        setInterval(() => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(JSON.stringify({ type: 'Ping' }));
            }
        }, 30000);
    }
}

// Initialize app when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.dashboardApp = new DashboardApp();
    });
} else {
    window.dashboardApp = new DashboardApp();
}
