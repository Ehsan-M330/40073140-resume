// Configuration file for API endpoints
// Update these values for production deployment

const CONFIG = {
    // Backend API URL
    // For local development: 'http://localhost:8000'
    // For production: 'https://your-backend-domain.com'
    API_BASE_URL: 'http://localhost:8000',
    
    // WebSocket URL
    // For local development: 'ws://localhost:8000'
    // For production: 'wss://your-backend-domain.com'
    WS_BASE_URL: 'ws://localhost:8000'
};

// Make it available globally
if (typeof window !== 'undefined') {
    window.CONFIG = CONFIG;
}

