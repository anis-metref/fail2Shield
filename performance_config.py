"""
Performance configuration for Fail2Shield Dashboard
"""

# Cache settings
CACHE_DURATION = 30  # seconds for main data
GEO_CACHE_DURATION = 3600  # seconds for geolocation data
SSH_LOG_CACHE_DURATION = 60  # seconds for SSH logs

# Performance settings
MAX_LOG_LINES = 500  # Reduce from 1000 to improve performance
MAX_BANNED_IPS_DISPLAY = 100  # Limit displayed IPs
BATCH_SIZE = 10  # Process IPs in batches

# UI optimization
ENABLE_AUTO_REFRESH = True
AUTO_REFRESH_INTERVAL = 60  # Increase interval to reduce load
LAZY_LOAD_GEOLOCATION = True  # Load geolocation on demand

# API optimization
IP_API_BATCH_SIZE = 5  # Process geolocation in batches
IP_API_TIMEOUT = 3  # Reduce timeout for faster response
MAX_CONCURRENT_REQUESTS = 3  # Limit concurrent API calls