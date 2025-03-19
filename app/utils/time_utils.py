"""
Time utility functions.
"""
import time
from datetime import datetime, timezone


def get_current_timestamp() -> int:
    """
    Get the current Unix timestamp.
    
    Returns:
        int: Current Unix timestamp.
    """
    return int(time.time())


def timestamp_to_datetime(timestamp: int) -> datetime:
    """
    Convert a Unix timestamp to a datetime object.
    
    Args:
        timestamp: Unix timestamp.
        
    Returns:
        datetime: Datetime object.
    """
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def is_token_expired(expires_at: int, buffer_seconds: int = 300) -> bool:
    """
    Check if a token is expired or about to expire.
    
    Args:
        expires_at: Token expiration timestamp.
        buffer_seconds: Buffer time in seconds to consider a token as expired.
        
    Returns:
        bool: True if the token is expired or about to expire, False otherwise.
    """
    current_time = get_current_timestamp()
    return current_time >= (expires_at - buffer_seconds) 