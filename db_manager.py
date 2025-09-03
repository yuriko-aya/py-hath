import os
import sqlite3
import threading
import logging
from contextlib import contextmanager
from typing import Optional, Tuple, List

logger = logging.getLogger(__name__)

db_path = os.path.join('data', 'pcache.db')

# Thread-local storage for database connections
_thread_local = threading.local()

def _get_connection():
    """Get a thread-local database connection."""
    if not hasattr(_thread_local, 'connection'):
        _thread_local.connection = sqlite3.connect(
            db_path, 
            timeout=30.0,  # 30 second timeout
            check_same_thread=False
        )
        # Enable WAL mode for better concurrency
        _thread_local.connection.execute('PRAGMA journal_mode=WAL')
        # Enable foreign keys
        _thread_local.connection.execute('PRAGMA foreign_keys=ON')
    return _thread_local.connection

@contextmanager
def get_db_connection():
    """Context manager for database connections with proper error handling."""
    conn = None
    try:
        conn = _get_connection()
        yield conn
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Database operation failed: {e}")
        raise
    # Note: We don't close the connection here as it's thread-local and reused

def close_thread_connection():
    """Close the thread-local connection. Call this when thread is ending."""
    if hasattr(_thread_local, 'connection'):
        try:
            _thread_local.connection.close()
            delattr(_thread_local, 'connection')
        except Exception as e:
            logger.warning(f"Error closing thread-local database connection: {e}")

def initialize_database():
    """Initialize the database schema if it doesn't exist."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    # Use direct SQLite connection for initialization (runs only once at startup)
    conn = sqlite3.connect(db_path, timeout=30.0)
    try:
        # Enable WAL mode for better concurrency
        conn.execute('PRAGMA journal_mode=WAL')
        # Enable foreign keys
        conn.execute('PRAGMA foreign_keys=ON')
        
        # Check if tables exist
        cursor = conn.cursor()
        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name IN ('cache', 'cache_info');
        """)
        existing = {row[0] for row in cursor.fetchall()}
        if {"cache", "cache_info"}.issubset(existing):
            cursor.execute("""SELECT cache_count FROM cache_info""")
            cache_info = cursor.fetchone()
            if cache_info is not None:
                logger.debug('Database already initialized')
                return False
            else:
                logger.warning('Database tables exist but cache_info is missing data, reinitializing')
            
        # Create tables
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS cache (
                static_range TEXT PRIMARY KEY,
                count INTEGER DEFAULT 0,
                last_access TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS cache_info (
                cache_count INTEGER DEFAULT 0,
                cache_size INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_last_access ON cache(last_access);
            
            INSERT OR IGNORE INTO cache_info (cache_count, cache_size) VALUES (0, 0);
        ''')
        conn.commit()
        logger.info("Database initialized successfully")
        return True
        
    finally:
        conn.close()

def get_oldest_static_range() -> Tuple[Optional[str], Optional[int]]:
    """Get the oldest static range by last access time."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT static_range, strftime("%s", last_access) 
                FROM cache 
                ORDER BY last_access ASC 
                LIMIT 1
            ''')
            row = cursor.fetchone()
            if row:
                return row[0], int(row[1])  # Return (static_range, unix_timestamp)
            return None, None
    except Exception as e:
        logger.error(f"Error getting oldest static range: {e}")
        return None, None

def update_last_access(static_range: str, new_file: bool = False) -> bool:
    """Update the last access time for a static range."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # If just accessing existing file, only update last_access
            if new_file:
                cursor.execute('''
                    INSERT INTO cache (static_range, count, last_access) 
                    VALUES (?, 1, CURRENT_TIMESTAMP)
                    ON CONFLICT(static_range) 
                    DO UPDATE SET last_access = CURRENT_TIMESTAMP, count = count + 1
                ''', (static_range,))
                # Update the total cache count when adding a new file, using the same connection
                update_cache_count(conn)
            else:
                cursor.execute('''
                    INSERT INTO cache (static_range, count, last_access) 
                    VALUES (?, 0, CURRENT_TIMESTAMP)
                    ON CONFLICT(static_range) 
                    DO UPDATE SET last_access = CURRENT_TIMESTAMP
                ''', (static_range,))
            return True
    except Exception as e:
        logger.error(f"Error updating last access for {static_range}: {e}")
        return False

def update_file_count(static_range: str, removal: bool = False) -> bool:
    """Update the file count for a static range."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            if removal:
                # If removing file, decrement count but don't go below 0
                # Don't update last_access when removing files
                cursor.execute('''
                    UPDATE cache 
                    SET count = MAX(count - 1, 0)
                    WHERE static_range = ?
                ''', (static_range,))
            else:
                # If adding file, increment count and update last_access
                cursor.execute('''
                    INSERT INTO cache (static_range, count, last_access) 
                    VALUES (?, 1, CURRENT_TIMESTAMP)
                    ON CONFLICT(static_range) 
                    DO UPDATE SET count = count + 1, last_access = CURRENT_TIMESTAMP
                ''', (static_range,))
            
            # Update the total cache count using the same connection/transaction
            update_cache_count(conn)
            return True
    except Exception as e:
        logger.error(f"Error updating file count for {static_range}: {e}")
        return False

def update_file_size(file_size: int, removal: bool = False):
    """Update total cache size"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Ensure cache_info table has at least one row
            cursor.execute('SELECT COUNT(*) FROM cache_info')
            if cursor.fetchone()[0] == 0:
                cursor.execute('INSERT INTO cache_info (cache_count, cache_size) VALUES (0, 0)')
            
            if removal:
                cursor.execute('''
                    UPDATE cache_info
                    SET cache_size = MAX(cache_size - ?, 0)
                ''', (file_size,))
            else:
                cursor.execute('''
                    UPDATE cache_info
                    SET cache_size = cache_size + ?
                ''', (file_size,))
            
            # Verify the update worked
            if cursor.rowcount == 0:
                logger.warning("No rows were updated in cache_info table")
                return False
            
            return True
    except Exception as e:
        logger.error(f"Error updating file size: {e}")
        return False

def update_cache_count(conn=None):
    """Update the total cache count based on the sum of all static range counts."""
    try:
        # Use provided connection or create a new one
        if conn is not None:
            cursor = conn.cursor()
            
            # Ensure cache_info table has at least one row
            cursor.execute('SELECT COUNT(*) FROM cache_info')
            if cursor.fetchone()[0] == 0:
                cursor.execute('INSERT INTO cache_info (cache_count, cache_size) VALUES (0, 0)')
            
            # Calculate total count from all static ranges
            cursor.execute('SELECT COALESCE(SUM(count), 0) FROM cache')
            total_count = cursor.fetchone()[0]
            
            # Update the cache_info table
            cursor.execute('UPDATE cache_info SET cache_count = ?', (total_count,))
            
            if cursor.rowcount == 0:
                logger.warning("No rows were updated in cache_info table for count")
                return False
            
            return True
        else:
            # Fallback to creating own connection if none provided
            with get_db_connection() as conn:
                return update_cache_count(conn)
            
    except Exception as e:
        logger.error(f"Error updating cache count: {e}")
        return False

def recalculate_cache_totals():
    """Recalculate both cache count and size from actual data. Use for database repair/validation."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Ensure cache_info table has at least one row
            cursor.execute('SELECT COUNT(*) FROM cache_info')
            if cursor.fetchone()[0] == 0:
                cursor.execute('INSERT INTO cache_info (cache_count, cache_size) VALUES (0, 0)')
            
            # Calculate total count from all static ranges
            cursor.execute('SELECT COALESCE(SUM(count), 0) FROM cache')
            total_count = cursor.fetchone()[0]
            
            # For size, we'd need to scan the actual files since we don't store per-range sizes
            # For now, just update the count and leave size as-is
            cursor.execute('UPDATE cache_info SET cache_count = ?', (total_count,))
            
            if cursor.rowcount == 0:
                logger.warning("No rows were updated in cache_info table for recalculation")
                return False
            
            logger.info(f"Cache totals recalculated: {total_count} files")
            return True
    except Exception as e:
        logger.error(f"Error recalculating cache totals: {e}")
        return False

def clean_up_data() -> bool:
    """Clean up the cache database by removing all entries."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Delete all entries (as per original implementation)
            cursor.execute('DELETE FROM cache')
            cursor.execute('DELETE FROM cache_info')
            rows_deleted = cursor.rowcount
            logger.info(f"Cleaned up {rows_deleted} cache entries")
            return True
    except Exception as e:
        logger.error(f"Error cleaning up cache data: {e}")
        return False

def get_static_range_list() -> List[str]:
    """Get a list of all static ranges in the cache."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT static_range FROM cache')
            rows = cursor.fetchall()
            return [row[0] for row in rows]
    except Exception as e:
        logger.error(f"Error getting static range list: {e}")
        return []

def remove_static_range(static_range: str) -> bool:
    """Remove a static range from the cache."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM cache WHERE static_range = ?', (static_range,))
            success = cursor.rowcount > 0
            if success:
                # Update the total cache count after removing a static range using same connection
                update_cache_count(conn)
            return success
    except Exception as e:
        logger.error(f"Error removing static range {static_range}: {e}")
        return False

def get_cache_size():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT cache_size FROM cache_info')
            row = cursor.fetchone()
            if row:
                return row[0] or 0
            return 0
    except Exception as e:
        logger.error(f"Error getting cache size: {e}")
        return 0

def get_cache_count():
    """Get the total number of files in cache."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT cache_count FROM cache_info')
            row = cursor.fetchone()
            if row:
                return row[0] or 0
            return 0
    except Exception as e:
        logger.error(f"Error getting cache count: {e}")
        return 0

def get_cache_stats() -> dict:
    """Get cache statistics for monitoring."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_ranges,
                    SUM(count) as total_files,
                    AVG(count) as avg_files_per_range,
                    MIN(last_access) as oldest_access,
                    MAX(last_access) as newest_access
                FROM cache
            ''')
            row = cursor.fetchone()
            if row:
                return {
                    'total_ranges': row[0] or 0,
                    'total_files': row[1] or 0,
                    'avg_files_per_range': round(row[2] or 0, 2),
                    'oldest_access': row[3],
                    'newest_access': row[4]
                }
            return {}
    except Exception as e:
        logger.error(f"Error getting cache stats: {e}")
        return {}

# Cleanup function to be called on shutdown
def cleanup_connections():
    """Clean up all database connections. Call this on application shutdown."""
    close_thread_connection()
    logger.debug("Database connections cleaned up")