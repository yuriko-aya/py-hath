"""
HTTP Session management for tracking and managing client connections.

This module provides session tracking, connection limits, and resource cleanup
for HTTP connections to the H@H client.
"""

import threading
import time
import socket
from typing import Dict, List, Optional, Set
from datetime import datetime
from .out import Out
from .stats import Stats


class HTTPSession:
    """Represents an individual HTTP session/connection."""
    
    def __init__(self, session_id: int, client_address: tuple):
        """Initialize an HTTP session.
        
        Args:
            session_id: Unique session identifier
            client_address: (IP, port) tuple of client
        """
        self.session_id = session_id
        self.client_address = client_address
        self.client_ip = client_address[0]
        self.client_port = client_address[1]
        
        # Timing
        self.start_time = time.time()
        self.last_activity = time.time()
        self.end_time: Optional[float] = None
        
        # Request tracking
        self.requests_served = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        
        # State
        self.active = True
        self.processing_request = False
        self.current_request_path: Optional[str] = None
        
        Out.debug(f"HTTP Session {session_id} started from {self.client_ip}:{self.client_port}")
    
    def update_activity(self):
        """Update the last activity timestamp."""
        self.last_activity = time.time()
    
    def start_processing_request(self, request_path: str):
        """Mark the start of request processing.
        
        Args:
            request_path: The request path being processed
        """
        self.processing_request = True
        self.current_request_path = request_path
        self.update_activity()
        Out.debug(f"Session {self.session_id} processing request: {request_path}")
    
    def end_processing_request(self):
        """Mark the end of request processing."""
        self.processing_request = False
        self.current_request_path = None
        self.update_activity()
    
    def add_bytes_sent(self, bytes_count: int):
        """Add to bytes sent counter.
        
        Args:
            bytes_count: Number of bytes sent
        """
        self.bytes_sent += bytes_count
        self.update_activity()
    
    def add_bytes_received(self, bytes_count: int):
        """Add to bytes received counter.
        
        Args:
            bytes_count: Number of bytes received
        """
        self.bytes_received += bytes_count
        self.update_activity()
    
    def start_request(self, request_path: str):
        """Mark the start of request processing.
        
        Args:
            request_path: The request path being processed
        """
        self.processing_request = True
        self.current_request_path = request_path
        self.update_activity()
        Out.debug(f"Session {self.session_id} processing request: {request_path}")
    
    def end_request(self, bytes_sent: int = 0, bytes_received: int = 0):
        """Mark the end of request processing.
        
        Args:
            bytes_sent: Number of bytes sent in response
            bytes_received: Number of bytes received in request
        """
        self.processing_request = False
        self.current_request_path = None
        self.requests_served += 1
        self.bytes_sent += bytes_sent
        self.bytes_received += bytes_received
        self.update_activity()
        
        # Update global stats
        if bytes_sent > 0:
            Stats.get_instance().add_bytes_sent(bytes_sent)
        if bytes_received > 0:
            Stats.get_instance().add_bytes_received(bytes_received)
        
        Out.debug(f"Session {self.session_id} completed request "
                 f"(sent: {bytes_sent}, received: {bytes_received})")
    
    def close(self):
        """Close the session."""
        if self.active:
            self.active = False
            self.end_time = time.time()
            duration = self.end_time - self.start_time
            
            Out.debug(f"HTTP Session {self.session_id} closed after {duration:.2f}s "
                     f"({self.requests_served} requests, {self.bytes_sent} bytes sent)")
    
    def get_duration(self) -> float:
        """Get session duration in seconds.
        
        Returns:
            Duration in seconds (ongoing sessions return time since start)
        """
        end_time = self.end_time if self.end_time else time.time()
        return end_time - self.start_time
    
    def get_idle_time(self) -> float:
        """Get time since last activity in seconds.
        
        Returns:
            Seconds since last activity
        """
        return time.time() - self.last_activity
    
    def is_expired(self, max_idle_time: float = 300.0) -> bool:
        """Check if session has exceeded maximum idle time.
        
        Args:
            max_idle_time: Maximum idle time in seconds
            
        Returns:
            True if session should be expired
        """
        return self.get_idle_time() > max_idle_time
    
    def get_info(self) -> dict:
        """Get session information as dictionary.
        
        Returns:
            Dictionary with session information
        """
        return {
            'session_id': self.session_id,
            'client_ip': self.client_ip,
            'client_port': self.client_port,
            'start_time': self.start_time,
            'duration': self.get_duration(),
            'idle_time': self.get_idle_time(),
            'active': self.active,
            'processing_request': self.processing_request,
            'current_request': self.current_request_path,
            'requests_served': self.requests_served,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received
        }


class HTTPSessionManager:
    """Manages HTTP sessions and connection limits."""
    
    _instance = None
    _lock = threading.RLock()
    
    def __new__(cls, *args, **kwargs):
        """Ensure singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def get_instance(cls):
        """Get the singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def __init__(self, max_connections: int = 20, max_connections_per_ip: int = 5):
        """Initialize the session manager.
        
        Args:
            max_connections: Maximum concurrent connections
            max_connections_per_ip: Maximum connections per IP address
        """
        # Prevent multiple initialization
        if hasattr(self, '_initialized'):
            return
        
        self.max_connections = max_connections
        self.max_connections_per_ip = max_connections_per_ip
        self._sessions: Dict[int, HTTPSession] = {}
        self._sessions_by_ip: Dict[str, Set[int]] = {}
        self._next_session_id = 1
        self._session_lock = threading.RLock()
        
        # Cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_running = True
        self._cleanup_thread.start()
        
        self._initialized = True
        Out.debug(f"HTTPSessionManager initialized with max {max_connections} connections "
                 f"({max_connections_per_ip} per IP)")
    
    def set_connection_limits(self, max_connections: int, max_connections_per_ip: int):
        """Update connection limits.
        
        Args:
            max_connections: Maximum concurrent connections
            max_connections_per_ip: Maximum connections per IP address
        """
        with self._session_lock:
            self.max_connections = max_connections
            self.max_connections_per_ip = max_connections_per_ip
            Out.debug(f"Updated connection limits: {max_connections} total, {max_connections_per_ip} per IP")
    
    def create_session(self, client_ip: str, client_port: int) -> Optional[HTTPSession]:
        """Create a new HTTP session.
        
        Args:
            client_ip: Client IP address
            client_port: Client port
            
        Returns:
            New HTTPSession or None if connection limit reached
        """
        with self._session_lock:
            # Check connection limits
            if len(self._sessions) >= self.max_connections:
                Out.warning(f"Connection limit reached ({self.max_connections}), "
                           f"rejecting connection from {client_ip}")
                return None
            
            # Check per-IP limits
            ip_sessions = self._sessions_by_ip.get(client_ip, set())
            if len(ip_sessions) >= self.max_connections_per_ip:
                Out.warning(f"Per-IP connection limit reached for {client_ip} "
                           f"({len(ip_sessions)}/{self.max_connections_per_ip})")
                return None
            
            # Create session
            session_id = self._next_session_id
            self._next_session_id += 1
            
            session = HTTPSession(session_id, (client_ip, client_port))
            self._sessions[session_id] = session
            
            # Track by IP
            if client_ip not in self._sessions_by_ip:
                self._sessions_by_ip[client_ip] = set()
            self._sessions_by_ip[client_ip].add(session_id)
            
            # Update stats
            Stats.get_instance().set_open_connections(len(self._sessions))
            
            Out.debug(f"Created session {session_id} for {client_ip} "
                     f"({len(self._sessions)} total connections)")
            
            return session
    
    def get_session(self, session_id: int) -> Optional[HTTPSession]:
        """Get a session by ID.
        
        Args:
            session_id: Session ID to retrieve
            
        Returns:
            HTTPSession or None if not found
        """
        with self._session_lock:
            return self._sessions.get(session_id)
    
    def close_session(self, session_id: int):
        """Close and remove a session.
        
        Args:
            session_id: Session ID to close
        """
        with self._session_lock:
            session = self._sessions.get(session_id)
            if session:
                session.close()
                
                # Remove from tracking
                del self._sessions[session_id]
                
                # Remove from IP tracking
                client_ip = session.client_ip
                if client_ip in self._sessions_by_ip:
                    self._sessions_by_ip[client_ip].discard(session_id)
                    if not self._sessions_by_ip[client_ip]:
                        del self._sessions_by_ip[client_ip]
                
                # Update stats
                Stats.set_open_connections(len(self._sessions))
                
                Out.debug(f"Closed session {session_id} "
                         f"({len(self._sessions)} remaining connections)")
    
    def cleanup_expired_sessions(self, max_idle_time: float = 300.0) -> int:
        """Clean up expired sessions.
        
        Args:
            max_idle_time: Maximum idle time before expiration
            
        Returns:
            Number of sessions cleaned up
        """
        expired_sessions = []
        
        with self._session_lock:
            for session_id, session in self._sessions.items():
                if session.is_expired(max_idle_time):
                    expired_sessions.append(session_id)
        
        # Close expired sessions
        for session_id in expired_sessions:
            Out.debug(f"Closing expired session {session_id}")
            self.close_session(session_id)
            
        return len(expired_sessions)
    
    def get_session_count(self) -> int:
        """Get current number of active sessions.
        
        Returns:
            Number of active sessions
        """
        with self._session_lock:
            return len(self._sessions)
    
    def get_sessions_by_ip(self, client_ip: str) -> List[HTTPSession]:
        """Get all sessions for a specific IP.
        
        Args:
            client_ip: IP address to search for
            
        Returns:
            List of sessions for that IP
        """
        with self._session_lock:
            session_ids = self._sessions_by_ip.get(client_ip, set())
            return [self._sessions[sid] for sid in session_ids if sid in self._sessions]
    
    def get_all_sessions(self) -> List[HTTPSession]:
        """Get all active sessions.
        
        Returns:
            List of all active sessions
        """
        with self._session_lock:
            return list(self._sessions.values())
    
    def get_session_stats(self) -> dict:
        """Get session statistics.
        
        Returns:
            Dictionary with session statistics
        """
        with self._session_lock:
            total_requests = sum(session.requests_served for session in self._sessions.values())
            total_bytes_sent = sum(session.bytes_sent for session in self._sessions.values())
            total_bytes_received = sum(session.bytes_received for session in self._sessions.values())
            
            processing_count = sum(1 for session in self._sessions.values() 
                                 if session.processing_request)
            
            # IP distribution
            ips = list(self._sessions_by_ip.keys())
            
            return {
                'active_sessions': len(self._sessions),
                'max_connections': self.max_connections,
                'sessions_processing': processing_count,
                'total_requests_this_session': total_requests,
                'total_bytes_sent_this_session': total_bytes_sent,
                'total_bytes_received_this_session': total_bytes_received,
                'unique_ips': len(ips),
                'client_ips': ips[:10]  # First 10 IPs
            }
    
    def get_stats(self) -> dict:
        """Get session statistics (alias for get_session_stats)."""
        return self.get_session_stats()
    
    def _cleanup_loop(self):
        """Background cleanup loop for expired sessions."""
        while self._cleanup_running:
            try:
                self.cleanup_expired_sessions()
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                Out.error(f"Error in session cleanup loop: {e}")
                time.sleep(60)  # Wait longer after error
    
    def shutdown(self):
        """Shutdown the session manager."""
        Out.debug("Shutting down HTTP session manager")
        self._cleanup_running = False
        
        # Close all sessions
        with self._session_lock:
            session_ids = list(self._sessions.keys())
            for session_id in session_ids:
                self.close_session(session_id)
        
        Out.debug("HTTP session manager shutdown complete")
