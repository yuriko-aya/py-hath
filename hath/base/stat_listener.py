"""
Statistics listener interface for receiving stat change notifications.
"""

from abc import ABC, abstractmethod


class StatListener(ABC):
    """Interface for classes that want to be notified of statistics changes."""
    
    @abstractmethod
    def stat_changed(self, stat_name: str):
        """Called when a statistic has changed.
        
        Args:
            stat_name: Name of the statistic that changed
        """
        pass
