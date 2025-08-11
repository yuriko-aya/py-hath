"""
Client API Result class for representing API command results.
"""


class ClientAPIResult:
    """Represents the result of a client API command."""
    
    def __init__(self, command: int, result_text: str):
        """Initialize a ClientAPIResult.
        
        Args:
            command: The command ID that was executed
            result_text: The result text ("OK", "FAIL", etc.)
        """
        self.command = command
        self.result_text = result_text
    
    def get_result_text(self) -> str:
        """Get the result text."""
        return self.result_text
    
    def __str__(self) -> str:
        """String representation of the result."""
        return f"{{ClientAPIResult: command={self.command}, resultText={self.result_text}}}"
    
    def __repr__(self) -> str:
        """Debug representation of the result."""
        return self.__str__()
