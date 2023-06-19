def vert(condition: bool, message: str = '') -> None:
    """Replacement for assert preconditions. Raises ValueError with the
        given message if the condition check fails.
    """
    if condition:
        return
    raise ValueError(message)

def tert(condition: bool, message: str = '') -> None:
    """Replacement for assert preconditions. Raises TypeError with the
        given message if the condition check fails.
    """
    if condition:
        return
    raise TypeError(message)
