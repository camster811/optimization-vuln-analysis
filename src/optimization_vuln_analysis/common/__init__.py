"""Method-independent serialization and artifact primitives."""


def require(condition, message):
    if not condition:
        raise ValueError(message)
