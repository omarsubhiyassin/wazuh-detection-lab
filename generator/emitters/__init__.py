"""Format-accurate log-line emitters.

Each function is pure: given a timestamp and fields, it returns one log line in
a REAL product format, so Wazuh's built-in decoders parse it. No I/O here.
"""
