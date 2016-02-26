"""
Guess we should override this with some
whatever-configuration-is-in-now config file.
"""

# Logging
logging = True
log_level = 'DEBUG'

# Keep-Alive settings
ping_timeout = 10.0
ping_interval = 60.0

# TODO: This stuff should not be in here as it is constant
# Signalling
path_length = 64
# Signalling messages
field_type = 'type'
field_data = 'data'
type_hello_server = 'hello-server'
type_hello_client = 'hello-client'
type_reset = 'reset'
type_key = 'key'
type_send_error = 'send-error'
