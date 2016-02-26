from zwnflibs import logging

__author__ = 'Lennart Grahl'

# Logging
logging_level = logging.DEBUG
logging_formatter = '{asctime} {name:<22} {levelname:<18} {message}'
logging_date_formatter = '%Y-%m-%d %H:%M:%S'
logging_style = '{'

# Signaling
path_length = 64
ping_timeout = 10.0
ping_interval = 60.0
# Signaling messages
field_type = 'type'
field_data = 'data'
type_hello_server = 'hello-server'
type_hello_client = 'hello-client'
type_reset = 'reset'
type_key = 'key'
type_send_error = 'send-error'
