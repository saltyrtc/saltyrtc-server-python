"""
The tests provided in this module make sure that the server
instance behaves as expected.
"""

import pytest

from saltyrtc import server


class TestServer:
    @pytest.mark.asyncio
    def test_repeated_permanent_keys(self, server_permanent_keys):
        """
        Ensure the server does not accept repeated keys.
        """
        keys = server_permanent_keys + [server_permanent_keys[1]]
        with pytest.raises(server.ServerKeyError) as exc_info:
            yield from server.serve(None, keys)
        assert 'Repeated permanent keys' in str(exc_info.value)
