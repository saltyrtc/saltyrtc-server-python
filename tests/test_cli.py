import binascii
import os
import stat
import subprocess

import pytest

from saltyrtc.server import __version__ as _version
from saltyrtc.server import Server


class TestCLI:
    @pytest.mark.asyncio
    def test_invalid_command(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            yield from cli('meow')
        assert 'No such command "meow"' in exc_info.value.output

    @pytest.mark.asyncio
    def test_invalid_verbosity(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            yield from cli('-v', '8')
        assert 'is not in the valid range' in exc_info.value.output

    @pytest.mark.asyncio
    def test_import_error_logbook(self, cli, fake_logbook_env):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            yield from cli('-v', '7', 'serve', env=fake_logbook_env)
        assert ('Please install saltyrtc.server[logging] for '
                'logging support') in exc_info.value.output

    @pytest.mark.asyncio
    def test_get_version(self, cli):
        output = yield from cli('version')
        assert 'Version: {}'.format(_version) in output
        assert str(Server.subprotocols) in output

    @pytest.mark.asyncio
    def test_generate_key_invalid_path(self, cli, tmpdir):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            yield from cli('generate', str(tmpdir))
        assert 'is a directory' in exc_info.value.output

    @pytest.mark.asyncio
    def test_generate_key_invalid_permissions(self, cli, tmpdir):
        keyfile = tmpdir.join('keyfile.key')
        keyfile.write('meow')
        keyfile.chmod(stat.S_IREAD)
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            yield from cli('generate', str(keyfile))
        assert 'is not writable' in exc_info.value.output

    @pytest.mark.asyncio
    def test_generate_key(self, cli, tmpdir):
        keyfile = tmpdir.join('keyfile.key')
        print((yield from cli('generate', str(keyfile))))

        # Check length
        key = binascii.unhexlify(keyfile.read())
        assert len(key) == 32

        # Check permissions
        stat_result = os.stat(str(keyfile))
        permissions = stat_result.st_mode
        assert permissions & stat.S_IRWXU == stat.S_IRUSR | stat.S_IWUSR
