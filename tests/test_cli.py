import binascii
import os
import signal
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
        output = yield from cli('-v', '7', '-c', 'version')
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
        yield from cli('generate', str(keyfile))

        # Check length
        key = binascii.unhexlify(keyfile.read())
        assert len(key) == 32

        # Check permissions
        stat_result = os.stat(str(keyfile))
        permissions = stat_result.st_mode
        assert permissions & stat.S_IRWXU == stat.S_IRUSR | stat.S_IWUSR

    @pytest.mark.asyncio
    def test_serve_key_missing(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            yield from cli('serve', '-k', pytest.saltyrtc.permanent_key)
        assert 'It is REQUIRED' in exc_info.value.output

    @pytest.mark.asyncio
    def test_serve_cert_missing(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            yield from cli('serve', '-sc', pytest.saltyrtc.cert)
        assert 'It is REQUIRED' in exc_info.value.output

    @pytest.mark.asyncio
    def test_serve_invalid_cert(self, cli, tmpdir):
        cert = tmpdir.join('cert.pem')
        cert.write('meowmeow')
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            yield from cli('serve', '-sc', str(cert), '-k', pytest.saltyrtc.permanent_key)
        assert 'ssl.SSLError' in exc_info.value.output

    @pytest.mark.asyncio
    def test_serve_invalid_key(self, cli, tmpdir):
        keyfile = tmpdir.join('keyfile.key')
        keyfile.write('6d656f77')
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            yield from cli('serve', '-sc', pytest.saltyrtc.cert, '-k', str(keyfile))
        assert 'ValueError' in exc_info.value.output

    @pytest.mark.asyncio
    def test_serve_invalid_host(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            yield from cli(
                'serve',
                '-sc', pytest.saltyrtc.cert,
                '-k', pytest.saltyrtc.permanent_key,
                '-h', 'meow',
            )
        assert 'Name or service not known' in exc_info.value.output

    @pytest.mark.asyncio
    def test_serve_invalid_port(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            yield from cli(
                'serve',
                '-sc', pytest.saltyrtc.cert,
                '-k', pytest.saltyrtc.permanent_key,
                '-p', 'meow',
            )
        assert 'is not a valid integer' in exc_info.value.output

    @pytest.mark.asyncio
    def test_serve_invalid_loop(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            yield from cli(
                'serve',
                '-sc', pytest.saltyrtc.cert,
                '-k', pytest.saltyrtc.permanent_key,
                '-l', 'meow',
            )
        assert 'invalid choice' in exc_info.value.output

    @pytest.saltyrtc.no_uvloop
    @pytest.mark.asyncio
    def test_serve_uvloop_unavailable(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            yield from cli(
                'serve',
                '-sc', pytest.saltyrtc.cert,
                '-k', pytest.saltyrtc.permanent_key,
                '-l', 'uvloop',
            )
        assert "Cannot use event loop 'uvloop'" in exc_info.value.output

    @pytest.mark.asyncio
    def test_serve_asyncio(self, cli, timeout_factory):
        output = yield from cli(
            'serve',
            '-sc', pytest.saltyrtc.cert,
            '-k', pytest.saltyrtc.permanent_key,
            '-p', '8443',
            timeout=timeout_factory(),
            signal=signal.SIGINT,
        )
        assert 'Stopped' in output

    @pytest.mark.asyncio
    def test_serve_asyncio_plus_logging(self, cli, timeout_factory):
        output = yield from cli(
            '-v', '7',
            'serve',
            '-sc', pytest.saltyrtc.cert,
            '-k', pytest.saltyrtc.permanent_key,
            '-p', '8443',
            timeout=timeout_factory(),
            signal=signal.SIGINT,
        )
        assert 'Server instance' in output
        assert 'Closing protocols' in output

    @pytest.saltyrtc.have_uvloop
    @pytest.mark.asyncio
    def test_serve_uvloop(self, cli, timeout_factory):
        output = yield from cli(
            'serve',
            '-sc', pytest.saltyrtc.cert,
            '-k', pytest.saltyrtc.permanent_key,
            '-p', '8443',
            '-l', 'uvloop',
            timeout=timeout_factory(),
            signal=signal.SIGINT,
        )
        assert 'Stopped' in output

    @pytest.saltyrtc.have_uvloop
    @pytest.mark.asyncio
    def test_serve_uvloop_plus_logging(self, cli, timeout_factory):
        output = yield from cli(
            '-v', '7',
            'serve',
            '-sc', pytest.saltyrtc.cert,
            '-k', pytest.saltyrtc.permanent_key,
            '-p', '8443',
            '-l', 'uvloop',
            timeout=timeout_factory(),
            signal=signal.SIGINT,
        )
        assert 'Server instance' in output
        assert 'Closing protocols' in output

    @pytest.mark.asyncio
    def test_serve_asyncio_restart(self, cli, timeout_factory):
        output = yield from cli(
            'serve',
            '-sc', pytest.saltyrtc.cert,
            '-k', pytest.saltyrtc.permanent_key,
            '-p', '8443',
            timeout=timeout_factory(),
            signal=[signal.SIGHUP, signal.SIGINT],
        )
        output = output.split('\n')
        assert output.count('Started') == 2
        assert output.count('Stopped') == 2

    @pytest.mark.asyncio
    def test_serve_safety_not_quite_off(self, cli, timeout_factory):
        env = os.environ.copy()
        env['SALTYRTC_SAFETY_OFF'] = 'Eh... yeah'
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            yield from cli(
                'serve',
                env=env,
             )
        assert 'It is REQUIRED' in exc_info.value.output

    @pytest.mark.asyncio
    def test_serve_safety_off(self, cli, timeout_factory):
        env = os.environ.copy()
        env['SALTYRTC_SAFETY_OFF'] = 'yes-and-i-know-what-im-doing'
        output = yield from cli(
            'serve',
            '-p', '8443',
            timeout=timeout_factory(),
            signal=signal.SIGINT,
            env=env,
        )
        assert 'Stopped' in output
