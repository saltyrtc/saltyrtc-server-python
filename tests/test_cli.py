import binascii
import os
import signal
import stat
import subprocess

import pytest

from saltyrtc.server import (
    Server,
    __version__ as _version,
    util,
)


@pytest.mark.usefixtures('evaluate_log')
class TestCLI:
    @pytest.mark.asyncio
    async def test_invalid_command(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli('meow')
        assert 'No such command "meow"' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_invalid_verbosity(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli('-v', '8')
        assert 'is not in the valid range' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_import_error_logbook(self, cli, fake_logbook_env):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli('-v', '7', 'serve', '-p', '8443', env=fake_logbook_env)
        assert ('Please install saltyrtc.server[logging] for '
                'logging support') in exc_info.value.output

    @pytest.mark.asyncio
    async def test_get_version(self, cli):
        output = await cli('-v', '7', '-c', 'version')
        assert 'Version: {}'.format(_version) in output
        assert str(Server.subprotocols) in output

    @pytest.mark.asyncio
    async def test_generate_key_invalid_path(self, cli, tmpdir):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli('generate', str(tmpdir))
        assert 'is a directory' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_generate_key_invalid_permissions(self, cli, tmpdir):
        keyfile = tmpdir.join('keyfile.key')
        keyfile.write('meow')
        keyfile.chmod(stat.S_IREAD)
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli('generate', str(keyfile))
        assert 'is not writable' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_generate_key(self, cli, tmpdir):
        keyfile = tmpdir.join('keyfile.key')
        await cli('generate', str(keyfile))

        # Check length
        key = binascii.unhexlify(keyfile.read())
        assert len(key) == 32

        # Check permissions
        stat_result = os.stat(str(keyfile))
        permissions = stat_result.st_mode
        assert permissions & stat.S_IRWXU == stat.S_IRUSR | stat.S_IWUSR

    @pytest.mark.asyncio
    async def test_serve_key_missing(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli(
                'serve',
                '-k', pytest.saltyrtc.permanent_key_primary,
                '-p', '8443',
            )
        assert 'It is REQUIRED' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_serve_cert_missing(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli(
                'serve',
                '-tc', pytest.saltyrtc.cert,
                '-tk', pytest.saltyrtc.key,
                '-p', '8443',
            )
        assert 'It is REQUIRED' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_serve_invalid_cert(self, cli, tmpdir):
        cert = tmpdir.join('cert.pem')
        cert.write('meowmeow')
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli(
                'serve',
                '-tc', str(cert),
                '-k', pytest.saltyrtc.permanent_key_primary,
                '-p', '8443',
            )
        assert 'SSLError' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_serve_invalid_key_file(self, cli, tmpdir):
        keyfile = tmpdir.join('keyfile.key')
        keyfile.write('6d656f77')
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli(
                'serve',
                '-tc', pytest.saltyrtc.cert,
                '-tk', pytest.saltyrtc.key,
                '-k', str(keyfile),
                '-p', '8443',
            )
        assert 'ValueError' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_serve_invalid_dh_params_file(self, cli, tmpdir):
        dh_params_file = tmpdir.join('dh_params.pem')
        dh_params_file.write('meowmeow')
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli(
                'serve',
                '-tc', pytest.saltyrtc.cert,
                '-tk', pytest.saltyrtc.key,
                '-k', pytest.saltyrtc.permanent_key_primary,
                '-dhp', str(dh_params_file),
                '-p', '8443',
            )
        assert 'SSLError' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_serve_invalid_hex_encoded_key(self, cli):
        key = open(pytest.saltyrtc.permanent_key_primary, 'r').read()[:63]
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli(
                'serve',
                '-tc', pytest.saltyrtc.cert,
                '-tk', pytest.saltyrtc.key,
                '-k', key,
                '-p', '8443',
            )
        assert 'ValueError' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_serve_invalid_host(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli(
                'serve',
                '-tc', pytest.saltyrtc.cert,
                '-tk', pytest.saltyrtc.key,
                '-k', pytest.saltyrtc.permanent_key_primary,
                '-h', 'meow',
                '-p', '8443',
            )
        assert any(('Name or service not known' in exc_info.value.output,
                    'No address associated with hostname' in exc_info.value.output))

    @pytest.mark.asyncio
    async def test_serve_invalid_port(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli(
                'serve',
                '-tc', pytest.saltyrtc.cert,
                '-tk', pytest.saltyrtc.key,
                '-k', pytest.saltyrtc.permanent_key_primary,
                '-p', 'meow',
            )
        assert 'is not a valid integer' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_serve_invalid_loop(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli(
                'serve',
                '-tc', pytest.saltyrtc.cert,
                '-tk', pytest.saltyrtc.key,
                '-k', pytest.saltyrtc.permanent_key_primary,
                '-p', '8443',
                '-l', 'meow',
            )
        assert 'invalid choice' in exc_info.value.output

    @pytest.saltyrtc.no_uvloop
    @pytest.mark.asyncio
    async def test_serve_uvloop_unavailable(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli(
                'serve',
                '-tc', pytest.saltyrtc.cert,
                '-tk', pytest.saltyrtc.key,
                '-k', pytest.saltyrtc.permanent_key_primary,
                '-p', '8443',
                '-l', 'uvloop',
            )
        assert "Cannot use event loop 'uvloop'" in exc_info.value.output

    @pytest.mark.asyncio
    async def test_serve_asyncio(self, cli):
        output = await cli(
            'serve',
            '-tc', pytest.saltyrtc.cert,
            '-tk', pytest.saltyrtc.key,
            '-k', pytest.saltyrtc.permanent_key_primary,
            '-p', '8443',
            signal=signal.SIGINT,
        )
        assert 'Stopped' in output

    @pytest.mark.asyncio
    async def test_serve_asyncio_dh_params(self, cli):
        output = await cli(
            'serve',
            '-tc', pytest.saltyrtc.cert,
            '-tk', pytest.saltyrtc.key,
            '-k', pytest.saltyrtc.permanent_key_primary,
            '-dhp', pytest.saltyrtc.dh_params,
            '-p', '8443',
            signal=signal.SIGINT,
        )
        assert 'Stopped' in output

    @pytest.mark.asyncio
    async def test_serve_asyncio_hex_encoded_key(self, cli):
        output = await cli(
            'serve',
            '-tc', pytest.saltyrtc.cert,
            '-tk', pytest.saltyrtc.key,
            '-k', open(pytest.saltyrtc.permanent_key_primary, 'r').read(),
            '-p', '8443',
            signal=signal.SIGINT,
        )
        assert 'Stopped' in output

    @pytest.mark.asyncio
    async def test_serve_asyncio_plus_logging(self, cli):
        output = await cli(
            '-v', '7',
            'serve',
            '-tc', pytest.saltyrtc.cert,
            '-tk', pytest.saltyrtc.key,
            '-k', pytest.saltyrtc.permanent_key_primary,
            '-p', '8443',
            signal=signal.SIGINT,
        )
        assert 'Server instance' in output
        assert 'Closing protocols' in output

    @pytest.saltyrtc.have_uvloop
    @pytest.mark.asyncio
    async def test_serve_uvloop(self, cli):
        output = await cli(
            'serve',
            '-tc', pytest.saltyrtc.cert,
            '-tk', pytest.saltyrtc.key,
            '-k', pytest.saltyrtc.permanent_key_primary,
            '-p', '8443',
            '-l', 'uvloop',
            signal=signal.SIGINT,
        )
        assert 'Stopped' in output

    @pytest.saltyrtc.have_uvloop
    @pytest.mark.asyncio
    async def test_serve_uvloop_dh_params(self, cli):
        output = await cli(
            'serve',
            '-tc', pytest.saltyrtc.cert,
            '-tk', pytest.saltyrtc.key,
            '-k', pytest.saltyrtc.permanent_key_primary,
            '-dhp', pytest.saltyrtc.dh_params,
            '-p', '8443',
            '-l', 'uvloop',
            signal=signal.SIGINT,
        )
        assert 'Stopped' in output

    @pytest.saltyrtc.have_uvloop
    @pytest.mark.asyncio
    async def test_serve_uvloop_plus_logging(self, cli):
        output = await cli(
            '-v', '7',
            'serve',
            '-tc', pytest.saltyrtc.cert,
            '-tk', pytest.saltyrtc.key,
            '-k', pytest.saltyrtc.permanent_key_primary,
            '-p', '8443',
            '-l', 'uvloop',
            signal=signal.SIGINT,
        )
        assert 'Server instance' in output
        assert 'Closing protocols' in output

    @pytest.mark.asyncio
    async def test_serve_asyncio_restart(self, cli):
        output = await cli(
            'serve',
            '-tc', pytest.saltyrtc.cert,
            '-tk', pytest.saltyrtc.key,
            '-k', pytest.saltyrtc.permanent_key_primary,
            '-p', '8443',
            signal=[signal.SIGHUP, signal.SIGINT],
        )
        output = output.split('\n')
        assert output.count('Started') == 2
        assert output.count('Stopped') == 2

    @pytest.mark.asyncio
    async def test_serve_safety_not_quite_off(self, cli):
        env = os.environ.copy()
        env['SALTYRTC_SAFETY_OFF'] = 'Eh... yeah'
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli(
                'serve',
                env=env,
             )
        assert 'It is REQUIRED' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_serve_safety_off(self, cli):
        env = os.environ.copy()
        env['SALTYRTC_SAFETY_OFF'] = 'yes-and-i-know-what-im-doing'
        output = await cli(
            'serve',
            '-p', '8443',
            signal=signal.SIGINT,
            env=env,
        )
        assert 'Stopped' in output

    @pytest.mark.asyncio
    async def test_serve_repeated_key(self, cli):
        primary_key = open(pytest.saltyrtc.permanent_key_primary, 'r').read()
        combinations = [
            ['-k', pytest.saltyrtc.permanent_key_primary,
             '-k', pytest.saltyrtc.permanent_key_primary],
            ['-k', pytest.saltyrtc.permanent_key_primary,
             '-k', primary_key],
            ['-k', pytest.saltyrtc.permanent_key_secondary,
             '-k', pytest.saltyrtc.permanent_key_secondary],
        ]

        # Try all combinations
        for key_arguments in combinations:
            with pytest.raises(subprocess.CalledProcessError) as exc_info:
                await cli(*[
                    'serve',
                    '-tc', pytest.saltyrtc.cert,
                    '-tk', pytest.saltyrtc.key,
                    '-p', '8443',
                ] + key_arguments)
            assert 'key has been supplied more than once' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_serve_invalid_2nd_key_file(self, cli, tmpdir):
        keyfile = tmpdir.join('keyfile.key')
        keyfile.write('6d656f77')
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli(
                'serve',
                '-tc', pytest.saltyrtc.cert,
                '-tk', pytest.saltyrtc.key,
                '-k', pytest.saltyrtc.permanent_key_primary,
                '-k', str(keyfile),
                '-p', '8443',
            )
        assert 'ValueError' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_serve_invalid_2nd_hex_encoded_key(self, cli):
        key = open(pytest.saltyrtc.permanent_key_primary, 'r').read()[:63]
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli(
                'serve',
                '-tc', pytest.saltyrtc.cert,
                '-tk', pytest.saltyrtc.key,
                '-k', pytest.saltyrtc.permanent_key_primary,
                '-k', key,
                '-p', '8443',
            )
        assert 'ValueError' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_serve_asyncio_2nd_key(self, cli):
        # Load keys
        primary_key = util.load_permanent_key(pytest.saltyrtc.permanent_key_primary)
        primary_key = primary_key.hex_pk().decode('ascii')
        secondary_key = util.load_permanent_key(pytest.saltyrtc.permanent_key_secondary)
        secondary_key = secondary_key.hex_pk().decode('ascii')

        # Check output
        output = await cli(
            'serve',
            '-tc', pytest.saltyrtc.cert,
            '-tk', pytest.saltyrtc.key,
            '-k', pytest.saltyrtc.permanent_key_primary,
            '-k', pytest.saltyrtc.permanent_key_secondary,
            '-p', '8443',
            signal=signal.SIGINT,
        )
        assert 'Primary public permanent key: {}'.format(primary_key) in output
        assert 'Secondary key #1: {}'.format(secondary_key) in output
        assert 'Stopped' in output

    @pytest.mark.asyncio
    async def test_serve_asyncio_2nd_key_reversed(self, cli):
        # Load keys
        primary_key = util.load_permanent_key(pytest.saltyrtc.permanent_key_primary)
        primary_key = primary_key.hex_pk().decode('ascii')
        secondary_key = util.load_permanent_key(pytest.saltyrtc.permanent_key_secondary)
        secondary_key = secondary_key.hex_pk().decode('ascii')

        # Check output
        output = await cli(
            'serve',
            '-tc', pytest.saltyrtc.cert,
            '-tk', pytest.saltyrtc.key,
            '-k', pytest.saltyrtc.permanent_key_secondary,
            '-k', pytest.saltyrtc.permanent_key_primary,
            '-p', '8443',
            signal=signal.SIGINT,
        )
        assert 'Primary public permanent key: {}'.format(secondary_key) in output
        assert 'Secondary key #1: {}'.format(primary_key) in output
        assert 'Stopped' in output

    @pytest.mark.asyncio
    async def test_serve_deprecated_options(self, cli):
        output = await cli(
            'serve',
            '-sc', pytest.saltyrtc.cert,
            '-sk', pytest.saltyrtc.key,
            '-k', pytest.saltyrtc.permanent_key_primary,
            '-p', '8443',
            signal=signal.SIGINT,
        )
        assert 'DeprecationWarning' in output
        assert 'Stopped' in output
