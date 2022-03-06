Release Process
===============

Signing key: https://lgrahl.de/pub/pgp-key.txt

1. Check the code:

   ```bash
   flake8 .
   isort -c . || isort -df
   rm -rf .mypy_cache && MYPYPATH=${PWD}/stubs mypy saltyrtc examples
   py.test
   ```

2. Set variables:

   ```bash
   export VERSION=<version>
   export GPG_KEY=3FDB14868A2B36D638F3C495F98FBED10482ABA6
   ```

3. Update version number in ``saltyrtc/server/__init__.py`` and
   ``CHANGELOG.rst``, also update the URL with the corresponding tags.

   Run `python setup.py checkdocs`.

4. Do a signed commit and signed tag of the release:

  ```bash
  git add saltyrtc/server/__init__.py CHANGELOG.rst
  git commit -S${GPG_KEY} -m "Release v${VERSION}"
  git tag -u ${GPG_KEY} -m "Release v${VERSION}" v${VERSION}
  ```

5. Build source and binary distributions:

   ```bash
   rm -rf build dist saltyrtc.server.egg-info .mypy_cache
   find . \( -name \*.pyc -o -name \*.pyo -o -name __pycache__ \) -prune -exec rm -rf {} +
   python setup.py sdist bdist_wheel
   ```

6. Sign files:

   ```bash
   gpg --detach-sign -u ${GPG_KEY} -a dist/saltyrtc.server-${VERSION}.tar.gz
   gpg --detach-sign -u ${GPG_KEY} -a dist/saltyrtc.server-${VERSION}*.whl
   ```

7. Upload package to PyPI and push:

   ```bash
   twine upload "dist/saltyrtc.server-${VERSION}*"
   git push
   git push --tags
   ```

8. Create a new release on GitHub.

9. Push a Docker file to the ``ci/docker-builds`` branch (and remove
   old images, if desired).

10. Prepare CHANGELOG.rst for upcoming changes:

   ```rst
   `Unreleased`_ (YYYY-MM-DD)
   --------------------------
   ```

11. Pat yourself on the back and celebrate!
