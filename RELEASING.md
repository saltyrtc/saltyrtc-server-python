Release Process
===============

Signing key: https://lgrahl.de/pgp-key.txt

1. Check the code:

   ```bash
   flake8 .
   isort -rc -c . || isort -rc -df
   python setup.py checkdocs
   py.test
   ```

2. Set variables:

   ```bash
   export VERSION=<version>
   export GPG_KEY=3FDB14868A2B36D638F3C495F98FBED10482ABA6
   ```

3. Update version number in ``saltyrtc/__init__.py`` and 
   ``CHANGELOG.rst``, also update the URL with the corresponding tags.

4. Do a signed commit and signed tag of the release:

  ```bash
  git add saltyrtc/__init__.py.py CHANGELOG.rst
  git commit -S${GPG_KEY} -m "Release v${VERSION}"
  git tag -u ${GPG_KEY} -m "Release v${VERSION}" v${VERSION}
  ```

5. Build source and binary distributions:

   ```bash
   python setup.py sdist bdist_wheel
   ```

6. Sign files:

   ```bash
   gpg --detach-sign -u ${GPG_KEY} -a dist/saltyrtc-${VERSION}.tar.gz
   gpg --detach-sign -u ${GPG_KEY} -a dist/saltyrtc-${VERSION}-py34.py35-none-any.whl
   ```

7. Upload package to PyPI and push:

   ```bash
   twine upload "dist/saltyrtc-${VERSION}*"
   git push
   git push --tags
   ```

8. Prepare CHANGELOG.rst for upcoming changes:

   ```rst
   `Unreleased`_ (YYYY-MM-DD)
   --------------------------
   ```

9. Pat yourself on the back and celebrate!
