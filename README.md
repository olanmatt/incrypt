incrypt [![Build Status](https://travis-ci.org/olanmatt/incrypt.svg?branch=master)](https://travis-ci.org/olanmatt/incrypt)
=======

An in-place file cryptography tool. Useful for simple file encryption with minimal memory and space requirements.

Uses a slightly modified [pbhandari](https://github.com/pbhandari)'s
[tinnaes](https://github.com/pbhandari/tinnaes) for the encryption.

Increases file size by at most 16 bytes, and at minimum a single byte.
