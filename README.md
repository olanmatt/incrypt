incrypt [![Build Status](https://travis-ci.org/olanmatt/incrypt.svg?branch=master)](https://travis-ci.org/olanmatt/incrypt)
=======

An in-place file cryptography tool. Useful for simple file encryption with minimal memory and space requirements.

Uses [kokke](https://github.com/kokke)'s tiny-AES128-C implementation.

Increases file size by at most 16 bytes, and at minimum a single byte.
