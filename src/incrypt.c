/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Matt Olan
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <incrypt.h>
#include <aes.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

void xor(uint8_t* a, uint8_t* b)
{
    int i;
    for (i = 0; i < BLOCKSIZE; ++i)
    {
        a[i] = a[i] ^ b[i];
    }
}

int incrypt(char* file, uint8_t *key, int decrypt)
{
    int fd;
    uint8_t in[BUFSIZE];
    uint8_t out[BUFSIZE];
    uint8_t i_block[BLOCKSIZE];
    uint8_t o_block[BLOCKSIZE];
    uint8_t last[BLOCKSIZE];
    int n_read;
    int offset;
    off_t size = lseek(fd, 0, SEEK_END);  // Get size of file

    // TODO(olanmatt): Better IVs.
    memset(out, 0, BUFSIZE);
    memset(in, 0, BUFSIZE);
    memset(i_block, 0, BLOCKSIZE);
    memset(o_block, 0, BLOCKSIZE);
    memset(last, 0, BLOCKSIZE);

    // TODO(olanmatt): Implement PBKDF2 key derivation

    if (BUFSIZE % BLOCKSIZE != 0)
    {
        perror("Buffer size must be a multiple of block size");
        return 2;
    }

    if ((fd = open(file, O_RDWR)) == -1)
    {
        perror("Could not open file for read or write");
        return 3;
    }

    while ((n_read = read(fd, in, BUFSIZE)) > 0)
    {
        for (offset = 0; offset < n_read; offset += BLOCKSIZE)
        {
            memcpy(i_block, in + offset, BLOCKSIZE);

            if (decrypt)
            {
                /*
                AES128_ECB_decrypt(block, key, out);
                xor(out, last);  // CBC mode
                memcpy(last, block, BUFSIZE);
                */
            }
            else
            {
                // PKCS7 padding
                if (n_read < offset + BLOCKSIZE)
                {
                    memset(i_block + (n_read % BLOCKSIZE), BLOCKSIZE - (n_read % BLOCKSIZE), BLOCKSIZE - (n_read % BLOCKSIZE));
                }
                else
                {
                }
                /*
                xor(block, out);  // CBC mode
                AES128_ECB_encrypt(in, key, out);
                */
            }

            memcpy(o_block, i_block, BLOCKSIZE);  // TODO(olanmatt): Remove.
            memcpy(out + offset, o_block, BLOCKSIZE);
        }

        lseek(fd, n_read * -1, SEEK_CUR);
        if (write(fd, out, offset) == -1)
        {
            perror("Could not write to output file");
            return 4;
        }

        memset(in, 0, BUFSIZE);
    }

    // TODO(olanmatt): Check if padding, otherwise pad 16.

    // Remove padding
    if (decrypt)
    {
        // TODO(olanmatt): Use padding for decryption validation.
        uint8_t padding_length = out[BUFSIZE - 1];  // Get padding length
        for (int i = BUFSIZE - 1; i >= BUFSIZE - padding_length; --i)
        {
            if (out[i] != padding_length)
            {
                perror("Decryption failed");
                //fprintf(stderr, "I am in stderr");
                // TODO(olanmatt): Reverse decryption of file.
                close(fd);
                // TODO(olanmatt): Prompt user for reverse decryption.
                incrypt(file, key, 0);
                return 1;
            }
        }
        ftruncate(fd, size - padding_length);  // Trunkate the file
    }

    close(fd);
    return 0;
}
