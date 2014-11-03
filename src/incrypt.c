/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Matt Olan
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

void xor(uint8_t* a, uint8_t* b)
{
    int i;
    for (i = 0; i < 16; ++i)
    {
        a[i] = a[i] ^ b[i];
    }
}

int incrypt(char* file, uint8_t *key, int decrypt)
{
    int fd;
    // TODO(olanmatt): Allow for larger buffers that are multiples of 16.
    uint8_t in[BUFSIZE];
    uint8_t out[BUFSIZE];
    uint8_t last[BUFSIZE];
    int n_read;

    // TODO(olanmatt): Better IVs.
    memset(out, 0, BUFSIZE);
    memset(in, 0, BUFSIZE);
    memset(last, 0, BUFSIZE);

    // TODO(olanmatt): Implement PBKDF2 key derivation

    if ((fd = open(file, O_RDWR)) == -1)
    {
        perror("Could not open file for read or write");
        return 2;
    }

    while ((n_read = read(fd, in, BUFSIZE)) > 0)
    {
        if (decrypt)
        {
            AES128_ECB_decrypt(in, key, out);
            xor(out, last);  // CBC mode
            memcpy(last, in, BUFSIZE);
        }
        else
        {
            // PKCS7 padding
            if (n_read < BUFSIZE)  // FIXME: Only need to pad for last 16 bytes
            {
                memset(in + n_read, BUFSIZE - n_read, BUFSIZE - n_read);
            }
            xor(in, out);  // CBC mode
            AES128_ECB_encrypt(in, key, out);
        }

        lseek(fd, n_read * -1, SEEK_CUR);
        if (write(fd, out, BUFSIZE) == -1)
        {
            perror("Could not write to output file");
            return 4;
        }

        memset(in, 0, BUFSIZE);
    }

    // Remove padding
    if (decrypt)
    {
        // TODO(olanmatt): Use padding for decryption validation.
        off_t size = lseek(fd, 0, SEEK_END);  // Get size of file
        uint8_t padding_length = out[BUFSIZE - 1];  // Get padding length
        ftruncate(fd, size - padding_length);  // Trunkate the file
    }

    close(fd);
    return 0;
}
