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
#include <stdio.h>
#include <string.h>
#include <stdint.h>

void xor(uint8_t* a, uint8_t* b)
{
    int i;
    for (i = 0; i < BLOCKSIZE; ++i)
    {
        a[i] = a[i] ^ b[i];
    }
}

int incrypt(int fi, int fo, uint8_t *key)
{
    uint8_t in[BUFSIZE];  // Input buffer
    uint8_t out[BUFSIZE];  // Output buffer
    uint8_t i_block[BLOCKSIZE];  // Input block
    uint8_t o_block[BLOCKSIZE];  // Output block
    uint8_t last[BLOCKSIZE];  // Previous block
    int n_read;
    int offset;

    memset(out, 0, BUFSIZE);
    memset(in, 0, BUFSIZE);
    memset(i_block, 0, BLOCKSIZE);
    memset(o_block, 0, BLOCKSIZE);
    memset(last, 0, BLOCKSIZE);

    // TODO(olanmatt): Insert validation block.

    // Add PKCS7 padding
    lseek(fi, (lseek(fi, 0, SEEK_END) % BLOCKSIZE) * -1, SEEK_CUR);
    n_read = read(fi, i_block, BLOCKSIZE);
    memset(i_block + n_read, BLOCKSIZE - n_read, BLOCKSIZE - n_read);
    lseek(fi, n_read * -1, SEEK_CUR);
    if (write(fi, i_block, BLOCKSIZE) == -1)
    {
        perror("Could not write to output file");
        return 4;
    }
    lseek(fi, 0, SEEK_SET);

    uint32_t cipherkey[44];
    aes128_expand_key(key, cipherkey);

    while ((n_read = read(fi, in, BUFSIZE)) > 0)
    {
        for (offset = 0; offset < n_read; offset += BLOCKSIZE)
        {
            memcpy(i_block, in + offset, BLOCKSIZE);
            xor(i_block, last);  // CBC mode
            aes128_encrypt_block(i_block, cipherkey, o_block);
            memcpy(last, o_block, BLOCKSIZE);
            memcpy(out + offset, o_block, BLOCKSIZE);
        }

        lseek(fi, n_read * -1, SEEK_CUR);
        if (write(fi, out, offset) == -1)
        {
            perror("Could not write to output file");
            return 4;
        }

        memset(in, 0, BUFSIZE);
    }

    close(fi);
    if (fi != fo)
        close(fo);
    return 0;
}

int decrypt(int fi, int fo, uint8_t *key)
{
    uint8_t in[BUFSIZE];  // Input buffer
    uint8_t out[BUFSIZE];  // Output buffer
    uint8_t i_block[BLOCKSIZE];  // Input block
    uint8_t o_block[BLOCKSIZE];  // Output block
    uint8_t last[BLOCKSIZE];  // Previous block
    int n_read;
    int offset;
    off_t size;

    memset(out, 0, BUFSIZE);
    memset(in, 0, BUFSIZE);
    memset(i_block, 0, BLOCKSIZE);
    memset(o_block, 0, BLOCKSIZE);
    memset(last, 0, BLOCKSIZE);

    size = lseek(fi, 0, SEEK_END);  // Get size of file
    lseek(fi, 0, SEEK_SET);

    uint32_t cipherkey[44];
    aes128_expand_key(key, cipherkey);

    while ((n_read = read(fi, in, BUFSIZE)) > 0)
    {
        // TODO(olanmatt): Break if invalid validation block.
        for (offset = 0; offset < n_read; offset += BLOCKSIZE)
        {
            memcpy(i_block, in + offset, BLOCKSIZE);
            aes128_decrypt_block(i_block, cipherkey, o_block);
            xor(o_block, last);  // CBC mode
            memcpy(last, i_block, BLOCKSIZE);
            memcpy(out + offset, o_block, BLOCKSIZE);
        }

        lseek(fi, n_read * -1, SEEK_CUR);
        if (write(fi, out, offset) == -1)
        {
            perror("Could not write to output file");
            return 4;
        }

        memset(in, 0, BUFSIZE);
    }

    // Remove PKCS7 padding
    off_t padding_length = o_block[BLOCKSIZE - 1];  // Get padding length
    ftruncate(fi, size - padding_length);  // Trunkate the file

    close(fi);
    if (fi != fo)
        close(fo);
    return 0;
}
