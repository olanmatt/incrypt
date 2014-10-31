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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
// #include <incrypt.h>

void usage()
{
    printf("Usage: incrypt [-d] [-k key] [file]\n");
    printf("Generate string permutations of charset to standard output.\n\n");
    printf("  -d, --decrypt\t\tdecrypt file with key\n");
    printf("  -k, --key\t\tkey for encrpytion and decryption\n");
    printf("      --help\t\tdisplay this help and exit\n");
    printf("      --version\t\toutput version infomation and exit\n");
}

void version()
{
    printf("incrypt 0.1\n");
    printf("Copyright (C) 2014 Matt Olan.\n");
    printf("License: The MIT License (MIT).\n\n");
    printf("This is free software: you are free to change and redistribute it.\n");
    printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
    printf("Written by Matt Olan.\n");
}

int main(int argc, char **argv)
{
    int c;
    char *file;
    int encrypt = 0;
    char *key;

    static struct option long_opts[] =
    {
        {"file",        required_argument,  NULL,   'f'},
        {"decrypt",     no_argument,        0,      'e'},
        {"key",         required_argument,  NULL,   'k'},
        {"help",        no_argument,        0,      'h'},
        {"version",     no_argument,        0,      'V'}
    };

    while ((c = getopt_long(argc, argv, "ek:f:", long_opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'h':
            usage();
            exit(0);

        case 'V':
            version();
            exit(0);

        case 'f':
            file = optarg;
            break;

        case 'e':
            encrypt = 1;
            break;

        case 'k':
            key = optarg;
            break;

        default:
            printf("Try `incrypt --help' for more information.");
            return 1;
        }
    }

    if (!file || !key)
    {
        return 1;
    }

    return 0;
}
