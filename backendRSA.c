/*
 * RSA encryption project back-end
 *
 * Created on: 08 - 05 - 2025
 *
 * Authors:
 *   Carlos, Filipe, Flavia, Giovanna and Mirian.
 *
 * Description:
 *   This code implements RSA encryption and decryption using GNU Multiple Precision
 *   Arithmetic Library (GMP). It includes functions to encrypt and decrypt messages,
 *   as well as to generate RSA keys. The code is designed to educational purposes - 
 *   do not use it in production.
 *
 * Copyright (C) 2025 Carlos, Filipe, Flavia, Giovanna and Mirian
 */

//  Standard C libraries
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

//  Emscripten libraries
// #include <emscripten.h>
#define EMSCRIPTEN_KEEPALIVE

//  GNU Multiple Precision Arithmetic Library
#include "gmp-6.3.0/mini-gmp/mini-gmp.c"


#define MAX_SIZE 2048

bool __isPrime(mpz_t n)
{
    if (mpz_cmp_ui(n, 1) <= 0)
        return false;

    mpz_t d, sqrt_n, r;
    mpz_init(d);
    mpz_init(sqrt_n);
    mpz_init(r);

    mpz_sqrt(sqrt_n, n);
    for (mpz_set_ui(d, 2); mpz_cmp(d, sqrt_n) <= 0; mpz_add_ui(d, d, 1))
    {
        mpz_mod(r, n, d);
        if (mpz_cmp_ui(r, 0) == 0)
        {
            mpz_clear(d);
            mpz_clear(sqrt_n);
            mpz_clear(r);
            return false;
        }
    }

    mpz_clear(d);
    mpz_clear(sqrt_n);
    mpz_clear(r);
    return true;
}

EMSCRIPTEN_KEEPALIVE
const char *generatePublicKey(const char *_p, const char *_q, const char *_e)
{
    mpz_t p, q, e, n, phi, gcd;
    mpz_init(p);
    mpz_init(q);
    mpz_init(e);
    mpz_init(n);
    mpz_init(phi);
    mpz_init(gcd);

    mpz_set_str(p, _p, 10);
    mpz_set_str(q, _q, 10);
    mpz_set_str(e, _e, 10);

    mpz_mul(n, p, q);

    if (mpz_cmp_ui(n, 126) < 0)
    {
        mpz_clear(p);
        mpz_clear(q);
        mpz_clear(e);
        mpz_clear(n);
        mpz_clear(phi);
        mpz_clear(gcd);
        return "KEY_ERROR: o produto dos primos deve ser maior que 126 para ser reversivel";
    }

    mpz_t p1, q1;
    mpz_init(p1);
    mpz_init(q1);
    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(phi, p1, q1);
    mpz_gcd(gcd, e, phi);

    mpz_clear(p1);
    mpz_clear(q1);

    if (mpz_cmp_ui(gcd, 1) != 0)
    {
        mpz_clear(p);
        mpz_clear(q);
        mpz_clear(e);
        mpz_clear(n);
        mpz_clear(phi);
        mpz_clear(gcd);
        return "KEY_ERROR: e não é coprimo com (p - 1)(q - 1)";
    }

    char *public_key = (char *)malloc(MAX_SIZE * sizeof(char));
    if (!public_key)
    {
        mpz_clear(p);
        mpz_clear(q);
        mpz_clear(e);
        mpz_clear(n);
        mpz_clear(phi);
        mpz_clear(gcd);
        return "KEY_ERROR: falha ao alocar memória";
    }

    sprintf(public_key, "%s", mpz_get_str(NULL, 10, n));

    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(e);
    mpz_clear(n);
    mpz_clear(phi);
    mpz_clear(gcd);
    return public_key;
}

EMSCRIPTEN_KEEPALIVE
const char *encryptMessage(const char *_msg, const char *_n, const char *_e)
{
    mpz_t n, e, m, c;
    mpz_init(n);
    mpz_init(e);
    mpz_init(m);
    mpz_init(c);

    mpz_set_str(n, _n, 10);
    mpz_set_str(e, _e, 10);

    size_t len = strlen(_msg);
    char *cypher_text = (char *)malloc(len * MAX_SIZE);
    if (!cypher_text)
    {
        mpz_clear(n);
        mpz_clear(e);
        mpz_clear(m);
        mpz_clear(c);
        return "KEY_ERROR: falha ao alocar memória";
    }
    cypher_text[0] = '\0';

    for (size_t i = 0; i < len; i++)
    {
        mpz_set_ui(m, (unsigned int)_msg[i]);
        mpz_powm(c, m, e, n);
        strcat(cypher_text, mpz_get_str(NULL, 10, c));
        strcat(cypher_text, " ");
    }

    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(m);
    mpz_clear(c);
    return cypher_text;
}

EMSCRIPTEN_KEEPALIVE
const char *decryptMessage(char *_cphr, const char *_p, const char *_q, const char *_e)
{
    size_t lenMsg = 0;
    for (size_t i = 0; _cphr[i] != '\0'; i++)
        if (_cphr[i] == ' ') lenMsg++;

    mpz_t n, d, p, q, e, phi;
    mpz_init(n);
    mpz_init(d);
    mpz_init(p);
    mpz_init(q);
    mpz_init(e);
    mpz_init(phi);

    mpz_set_str(p, _p, 10);
    mpz_set_str(q, _q, 10);
    mpz_set_str(e, _e, 10);

    mpz_mul(n, p, q);

    mpz_t p1, q1;
    mpz_init(p1);
    mpz_init(q1);
    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(phi, p1, q1);
    mpz_clear(p1);
    mpz_clear(q1);

    mpz_invert(d, e, phi);
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(e);
    mpz_clear(phi);

    char *message = (char *)malloc((lenMsg + 1) * sizeof(char));
    if (!message)
    {
        mpz_clear(n);
        mpz_clear(d);
        return "KEY_ERROR: falha ao alocar memória";
    }
    message[0] = '\0';

    char *_c = (char *)malloc(MAX_SIZE);
    if (!_c)
    {
        mpz_clear(n);
        mpz_clear(d);
        free(message);
        return "KEY_ERROR: falha ao alocar memória";
    }

    mpz_t c, m;
    mpz_init(c);
    mpz_init(m);

    for (size_t i = 0; i < lenMsg; i++)
    {
        sscanf(_cphr, "%s ", _c);
        _cphr += strlen(_c) + 1;
        mpz_set_str(c, _c, 10);
        mpz_powm(m, c, d, n);
        strcat(message, (char[2]){(char)mpz_get_ui(m), '\0'});
    }

    free(_c);
    mpz_clear(n);
    mpz_clear(d);
    mpz_clear(c);
    mpz_clear(m);
    return message;
}
