/*
 * Copyright 2020-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <cjson/cJSON.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include "ext_dat.h"

/*
 * Subject Sign Tool (1.2.643.100.111) The name of the tool used to signs the subject (UTF8String)
 * This extension is required to obtain the status of a qualified certificate at Russian Federation.
 * RFC-style description is available here: https://tools.ietf.org/html/draft-deremin-rfc4491-bis-04#section-5
 * Russian Federal Law 63 "Digital Sign" is available here:  http://www.consultant.ru/document/cons_doc_LAW_112701/
 *
 * EAR Attestation Result (1.7.6.5.123) The Verifier's Entity Attestation
 * Result for the remote-attestation demo, carried as a JWT in a UTF8String.
 */

static int i2r_ear(X509V3_EXT_METHOD *method, ASN1_UTF8STRING *utf8,
                   BIO *out, int indent);

/*
 * subjectSignTool prints its UTF8String verbatim via i2s. earAttestationResult
 * instead uses i2r, so the compact JWT it carries can be decoded for display;
 * i2s must stay NULL here, since X509V3_EXT_print() checks i2s first and would
 * never reach i2r. s2i is unaffected, so extension creation is unchanged.
 */
const X509V3_EXT_METHOD ossl_v3_utf8_list[2] = {
    EXT_UTF8STRING(NID_subjectSignTool),
    { NID_earAttestationResult, 0, ASN1_ITEM_ref(ASN1_UTF8STRING),
      0, 0, 0, 0,
      0, (X509V3_EXT_S2I)s2i_ASN1_UTF8STRING,
      0, 0,
      (X509V3_EXT_I2R)i2r_ear,
      0, NULL },
};

/*
 * Decodes the base64url segment [in, in+len) into a freshly allocated buffer.
 * Returns the decoded length and sets *out (caller frees), or -1 on failure.
 */
static int b64url_decode(const char *in, int len, unsigned char **out)
{
    char *b64;
    unsigned char *buf;
    int pad, i, n;

    /* A base64 remainder of 1 char cannot encode any whole byte. */
    if (len <= 0 || len % 4 == 1)
        return -1;
    pad = (4 - (len % 4)) % 4;

    if ((b64 = OPENSSL_malloc((size_t)len + pad)) == NULL)
        return -1;
    for (i = 0; i < len; i++)
        b64[i] = in[i] == '-' ? '+' : (in[i] == '_' ? '/' : in[i]);
    for (i = 0; i < pad; i++)
        b64[len + i] = '=';

    if ((buf = OPENSSL_malloc(3 * (((size_t)len + pad) / 4))) == NULL) {
        OPENSSL_free(b64);
        return -1;
    }
    n = EVP_DecodeBlock(buf, (const unsigned char *)b64, len + pad);
    OPENSSL_free(b64);

    /*
     * EVP_DecodeBlock() reports the padded length -- the '=' decode to trailing
     * zero bytes it leaves in the buffer -- so the padding is subtracted here.
     */
    if (n < pad) {
        OPENSSL_free(buf);
        return -1;
    }
    *out = buf;
    return n - pad;
}

/*
 * cJSON_Print() formats from column 0, so every line is shifted to sit under
 * the extension's own indent.
 */
static void print_indented(BIO *out, const char *s, int indent)
{
    const char *nl;

    BIO_printf(out, "%*s", indent, "");
    while ((nl = strchr(s, '\n')) != NULL) {
        BIO_write(out, s, (int)(nl - s) + 1);
        BIO_printf(out, "%*s", indent, "");
        s = nl + 1;
    }
    BIO_puts(out, s);
}

/*
 * Prints the EAR as the decoded claims of the JWT's payload segment.
 *
 * The JWT signature is NOT checked: this function has no Verifier public key,
 * and runs against any certificate handed to X509V3_EXT_print(), trusted or
 * not. The claims shown are therefore unauthenticated input, and the banner
 * says so -- appraising the EAR is the relying party's job, not the printer's.
 *
 * Anything that is not a JWT whose payload parses as JSON falls back to the
 * stored string, so an unexpected value is shown rather than reported as an
 * error.
 */
static int i2r_ear(X509V3_EXT_METHOD *method, ASN1_UTF8STRING *utf8,
                   BIO *out, int indent)
{
    char *jwt, *p1, *p2, *pretty = NULL;
    unsigned char *payload = NULL;
    cJSON *json = NULL;
    int n, ok = 0;

    /* i2s_ASN1_UTF8STRING() returns the value as a NUL-terminated C string. */
    if ((jwt = i2s_ASN1_UTF8STRING(method, utf8)) == NULL)
        return 0;

    /* Compact serialisation: header '.' payload '.' signature. */
    if ((p1 = strchr(jwt, '.')) == NULL
            || (p2 = strchr(p1 + 1, '.')) == NULL
            || (n = b64url_decode(p1 + 1, (int)(p2 - p1 - 1), &payload)) < 0)
        goto raw;

    if ((json = cJSON_ParseWithLength((const char *)payload, n)) == NULL
            || (pretty = cJSON_Print(json)) == NULL)
        goto raw;

    BIO_printf(out, "%*s[JWT payload; signature NOT verified]\n", indent, "");
    print_indented(out, pretty, indent);
    ok = 1;

 raw:
    if (!ok) {
        BIO_printf(out, "%*s", indent, "");
        ok = BIO_puts(out, jwt) > 0;
    }
    cJSON_free(pretty);
    cJSON_Delete(json);
    OPENSSL_free(payload);
    OPENSSL_free(jwt);
    return ok;
}

char *i2s_ASN1_UTF8STRING(X509V3_EXT_METHOD *method,
                          ASN1_UTF8STRING *utf8)
{
    char *tmp;

    if (utf8 == NULL || utf8->length == 0) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if ((tmp = OPENSSL_malloc(utf8->length + 1)) == NULL)
        return NULL;
    memcpy(tmp, utf8->data, utf8->length);
    tmp[utf8->length] = 0;
    return tmp;
}

ASN1_UTF8STRING *s2i_ASN1_UTF8STRING(X509V3_EXT_METHOD *method,
                                     X509V3_CTX *ctx, const char *str)
{
    ASN1_UTF8STRING *utf8;
    if (str == NULL) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_NULL_ARGUMENT);
        return NULL;
    }
    if ((utf8 = ASN1_UTF8STRING_new()) == NULL) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB);
        return NULL;
    }
    if (!ASN1_STRING_set((ASN1_STRING *)utf8, str, strlen(str))) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB);
        ASN1_UTF8STRING_free(utf8);
        return NULL;
    }
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(utf8->data, utf8->data, utf8->length);
#endif                          /* CHARSET_EBCDIC */
    return utf8;
}
