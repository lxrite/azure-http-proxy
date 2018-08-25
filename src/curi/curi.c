// Copyright (c) 2013 Clodéric Mars

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#ifdef _MSC_VER
#   pragma warning(push)
#   pragma warning(disable: 4100) // Disabling the 'unreferenced formal parameter' visual studio warning
#endif

#include "curi.h"

#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>

static void* default_allocate(void* userData, size_t size)
{
    return malloc(size);
}

static void default_deallocate(void* userData, void* ptr, size_t size)
{
    free(ptr);
}

void curi_default_settings(curi_settings* settings)
{
    memset(settings,0,sizeof(curi_settings));
    settings->allocate = default_allocate;
    settings->deallocate = default_deallocate;
    settings->query_item_separator = '&';
    settings->query_item_key_separator = '=';
}

static curi_status handle_str_callback(int (*callback)(void* userData, const char* str, size_t strLen), const char* str, size_t strLen, const curi_settings* settings, void* userData)
{
    curi_status status = curi_status_success;

    if (strLen > 0 && callback && callback(userData,str,strLen) == 0)
        status = curi_status_canceled;

    return status;
}

static curi_status handle_str_callback_url_decoded(int (*callback)(void* userData, const char* str, size_t strLen), const char* str, size_t strLen, const curi_settings* settings, void* userData)
{
    curi_status status = curi_status_success;

    if (strLen > 0 && callback)
    {
        size_t allocationSize = (strLen+1) * sizeof(char);
        size_t urlDecodedStrLen;
        char* urlDecodedStr = (char*)settings->allocate(userData, allocationSize);

        status = curi_url_decode(str,strLen,urlDecodedStr,strLen+1,&urlDecodedStrLen);

        if (status == curi_status_success)
            if (callback(userData,urlDecodedStr,urlDecodedStrLen) == 0)
                status =  curi_status_canceled;

        settings->deallocate(userData, urlDecodedStr, allocationSize);
    }

    return status;
}

static curi_status handle_scheme(const char* scheme, size_t schemeLen, const curi_settings* settings, void* userData)
{
    return handle_str_callback(settings->scheme_callback, scheme, schemeLen, settings, userData);
}

static curi_status handle_userinfo(const char* userinfo, size_t userinfoLen, const curi_settings* settings, void* userData)
{
    if (settings->url_decode == 0)
        return handle_str_callback(settings->userinfo_callback, userinfo, userinfoLen, settings, userData);
    else
        return handle_str_callback_url_decoded(settings->userinfo_callback, userinfo, userinfoLen, settings, userData);
}

static curi_status handle_host(const char* host, size_t hostLen, const curi_settings* settings, void* userData)
{
    if (settings->url_decode == 0)
        return handle_str_callback(settings->host_callback, host, hostLen, settings, userData);
    else
        return handle_str_callback_url_decoded(settings->host_callback, host, hostLen, settings, userData);
}

static curi_status handle_port(const char* portStr, size_t portStrLen, const curi_settings* settings, void* userData)
{
    curi_status status = handle_str_callback(settings->portStr_callback, portStr, portStrLen, settings, userData);

    if (status == curi_status_success)
    {
        if (portStrLen > 0 && settings->port_callback)
        {
            unsigned int value = atoi(portStr); // Should work because there is no number after the port in URIs
            if(settings->port_callback(userData, value) == 0)
                status =  curi_status_canceled;
        }
    }

    return status ;
}

static curi_status handle_path(const char* path, size_t pathLen, const curi_settings* settings, void* userData)
{
    if (settings->url_decode == 0)
        return handle_str_callback(settings->path_callback, path, pathLen, settings, userData);
    else
        return handle_str_callback_url_decoded(settings->path_callback, path, pathLen, settings, userData);
}

static curi_status handle_path_segment(const char* pathSegment, size_t pathSegmentLen, const curi_settings* settings, void* userData)
{
    if (settings->url_decode == 0)
        return handle_str_callback(settings->path_segment_callback, pathSegment, pathSegmentLen, settings, userData);
    else
        return handle_str_callback_url_decoded(settings->path_segment_callback, pathSegment, pathSegmentLen, settings, userData);
}

static curi_status handle_query(const char* query, size_t queryLen, const curi_settings* settings, void* userData)
{
    if (settings->url_decode == 0)
        return handle_str_callback(settings->query_callback, query, queryLen, settings, userData);
    else
        return handle_str_callback_url_decoded(settings->query_callback, query, queryLen, settings, userData);
}

static curi_status handle_query_item_decodedKey(const char* key, size_t keyLen, const char* value, size_t valueLen, const curi_settings* settings, void* userData)
{
    // Key is valid, callbacks exist
    if (settings->query_item_null_callback)
    {
        if (valueLen == 0)
        {
            if (settings->query_item_null_callback(userData, key, keyLen) == 0)
                return curi_status_canceled;
            else
                return curi_status_success;
        }
    }

    if (valueLen != 0 && settings->query_item_int_callback)
    {
        char* valueEnd = 0;
        long int intValue = 0;
        intValue = strtol(value,&valueEnd,10); // Trying to parse an integer
        if (valueEnd == value + valueLen)
        {
            if (settings->query_item_int_callback(userData, key, keyLen, intValue) == 0)
                return curi_status_canceled;
            else
                return curi_status_success;
        }
    }

    if (valueLen != 0 && settings->query_item_double_callback)
    {
        char* valueEnd = 0;
        double doubleValue = 0;
        doubleValue = strtod(value,&valueEnd); // Trying to parse a double
        if (valueEnd == value + valueLen)
        {
            if (settings->query_item_double_callback(userData, key, keyLen, doubleValue) == 0)
                return curi_status_canceled;
            else
                return curi_status_success;
        }
    }

    if (settings->query_item_str_callback)
    {
        if (settings->url_decode == 0)
        {
            if (settings->query_item_str_callback(userData, key, keyLen, value, valueLen) == 0)
                return curi_status_canceled;
            else
                return curi_status_success;
        }
        else
        {
            curi_status status = curi_status_success;

            size_t valueAllocationSize = (valueLen+1) * sizeof(char);
            size_t urlDecodedValueLen = 0;
            char* urlDecodedValue = (char*)settings->allocate(userData, valueAllocationSize);

            status = curi_url_decode(value,valueLen,urlDecodedValue,valueLen+1,&urlDecodedValueLen);

            if (status == curi_status_success)
                if (settings->query_item_str_callback(userData, key, keyLen, urlDecodedValue, urlDecodedValueLen) == 0)
                    status =  curi_status_canceled;

            settings->deallocate(userData, urlDecodedValue, valueAllocationSize);

            return status;
        }
    }

    return curi_status_success;
}

static curi_status handle_query_item(const char* key, size_t keyLen, const char* value, size_t valueLen, const curi_settings* settings, void* userData)
{
    curi_status status = curi_status_success;
    if (keyLen > 0 && (settings->query_item_null_callback || settings->query_item_int_callback || settings->query_item_double_callback || settings->query_item_str_callback))
    {
        if (settings->url_decode == 0)
        {
            status = handle_query_item_decodedKey(key, keyLen, value, valueLen, settings, userData);
        }
        else
        {
            size_t keyAllocationSize = (keyLen+1) * sizeof(char);
            size_t urlDecodedKeyLen;
            char* urlDecodedKey = (char*)settings->allocate(userData, keyAllocationSize);

            status = curi_url_decode(key, keyLen, urlDecodedKey, keyLen+1, &urlDecodedKeyLen);

            if (status == curi_status_success)
                status = handle_query_item_decodedKey(urlDecodedKey, urlDecodedKeyLen, value, valueLen, settings, userData);

            settings->deallocate(userData, urlDecodedKey, keyAllocationSize);
        }
    }
    return status;
}

static curi_status handle_fragment(const char* fragment, size_t fragmentLen, const curi_settings* settings, void* userData)
{
    if (settings->url_decode == 0)
        return handle_str_callback(settings->fragment_callback, fragment, fragmentLen, settings, userData);
    else
        return handle_str_callback_url_decoded(settings->fragment_callback, fragment, fragmentLen, settings, userData);
}

static const char end = '\0';

static const char* read_char(const char* uri, size_t len, size_t* offset)
{
    const char* c = &end;
    if (*offset < len)
    {
        c = uri + *offset;
    }
    ++(*offset);
    return c;
}

#define TRY(status, offset, parse_fun_call) \
{ \
    size_t __TRY_initialOffset = *(offset); \
    curi_status __TRY_tryStatus = parse_fun_call; \
    if (__TRY_tryStatus == curi_status_error) \
        *(offset) = __TRY_initialOffset; \
    else \
        status = __TRY_tryStatus; \
} \

#define CASE_ALPHA \
    case 'A': \
    case 'B': \
    case 'C': \
    case 'D': \
    case 'E': \
    case 'F': \
    case 'G': \
    case 'H': \
    case 'I': \
    case 'J': \
    case 'K': \
    case 'L': \
    case 'M': \
    case 'N': \
    case 'O': \
    case 'P': \
    case 'Q': \
    case 'R': \
    case 'S': \
    case 'T': \
    case 'U': \
    case 'V': \
    case 'W': \
    case 'X': \
    case 'Y': \
    case 'Z': \
    case 'a': \
    case 'b': \
    case 'c': \
    case 'd': \
    case 'e': \
    case 'f': \
    case 'g': \
    case 'h': \
    case 'i': \
    case 'j': \
    case 'k': \
    case 'l': \
    case 'm': \
    case 'n': \
    case 'o': \
    case 'p': \
    case 'q': \
    case 'r': \
    case 's': \
    case 't': \
    case 'u': \
    case 'v': \
    case 'w': \
    case 'x': \
    case 'y': \
    case 'z'

#define CASE_DIGIT \
    case '0': \
    case '1': \
    case '2': \
    case '3': \
    case '4': \
    case '5': \
    case '6': \
    case '7': \
    case '8': \
    case '9'

static curi_status parse_digit(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    switch (*read_char(uri,len,offset))
    {
        CASE_DIGIT:
            return curi_status_success;
        default:
            return curi_status_error;
    }
}

static curi_status parse_char(char c, const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userDatat)
{
    if (*read_char(uri,len,offset) == c)
        return curi_status_success;
    else
        return curi_status_error;
}

static curi_status parse_scheme(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / ".")
    const size_t schemeStartOffset = *offset;
    curi_status status = curi_status_success;

    if (status == curi_status_success)
    {
        switch (*read_char(uri,len,offset))
        {
            CASE_ALPHA:
                status = curi_status_success;
                break;
            default:
                status = curi_status_error;
        }
    }

    if (status == curi_status_success)
    {
        curi_status tryStatus = curi_status_success;
        while (tryStatus == curi_status_success)
        {
            size_t initialOffset = *offset;
            switch (*read_char(uri,len,offset))
            {
                CASE_ALPHA:
                CASE_DIGIT:
                case '+':
                case '-':
                case '.':
                    tryStatus = curi_status_success;
                    break;
                default:
                    tryStatus = curi_status_error;
                    *offset = initialOffset;
            }
        }
    }

    if (status == curi_status_success)
        status = handle_scheme(uri + schemeStartOffset, *offset - schemeStartOffset, settings, userData);

    return status;
}

#define CASE_UNRESERVED \
    CASE_ALPHA: \
    CASE_DIGIT: \
    case '-': \
    case '.': \
    case '_': \
    case '~'

static curi_status parse_unreserved(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
    switch (*read_char(uri,len,offset))
    {
        CASE_UNRESERVED:
            return curi_status_success;
        default:
            return curi_status_error;
    }
}

#define CASE_HEXDIGIT \
    CASE_DIGIT: \
    case 'A': \
    case 'B': \
    case 'C': \
    case 'D': \
    case 'E': \
    case 'F': \
    case 'a': \
    case 'b': \
    case 'c': \
    case 'd': \
    case 'e': \
    case 'f'

static curi_status parse_hexdigit(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    switch (*read_char(uri,len,offset))
    {
        CASE_HEXDIGIT:
            return curi_status_success;
        default:
            return curi_status_error;
    }
}

static curi_status parse_h8(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // h8 = HEXDIG HEXDIG
    switch (*read_char(uri,len,offset))
    {
        CASE_HEXDIGIT:
            break;
        default:
            return curi_status_error;
    }

    switch (*read_char(uri,len,offset))
    {
        CASE_HEXDIGIT:
            return curi_status_success;
        default:
            return curi_status_error;
    }
}

static curi_status parse_percent_encoded(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // percent-encoded = "%" h8
    switch (*read_char(uri,len,offset))
    {
        case '%':
            break;
        default:
            return curi_status_error;
    }

    return parse_h8(uri,len,offset,settings,userData);
}

#define CASE_SUB_DELIMS \
    case '!': \
    case '$': \
    case '&': \
    case '\'': \
    case '(': \
    case ')': \
    case '*': \
    case '+': \
    case ',': \
    case ';': \
    case '='

static curi_status parse_sub_delims(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    //sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
    //             / "*" / "+" / "," / ";" / "="
    switch (*read_char(uri,len,offset))
    {
        CASE_SUB_DELIMS:
            return curi_status_success;
        default:
            return curi_status_error;
    }
}

static curi_status parse_userinfo_and_at(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // userinfo_and_at = userinfo "@"
    // userinfo = *( unreserved / "%" h8 / sub-delims / ":" )
    const size_t userinfoStartOffset = *offset;
    size_t userinfoEndOffset;
    curi_status status = curi_status_success;

    while (status == curi_status_success)
    {
        size_t initialOffset = *offset;
        switch (*read_char(uri,len,offset))
        {
            CASE_UNRESERVED:
                break;
            case '%':
                status = parse_h8(uri, len, offset, settings, userData);
                break;
            CASE_SUB_DELIMS:
            case ':':
                break;
            default:
                status = curi_status_error;
        }
        if (status == curi_status_error)
            *offset = initialOffset;
    }

    userinfoEndOffset = *offset;

    status = parse_char('@', uri, len, offset, settings, userData);

    if (status == curi_status_success)
        status = handle_userinfo(uri + userinfoStartOffset, userinfoEndOffset - userinfoStartOffset, settings, userData);

    return status;
}

static curi_status parse_reg_name(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // reg-name = *( unreserved / "%" h8 / sub-delims )
    curi_status status = curi_status_success;

    while (status == curi_status_success)
    {
        size_t initialOffset = *offset;
        switch (*read_char(uri,len,offset))
        {
            CASE_UNRESERVED:
                break;
            case '%':
                status = parse_h8(uri, len, offset, settings, userData);
                break;
            CASE_SUB_DELIMS:
                break;
            default:
                status = curi_status_error;
        }
        if (status == curi_status_error)
            *offset = initialOffset;
    }

    return curi_status_success;
}

static curi_status parse_dec_octet(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // dec-octet = DIGIT                 ; 0-9
    //           / %x31-39 DIGIT         ; 10-99
    //           / "1" 2DIGIT            ; 100-199
    //           / "2" %x30-34 DIGIT     ; 200-249
    //           / "25" %x30-35          ; 250-255
    int number;
    char numberStr[4] = {'\0', '\0', '\0', '\0'};
    size_t previousOffset;
    size_t i;

    for (i = 0 ; i < 3 ; ++i)
    {
        previousOffset = *offset;
        if (parse_digit(uri, len, offset, settings, userData) !=  curi_status_success)
        {
            *offset = previousOffset;
            break;
        }
        numberStr[i] = uri[previousOffset];
    }

    number = atoi(numberStr);
    if (number >= 0 && number <= 255)
        return curi_status_success;
    else
        return curi_status_error;
}

static curi_status parse_IPv4address(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
    curi_status status = curi_status_success;

    if (status == curi_status_success)
        status = parse_dec_octet(uri, len, offset, settings, userData);

    if (status == curi_status_success)
        status = parse_char('.', uri, len, offset, settings, userData);

    if (status == curi_status_success)
        status = parse_dec_octet(uri, len, offset, settings, userData);

    if (status == curi_status_success)
        status = parse_char('.', uri, len, offset, settings, userData);

    if (status == curi_status_success)
        status = parse_dec_octet(uri, len, offset, settings, userData);

    if (status == curi_status_success)
        status = parse_char('.', uri, len, offset, settings, userData);

    if (status == curi_status_success)
        status = parse_dec_octet(uri, len, offset, settings, userData);

    return status;
}

static curi_status parse_h16(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // h16 = 1*4HEXDIG
    curi_status status = curi_status_success;
    size_t i;

    if (status == curi_status_success)
        status = parse_hexdigit(uri, len, offset, settings, userData);

    for (i = 0 ; i < 3 ; ++i)
        TRY(status,offset,parse_hexdigit(uri, len, offset, settings, userData));

    return status;
}

static curi_status parse_h16_and_colon(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // h16_and_colon = h16 ":"
    curi_status status = curi_status_success;

    if (status == curi_status_success)
        status = parse_h16(uri, len, offset, settings, userData);

    if (status == curi_status_success)
        status = parse_char(':', uri, len, offset, settings, userData);

    return status;
}

static curi_status parse_ls32(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // ls32 = ( h16_and_colon h16 ) / IPv4address
    curi_status status = curi_status_error;

    if (status == curi_status_error)
    {
        size_t initialOffset = *offset;
        curi_status tryStatus = curi_status_success;

        if (tryStatus == curi_status_success)
            tryStatus = parse_h16_and_colon(uri, len, offset, settings, userData);
        if (tryStatus == curi_status_success)
            tryStatus = parse_h16(uri, len, offset, settings, userData);

        if (tryStatus == curi_status_error)
            *offset = initialOffset;
        else
            status = tryStatus;
    }

    if (status == curi_status_error)
        TRY(status,offset,parse_IPv4address(uri, len, offset, settings, userData));

    return status;
}

static curi_status parse_IPv6address(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // IPv6address =                            6( h16 ":" ) ls32
    //             /                       "::" 5( h16 ":" ) ls32
    //             / [               h16 ] "::" 4( h16 ":" ) ls32
    //             / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
    //             / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
    //             / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
    //             / [ *4( h16 ":" ) h16 ] "::"              ls32
    //             / [ *5( h16 ":" ) h16 ] "::"              h16
    //             / [ *6( h16 ":" ) h16 ] "::"

    // Let's simplify it to [ (":" / 1*7(h16_and_colon)) ":"] ( (0*6(h16_and_colon) ls32) / h16 )

    curi_status status = curi_status_success;

    if (status == curi_status_success)
    {
        size_t initialOffset = *offset;
        curi_status tryStatus = curi_status_error;

        if (tryStatus == curi_status_error)
            TRY(tryStatus,offset,parse_char(':', uri, len, offset, settings, userData));

        if (tryStatus == curi_status_error)
        {
            size_t i;
            tryStatus = curi_status_success;

            if (tryStatus == curi_status_success)
                tryStatus = parse_h16_and_colon(uri, len, offset, settings, userData);

            for (i = 0 ; i < 6 ; ++i)
                TRY(tryStatus,offset,parse_h16_and_colon(uri, len, offset, settings, userData));
        }

        if (tryStatus == curi_status_success)
            tryStatus = parse_char(':', uri, len, offset, settings, userData);

        if (tryStatus == curi_status_error)
            *offset = initialOffset;
        else
            status = tryStatus;
    }

    if (status == curi_status_success)
    {
        status = curi_status_error;

        if (status == curi_status_error)
        {
            size_t initialOffset = *offset;
            curi_status tryStatus = curi_status_success;
            size_t i;
            for (i = 0 ; i < 6 ; ++i)
                TRY(tryStatus,offset,parse_h16_and_colon(uri, len, offset, settings, userData));

            if (tryStatus == curi_status_success)
                tryStatus = parse_ls32(uri, len, offset, settings, userData);

            if (tryStatus == curi_status_error)
                *offset = initialOffset;
            else
                status = tryStatus;
        }

        if (status == curi_status_error)
            TRY(status,offset,parse_h16(uri, len, offset, settings, userData));
    }

    return status;
}

static curi_status parse_IPvFuture(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
    curi_status status = curi_status_success;

    if (status == curi_status_success)
        status = parse_char('v', uri, len, offset, settings, userData);
    if (status == curi_status_success)
        status = parse_hexdigit(uri, len, offset, settings, userData);
    if (status == curi_status_success)
        status = parse_char('.', uri, len, offset, settings, userData);
    if (status == curi_status_success)
    {
        status = curi_status_error;
        if (status == curi_status_error)
            TRY(status,offset,parse_unreserved(uri, len, offset, settings, userData));
        if (status == curi_status_error)
            TRY(status,offset,parse_sub_delims(uri, len, offset, settings, userData));
        if (status == curi_status_error)
            TRY(status,offset,parse_char(':', uri, len, offset, settings, userData));

        while(status == curi_status_success)
        {
            status = curi_status_error;
            if (status == curi_status_error)
                TRY(status,offset,parse_unreserved(uri, len, offset, settings, userData));
            if (status == curi_status_error)
                TRY(status,offset,parse_sub_delims(uri, len, offset, settings, userData));
            if (status == curi_status_error)
                TRY(status,offset,parse_char(':', uri, len, offset, settings, userData));
            if (status == curi_status_error)
            {
                status = curi_status_success;
                break;
            }
        }

    }

    return status;
}

static curi_status parse_IP_literal(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"
    curi_status status = curi_status_success;

    if (status == curi_status_success)
        status = parse_char('[', uri, len, offset, settings, userData);

    if (status == curi_status_success)
    {
        status = curi_status_error;

        if (status == curi_status_error)
            TRY(status, offset, parse_IPv6address(uri, len, offset, settings, userData));

        if (status == curi_status_error)
            TRY(status, offset, parse_IPvFuture(uri, len, offset, settings, userData));
    }

    if (status == curi_status_success)
        status = parse_char(']', uri, len, offset, settings, userData);

    return status;
}

static curi_status parse_host(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // host = IP-literal / IPv4address / reg-name
    const size_t initialOffset = *offset;
    curi_status status = curi_status_error;

    if (status == curi_status_error)
        TRY(status, offset, parse_IP_literal(uri, len, offset, settings, userData));

    if (status == curi_status_error)
        TRY(status, offset, parse_IPv4address(uri, len, offset, settings, userData));

    if (status == curi_status_error)
        TRY(status, offset, parse_reg_name(uri, len, offset, settings, userData));

    if (status == curi_status_success)
        status = handle_host(uri + initialOffset, *offset - initialOffset, settings, userData);

    return status;
}

static curi_status parse_port(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // port = *DIGIT
    const size_t initialOffset = *offset;

    for ( ; ; )
    {
        size_t subOffset = *offset;
        curi_status subStatus = parse_digit(uri, len, &subOffset, settings, userData);

        if (subStatus == curi_status_success)
            *offset = subOffset;
        else
            break;
    }

    return handle_port(uri + initialOffset, *offset - initialOffset, settings, userData);
}

static curi_status parse_authority(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // authority = [ userinfo_and_at ] host [ ":" port ]

    curi_status status = curi_status_success;

    if (status == curi_status_success)
        TRY(status, offset, parse_userinfo_and_at(uri, len, offset, settings, userData));

    if (status == curi_status_success)
        status = parse_host(uri, len, offset, settings, userData);

    if (status == curi_status_success)
    {
        size_t initialOffset = *offset;
        curi_status subStatus = curi_status_success;
        if (subStatus == curi_status_success)
            subStatus = parse_char(':', uri, len, offset, settings, userData);
        if (subStatus == curi_status_success)
            subStatus = parse_port(uri, len, offset, settings, userData);
        if (subStatus == curi_status_error)
            *offset = initialOffset;
        else
            status = subStatus;
    }

    return status;
}

#define CASE_PCHAR_NO_PCT \
    CASE_UNRESERVED: \
    CASE_SUB_DELIMS: \
    case ':': \
    case '@'

static curi_status parse_pchar(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // pchar = unreserved / "%" h8 / sub-delims / ":" / "@"
    switch (*read_char(uri,len,offset))
    {
        CASE_PCHAR_NO_PCT:
            return curi_status_success;
        case '%':
            return parse_h8(uri, len, offset, settings, userData);
        default:
            return curi_status_error;
    }
}

static curi_status parse_pchars(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // pchars = *pchar

    curi_status status = curi_status_success;

    while (status == curi_status_success)
    {
        size_t subOffset = *offset;
        curi_status subStatus = parse_pchar(uri, len, &subOffset, settings, userData);

        if (subStatus == curi_status_success)
        {
            *offset = subOffset;
            status = curi_status_success;
        }
        else
            break;
    }

    return status;
}


static curi_status parse_segment(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData, int notEmpty)
{
    // segment = pchars
    // segment-not-empty = pchar pchars
    const size_t initialOffset = *offset;
    curi_status status = curi_status_success;

    if (notEmpty && status == curi_status_success)
        status = parse_pchar(uri, len, offset, settings, userData);

    if (status == curi_status_success)
        status = parse_pchars(uri, len, offset, settings, userData);

    if (status == curi_status_success)
        status = handle_path_segment(uri + initialOffset, *offset - initialOffset, settings, userData);

    return status;
}

static curi_status parse_segments(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // segments  = *( "/" segment )
    curi_status status = curi_status_success;

    for ( ; ; )
    {
        size_t initialOffset = *offset;
        curi_status tryStatus = curi_status_success;

        if (tryStatus == curi_status_success)
            tryStatus = parse_char('/', uri, len, offset, settings, userData);

        if (tryStatus == curi_status_success)
            tryStatus = parse_segment(uri, len, offset, settings, userData, 0);

        if (tryStatus == curi_status_error)
        {
            *offset = initialOffset;
            break;
        }
        else
            status = tryStatus;
    }

    return status;
}

static curi_status parse_path_absolute_or_empty(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // path-absolute-or-empty  = segments
    const size_t initialOffset = *offset;

    curi_status status = parse_segments(uri, len, offset, settings, userData);

    if (status == curi_status_success)
        status = handle_path(uri + initialOffset, *offset - initialOffset, settings, userData);

    return status;
}

static curi_status parse_path_absolute(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // path-absolute = "/" [ segment-not-empty segments ]
    const size_t initialOffset = *offset;
    curi_status status = curi_status_success;

    if (status == curi_status_success)
        status = parse_char('/', uri, len, offset, settings, userData);

    if (status == curi_status_success)
    {
        size_t initialOffset = *offset;
        curi_status tryStatus = curi_status_success;

        if (tryStatus == curi_status_success)
            tryStatus = parse_segment(uri, len, offset, settings, userData, 1);

        if (tryStatus == curi_status_success)
            tryStatus = parse_segments(uri, len, offset, settings, userData);

        if (tryStatus == curi_status_error)
            *offset = initialOffset;
        else
            status = tryStatus;
    }

    if (status == curi_status_success)
        status = handle_path(uri + initialOffset, *offset - initialOffset, settings, userData);

    return status;
}

static curi_status parse_path_relative(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // path-relative = segment-not-empty segments
    const size_t initialOffset = *offset;
    curi_status status = curi_status_success;

    if (status == curi_status_success)
    {
        size_t initialOffset = *offset;
        curi_status tryStatus = curi_status_success;

        if (tryStatus == curi_status_success)
            tryStatus = parse_segment(uri, len, offset, settings, userData, 1);

        if (tryStatus == curi_status_success)
            tryStatus = parse_segments(uri, len, offset, settings, userData);

        if (tryStatus == curi_status_error)
            *offset = initialOffset;
        else
            status = tryStatus;
    }

    if (status == curi_status_success)
        status = handle_path(uri + initialOffset, *offset - initialOffset, settings, userData);

    return status;
}

static curi_status parse_path_empty(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // path-empty = ""
    return curi_status_success;
}

static curi_status parse_path(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // path = path-absolute
    //      / path-relative
    //      / path-empty
    curi_status status = curi_status_error;

    if (status == curi_status_error)
        TRY(status,offset,parse_path_absolute(uri, len, offset, settings, userData));

    if (status == curi_status_error)
        TRY(status,offset,parse_path_relative(uri, len, offset, settings, userData));

    if (status == curi_status_error)
        TRY(status,offset,parse_path_empty(uri, len, offset, settings, userData));

    return status;
}

static curi_status parse_hier_part(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // hier-part = "//" authority path-absolute-or-empty
    //             / path
    curi_status status = curi_status_error;

    if (status == curi_status_error)
    {
        size_t initialOffset = *offset;
        curi_status tryStatus = curi_status_success;
        if (tryStatus == curi_status_success)
            tryStatus = parse_char('/', uri, len, offset, settings, userData);
        if (tryStatus == curi_status_success)
            tryStatus = parse_char('/', uri, len, offset, settings, userData);
        if (tryStatus == curi_status_success)
            tryStatus = parse_authority(uri, len, offset, settings, userData);
        if (tryStatus == curi_status_success)
            tryStatus = parse_path_absolute_or_empty(uri, len, offset, settings, userData);
        if (tryStatus == curi_status_error)
            *offset = initialOffset;
        else
            status = tryStatus;
    }

    if (status == curi_status_error)
        TRY(status,offset,parse_path(uri, len, offset, settings, userData));

    return status;
}

#define CASE_QUERY_FRAGMENT_CHAR_NO_PCT \
    CASE_PCHAR_NO_PCT: \
    case '/': \
    case '?'

static curi_status parse_query_fragment_char(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // query_fragment_char = pchar / "/" / "?"

    switch (*read_char(uri, len, offset))
    {
        CASE_QUERY_FRAGMENT_CHAR_NO_PCT:
            return curi_status_success;
            break;
        case '%':
            return parse_h8(uri, len, offset, settings, userData);
            break;
        default:
            return curi_status_error;
            break;
    }
}

static curi_status parse_query_item(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // query_item = query_item_key [query_item_key_separator query_item_value]
    // query_item_key = *query_fragment_char (but no query_item_separator or query_item_key_separator)
    // query_item_separator = settings->query_item_separator (default is "&")
    // query_item_key_separator = settings->query_item_key_separator (default is "=")
    // query_item_value = *query_fragment_char (but no query_item_separator)

    const size_t keyStartOffset = *offset;
    size_t keyEndOffset;

    curi_status status = curi_status_success;
    while (status == curi_status_success)
    {
        size_t previousOffset = *offset;

        char c = *read_char(uri, len, offset);
        if (c == settings->query_item_separator)
            status = curi_status_error;
        else if (c == settings->query_item_key_separator)
            status = curi_status_error;
        else
        {
            switch (c)
            {
                CASE_QUERY_FRAGMENT_CHAR_NO_PCT:
                    status = curi_status_success;
                    break;
                case '%':
                    status = parse_h8(uri, len, offset, settings, userData);
                    break;
                default:
                    status = curi_status_error;
                    break;
            }
        }

        if (status != curi_status_success)
            *offset = previousOffset;
    };

    keyEndOffset = *offset;

    status = parse_char(settings->query_item_key_separator, uri, len, offset, settings, userData);

    if (status == curi_status_success)
    {
        // There is a value
        const size_t valueStartOffset = *offset;

        while (status == curi_status_success)
        {
            size_t previousOffset = *offset;

            char c = *read_char(uri, len, offset);
            if (c == settings->query_item_separator)
                status = curi_status_error;
            else
            {
                switch (c)
                {
                    CASE_QUERY_FRAGMENT_CHAR_NO_PCT:
                        status = curi_status_success;
                        break;
                    case '%':
                        status = parse_h8(uri, len, offset, settings, userData);
                        break;
                    default:
                        status = curi_status_error;
                        break;
                }
            }

            if (status != curi_status_success)
                *offset = previousOffset;
        }

        status = handle_query_item(uri + keyStartOffset, keyEndOffset - keyStartOffset, uri + valueStartOffset, *offset - valueStartOffset, settings, userData);
    }
    else
    {
        *offset = keyEndOffset;
        // There is no value
        status = handle_query_item(uri + keyStartOffset, keyEndOffset - keyStartOffset, 0, 0, settings, userData);
    }

    return status;
}

static curi_status parse_query(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData, int parseSeparator)
{
    // If not interested in individual items,
    //      query = "?" *query_fragment_char
    // if interested,
    //      query = "?" query_item *(query_item_separator query_item)
    //      query_item_separator = settings->query_item_separator (default is "&")

    curi_status status = curi_status_success;

    size_t queryStartOffset;

    if (parseSeparator && status == curi_status_success)
        status = parse_char('?', uri, len, offset, settings, userData);

    queryStartOffset = *offset;

    if (status == curi_status_success)
    {
        if (!settings->query_item_null_callback && !settings->query_item_int_callback && !settings->query_item_double_callback && !settings->query_item_str_callback)
        {
            while (status == curi_status_success)
            {
                size_t previousOffset = *offset;

                status = parse_query_fragment_char(uri, len, offset, settings, userData);

                if (status != curi_status_success)
                    *offset = previousOffset;
            }

            status = curi_status_success;
        }
        else
        {
            status = parse_query_item(uri, len, offset, settings, userData);

            if (status == curi_status_success)
            {
                curi_status tryStatus = curi_status_success;
                while (tryStatus == curi_status_success)
                {
                    size_t previousOffset = *offset;

                    tryStatus = parse_char(settings->query_item_separator, uri, len, offset, settings, userData);

                    if (tryStatus == curi_status_success)
                        tryStatus = parse_query_item(uri, len, offset, settings, userData);

                    if (tryStatus == curi_status_error)
                        *offset = previousOffset;
                    else
                        status = tryStatus;
                }
            }
        }
    }

    if (status == curi_status_success)
        status = handle_query(uri + queryStartOffset, *offset - queryStartOffset, settings, userData);

    return status;
}

static curi_status parse_fragment(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // fragment = "#" *query_fragment_char
    curi_status status = curi_status_success;
    size_t fragmentStartOffset;

    if (status == curi_status_success)
        status = parse_char('#', uri, len, offset, settings, userData);

    fragmentStartOffset = *offset;

    if (status == curi_status_success)
    {
        while (status == curi_status_success)
        {
            size_t previousOffset = *offset;

            status = parse_query_fragment_char(uri, len, offset, settings, userData);

            if (status != curi_status_success)
                *offset = previousOffset;
        }
        status = curi_status_success;
    }

    if (status == curi_status_success)
        status = handle_fragment(uri + fragmentStartOffset, *offset - fragmentStartOffset, settings, userData);

    return status;
}

static curi_status parse_full_uri(const char* uri, size_t len, size_t* offset, const curi_settings* settings, void* userData)
{
    // URI = scheme ":" hier-part [ query ] [ fragment ]
    curi_status status = curi_status_success;

    if (status == curi_status_success)
        status = parse_scheme(uri, len, offset, settings, userData);

    if (status == curi_status_success)
        status = parse_char(':', uri, len, offset, settings, userData);

    if (status == curi_status_success)
        status = parse_hier_part(uri, len, offset, settings, userData);

    if (status == curi_status_success)
        TRY(status, offset, parse_query(uri, len, offset, settings, userData, 1));

    if (status == curi_status_success)
        TRY(status, offset, parse_fragment(uri, len, offset, settings, userData));

    return status;
}

curi_status curi_parse_full_uri(const char* uri, size_t len, const curi_settings* settings /*= 0*/, void* userData /*= 0*/)
{
    size_t offset = 0;
    curi_status status;

    if (settings)
    {
        // parsing with the given settings
        status = parse_full_uri(uri, len, &offset, settings, userData);
    }
    else
    {
        curi_settings defaultSettings;
        curi_default_settings(&defaultSettings);
        // parsing with default settings
        status = parse_full_uri(uri, len, &offset, &defaultSettings, userData);
    }

    if (status == curi_status_success && *read_char(uri,len,&offset) != '\0')
        // the URI weren't fully consumed
        // TODO: set an error string somewhere
        status = curi_status_error;

    return status;
}

curi_status curi_parse_full_uri_nt(const char* uri, const curi_settings* settings /*= 0*/, void* userData /*= 0*/)
{
    return curi_parse_full_uri(uri, SIZE_MAX, settings, userData);
}

curi_status curi_parse_path(const char* path, size_t len, const curi_settings* settings /*= 0*/, void* userData /*= 0*/)
{
    size_t offset = 0;
    curi_status status;

    if (settings)
    {
        // parsing with the given settings
        status = parse_path(path, len, &offset, settings, userData);
    }
    else
    {
        curi_settings defaultSettings;
        curi_default_settings(&defaultSettings);
        // parsing with default settings
        status = parse_path(path, len, &offset, &defaultSettings, userData);
    }

    if (status == curi_status_success && *read_char(path, len, &offset) != '\0')
        // the imput weren't fully consumed
        // TODO: set an error string somewhere
        status = curi_status_error;

    return status;
}


curi_status curi_parse_path_nt(const char* path, const curi_settings* settings /*= 0*/, void* userData /*= 0*/)
{
    return curi_parse_path(path, SIZE_MAX, settings, userData);
}

curi_status curi_parse_query(const char* query, size_t len, const curi_settings* settings /*= 0*/, void* userData /*= 0*/)
{
    size_t offset = 0;
    curi_status status;

    if (settings)
    {
        // parsing with the given settings
        status = parse_query(query, len, &offset, settings, userData, 0);
    }
    else
    {
        curi_settings defaultSettings;
        curi_default_settings(&defaultSettings);
        // parsing with default settings
        status = parse_query(query, len, &offset, &defaultSettings, userData, 0);
    }

    if (status == curi_status_success && *read_char(query, len, &offset) != '\0')
        // the imput weren't fully consumed
        // TODO: set an error string somewhere
        status = curi_status_error;

    return status;
}

curi_status curi_parse_query_nt(const char* query, const curi_settings* settings /*= 0*/, void* userData /*= 0*/)
{
    return curi_parse_query(query, SIZE_MAX, settings, userData);
}

curi_status curi_url_decode(const char* input, size_t inputLen, char* output, size_t outputCapacity, size_t* outputLen /*=0*/)
{
    curi_status status = curi_status_error;
    size_t inputOffset = 0;
    size_t outputOffset = 0;

    #define HEXTOI(x) (isdigit(x) ? x - '0' : tolower(x) - 'a' + 10)

    while ( outputOffset < outputCapacity )
    {
        status = curi_status_error;
        if (status == curi_status_error)
        {
            // percent encoding
            TRY(status, &inputOffset, parse_percent_encoded(input, inputLen, &inputOffset, 0, 0));

            if (status == curi_status_success)
            {
                int encodedChar = ((HEXTOI(input[inputOffset - 2]) << 4) | HEXTOI(tolower(input[inputOffset - 1])));
                if (encodedChar < 128) // Only support ascii percent encodage at the moment.
                {
                    output[outputOffset] = (char)encodedChar;
                    ++outputOffset;
                }
                else
                {
                    status = curi_status_error;
                }
            }
        }

        if (status == curi_status_error)
        {
            // '+' as a space
            TRY(status, &inputOffset, parse_char('+', input, inputLen, &inputOffset, 0, 0));
            if (status == curi_status_success)
            {
                 output[outputOffset] = ' ';
                 ++outputOffset;
            }
        }

        if (status == curi_status_error)
        {
            // "any" character
            output[outputOffset] = *read_char(input, inputLen, &inputOffset);
            if (output[outputOffset] == '\0')
            {
                if (outputLen)
                    *outputLen = outputOffset;

                return curi_status_success;
            }
            else
            {
                ++outputOffset;
            }
        }
    }

    if (*read_char(input, inputLen, &inputOffset) == '\0')
    {
        if (outputLen)
            *outputLen = outputOffset;

        return curi_status_success;
    }
    else
    {
        return curi_status_error;
    }
}

curi_status curi_url_decode_nt(const char* input, char* output, size_t outputCapacity, size_t* outputLen /*=0*/)
{
    return curi_url_decode(input, SIZE_MAX, output, outputCapacity, outputLen);
}

#ifdef _MSC_VER
#   pragma warning(pop)
#endif
