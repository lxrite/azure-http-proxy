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

#ifndef CURI_H
#define CURI_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup parsing URI parsing
    \brief Parsing URIs and URI elements.
 */

/** Error codes returned from this interface
    \ingroup parsing
*/
typedef enum
{
    curi_status_success = 0, //!< No error
    curi_status_canceled, //!< A callback returned 0, stopping the operation
    curi_status_error //!< An error occured
} curi_status;

/** Parsing parameters
    \ingroup parsing
*/
typedef struct
{
    void* (*allocate)(void* userData, size_t size); //!< function used for memory allocation (default is based on malloc).
    void (*deallocate)(void* userData, void* ptr, size_t size); //!< function used for memory deallocation (default is based on free).
    int (*scheme_callback)(void* userData, const char* scheme, size_t schemeLen); //!< if not-NULL, called with the parsed scheme (default is NULL).
    int (*userinfo_callback)(void* userData, const char* userinfo, size_t userinfoLen); //!< if not-NULL, called with the parsed userinfo (default is NULL).
    int (*host_callback)(void* userData, const char* host, size_t hostLen); //!< if not-NULL, called with the parsed host (default is NULL).
    int (*portStr_callback)(void* userData, const char* portStr, size_t portStrLen); //!< if not-NULL, called with the parsed port (default is NULL).
    int (*port_callback)(void* userData, unsigned int port); //!< if not-NULL, called with the parsed port as a number (default is NULL).
    int (*path_callback)(void* userData, const char* path, size_t pathLen); //!< if not-NULL, called with the parsed path (default is NULL).
    int (*path_segment_callback)(void* userData, const char* pathSegment, size_t pathSegmentLen); //!< if not-NULL, called with the parsed path segment (default is NULL).
    int (*query_callback)(void* userData, const char* query, size_t queryLen); //!< if not-NULL, called with the parsed query (default is NULL).
    int (*query_item_null_callback)(void* userData, const char* queryItemKey, size_t queryItemKeyLen); //!< if not-NULL, called with each of the parsed query items having no value (default is NULL).
    int (*query_item_int_callback)(void* userData, const char* queryItemKey, size_t queryItemKeyLen, long int queryItemValue); //!< if not-NULL, called with each of the parsed query items having an int value (default is NULL).
    int (*query_item_double_callback)(void* userData, const char* queryItemKey, size_t queryItemKeyLen, double queryItemValue); //!< if not-NULL, called with each of the parsed query items having an double value (default is NULL).
    int (*query_item_str_callback)(void* userData, const char* queryItemKey, size_t queryItemKeyLen, const char* queryItemValue, size_t queryItemValueLen); //!< if not-NULL, called with each of the parsed query items that hasn't been handled by the previous callbacks (default is NULL).
    char query_item_separator; //!< the character separating query items (default is '&').
    char query_item_key_separator; //!< the character separating, in query items, the key from the value (default is '=').
    int (*fragment_callback)(void* userData, const char* fragment, size_t fragmentLen); //!< if not-NULL, called with the parsed fragment (default is NULL).
    int url_decode; //!< if != 0, the string passed to the callbacks ae first url decoded, requiring the allocation of a temporary string.
} curi_settings;

/** Set the given settings to their default value

    \ingroup parsing
*/
void curi_default_settings(curi_settings* settings);

/** Parse the given NULL-terminated string as a full URI.

    \note This function doesn't do compute `strlen(uri)`, it calls `curi_parse_full_uri`
    with a length set to SIZE_MAX.

    \ingroup parsing
*/
curi_status curi_parse_full_uri_nt(const char* uri, const curi_settings* settings /*= 0*/, void* userData /*= 0*/);

/** Parse the given string as a full URI specifying its length.

    \note In practice the parsing ends once the given length is reached or a
    NULL-character ('\0') is read, making this function working for NULL-terminated
    string as well.

    \ingroup parsing
*/
curi_status curi_parse_full_uri(const char* uri, size_t len, const curi_settings* settings /*= 0*/, void* userData /*= 0*/);

/** Parse the given NULL-terminated string as a URI path.

    \note This function doesn't do compute `strlen(path)`, it calls `curi_parse_path`
    with a length set to SIZE_MAX.

    \ingroup parsing
*/
curi_status curi_parse_path_nt(const char* path, const curi_settings* settings /*= 0*/, void* userData /*= 0*/);

/** Parse the given string as a URI path specifying its length.

    \note In practice the parsing ends once the given length is reached or a
    NULL-character ('\0') is read, making this function working for NULL-terminated
    string as well.

    \ingroup parsing
*/
curi_status curi_parse_path(const char* path, size_t len, const curi_settings* settings /*= 0*/, void* userData /*= 0*/);

/** Parse the given NULL-terminated string as a URI query.

    \note This function doesn't do compute `strlen(query)`, it calls `curi_parse_query`
    with a length set to SIZE_MAX.

    \ingroup parsing
*/
curi_status curi_parse_query_nt(const char* query, const curi_settings* settings /*= 0*/, void* userData /*= 0*/);

/** Parse the given string as a URI query specifying its length.

    \note In practice the parsing ends once the given length is reached or a
    NULL-character ('\0') is read, making this function working for NULL-terminated
    string as well.

    \ingroup parsing
*/
curi_status curi_parse_query(const char* query, size_t len, const curi_settings* settings /*= 0*/, void* userData /*= 0*/);

/** \defgroup url_decoding URL decoding
    \brief Decoding percent encoded strings.
 */

/** URL Decode the given string.

    - Percent decoding of ascii characters (from %00 to %1F) are supported
    - as well as '+' standing for a space.

    \note This function doesn't do compute `strlen(input)`, it calls `curi_url_decode`
    with a length set to SIZE_MAX.

    \ingroup url_decoding
*/
curi_status curi_url_decode_nt(const char* input, char* output, size_t outputCapacity, size_t* outputLen /*=0*/);

/** URL Decode the given string.

    - Percent decoding of ascii characters (from %00 to %1F) are supported
    - as well as '+' standing for a space.

    \note In practice the parsing ends once the given length is reached or a
    NULL-character ('\0') is read, making this function working for NULL-terminated
    string as well.

    \ingroup url_decoding
*/
curi_status curi_url_decode(const char* input, size_t inputLen, char* output, size_t outputCapacity, size_t* outputLen /*=0*/);

#ifdef __cplusplus
}
#endif

#endif
