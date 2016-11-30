/*
The MIT License (MIT)

Copyright (c) 2013-2015 SRS(ossrs)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <srs_rtmp_handshake.hpp>

#include <time.h>

#include <srs_core_autofree.hpp>
#include <srs_kernel_error.hpp>
#include <srs_kernel_log.hpp>
#include <srs_rtmp_io.hpp>
#include <srs_rtmp_utility.hpp>
#include <srs_rtmp_stack.hpp>
#include <srs_kernel_stream.hpp>

SrsSimpleHandshake::SrsSimpleHandshake()
{
}

SrsSimpleHandshake::~SrsSimpleHandshake()
{
}

int SrsSimpleHandshake::handshake_with_client(SrsHandshakeBytes* hs_bytes, ISrsProtocolReaderWriter* io)
{
    int ret = ERROR_SUCCESS;
    
    ssize_t nsize;
    
    if ((ret = hs_bytes->read_c0c1(io)) != ERROR_SUCCESS) {
        return ret;
    }

    // plain text required.
    if (hs_bytes->c0c1[0] != 0x03) {
        ret = ERROR_RTMP_PLAIN_REQUIRED;
        srs_warn("only support rtmp plain text. ret=%d", ret);
        return ret;
    }
    srs_verbose("check c0 success, required plain text.");
    
    if ((ret = hs_bytes->create_s0s1s2(hs_bytes->c0c1 + 1)) != ERROR_SUCCESS) {
        return ret;
    }
    
    if ((ret = io->write(hs_bytes->s0s1s2, 3073, &nsize)) != ERROR_SUCCESS) {
        srs_warn("simple handshake send s0s1s2 failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("simple handshake send s0s1s2 success.");
    
    if ((ret = hs_bytes->read_c2(io)) != ERROR_SUCCESS) {
        return ret;
    }
    
    srs_trace("simple handshake success.");
    
    return ret;
}

int SrsSimpleHandshake::handshake_with_server(SrsHandshakeBytes* hs_bytes, ISrsProtocolReaderWriter* io)
{
    int ret = ERROR_SUCCESS;
    
    ssize_t nsize;
    
    // simple handshake
    if ((ret = hs_bytes->create_c0c1()) != ERROR_SUCCESS) {
        return ret;
    }
    
    if ((ret = io->write(hs_bytes->c0c1, 1537, &nsize)) != ERROR_SUCCESS) {
        srs_warn("write c0c1 failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("write c0c1 success.");
    
    if ((ret = hs_bytes->read_s0s1s2(io)) != ERROR_SUCCESS) {
        return ret;
    }
    
    // plain text required.
    if (hs_bytes->s0s1s2[0] != 0x03) {
        ret = ERROR_RTMP_HANDSHAKE;
        srs_warn("handshake failed, plain text required. ret=%d", ret);
        return ret;
    }
    
    if ((ret = hs_bytes->create_c2()) != ERROR_SUCCESS) {
        return ret;
    }
    
    // for simple handshake, copy s1 to c2.
    // @see https://github.com/ossrs/srs/issues/418
    memcpy(hs_bytes->c2, hs_bytes->s0s1s2 + 1, 1536);
    
    if ((ret = io->write(hs_bytes->c2, 1536, &nsize)) != ERROR_SUCCESS) {
        srs_warn("simple handshake write c2 failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("simple handshake write c2 success.");
    
    srs_trace("simple handshake success.");
    
    return ret;
}

SrsComplexHandshake::SrsComplexHandshake()
{
}

SrsComplexHandshake::~SrsComplexHandshake()
{
}

int SrsComplexHandshake::handshake_with_client(SrsHandshakeBytes* /*hs_bytes*/, ISrsProtocolReaderWriter* /*io*/)
{
    return ERROR_RTMP_TRY_SIMPLE_HS;
}

int SrsComplexHandshake::handshake_with_server(SrsHandshakeBytes* /*hs_bytes*/, ISrsProtocolReaderWriter* /*io*/)
{
    return ERROR_RTMP_TRY_SIMPLE_HS;
}
