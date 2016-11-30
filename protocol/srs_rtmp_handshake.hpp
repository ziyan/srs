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

#ifndef SRS_RTMP_PROTOCOL_HANDSHKAE_HPP
#define SRS_RTMP_PROTOCOL_HANDSHKAE_HPP

/*
#include <srs_rtmp_handshake.hpp>
*/

#include <srs_core.hpp>

class ISrsProtocolReaderWriter;
class SrsComplexHandshake;
class SrsHandshakeBytes;
class SrsStream;

/**
* simple handshake.
* user can try complex handshake first, 
* rollback to simple handshake if error ERROR_RTMP_TRY_SIMPLE_HS
*/
class SrsSimpleHandshake
{
public:
    SrsSimpleHandshake();
    virtual ~SrsSimpleHandshake();
public:
    /**
    * simple handshake.
    */
    virtual int handshake_with_client(SrsHandshakeBytes* hs_bytes, ISrsProtocolReaderWriter* io);
    virtual int handshake_with_server(SrsHandshakeBytes* hs_bytes, ISrsProtocolReaderWriter* io);
};

/**
* rtmp complex handshake,
* @see also crtmp(crtmpserver) or librtmp,
* @see also: http://blog.csdn.net/win_lin/article/details/13006803
*/
class SrsComplexHandshake
{
public:
    SrsComplexHandshake();
    virtual ~SrsComplexHandshake();
public:
    /**
    * complex hanshake.
    * @return user must:
    *     continue connect app if success,
    *     try simple handshake if error is ERROR_RTMP_TRY_SIMPLE_HS,
    *     otherwise, disconnect
    */
    virtual int handshake_with_client(SrsHandshakeBytes* hs_bytes, ISrsProtocolReaderWriter* io);
    virtual int handshake_with_server(SrsHandshakeBytes* hs_bytes, ISrsProtocolReaderWriter* io);
};

#endif
