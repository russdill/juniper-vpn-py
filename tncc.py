#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import mechanize
import cookielib
import struct
import ssl
import base64
import collections
import zlib
import HTMLParser

ssl._create_default_https_context = ssl._create_unverified_context

# 0013 - Message
def decode_0013(buf):
    ret = collections.defaultdict(list)
    while (len(buf) >= 12):
        length, cmd, out = decode_packet(buf)
        buf = buf[length:]
        ret[cmd].append(out)
    return ret

# 0012 - u32
def decode_0012(buf):
    return struct.unpack(">I", buf)

# 0ce4 - encapsulation
def decode_0ce4(buf):
    ret = collections.defaultdict(list)
    while (len(buf) >= 12):
        length, cmd, out = decode_packet(buf)
        buf = buf[length:]
        ret[cmd].append(out)
    return ret

# 0ce5 - string without hex prefixer
def decode_0ce5(buf):
    return struct.unpack(str(len(buf)) + "s", buf)

# 0ce7 - string with hex prefixer
def decode_0ce7(buf):
    _, s = struct.unpack(">I" + str(len(buf) - 4) + "s", buf)
    return s

# 0cf0 - encapsulation
def decode_0cf0(buf):
    ret = dict()
    cmd, _, out = decode_packet(buf)
    ret[cmd] = out
    return ret

# 0cf1 - string without hex prefixer
def decode_0cf1(buf):
    return struct.unpack(str(len(buf)) + "s", buf)

# 0cf3 - u32
def decode_0cf3(buf):
    return struct.unpack(">I", buf)

def decode_packet(buf):
    cmd, _1, _2, length, _3 = struct.unpack(">IBBHI", buf[:12])
    if (length < 12):
        raise Exception("Invalid packet")

    data = buf[12:length]

    if cmd == 0x0013:
        data = decode_0013(data)
    elif cmd == 0x0012:
        data = decode_0012(data)
    elif cmd == 0x0ce4:
        data = decode_0ce4(data)
    elif cmd == 0x0ce5:
        data = decode_0ce5(data)
    elif cmd == 0x0ce7:
        data = decode_0ce7(data)
    elif cmd == 0x0cf0:
        data = decode_0cf0(data)
    elif cmd == 0x0cf1:
        data = decode_0cf1(data)
    elif cmd == 0x0cf3:
        data = decode_0cf3(data)
    else:
        data = None

    return length, cmd, data

def encode_packet(cmd, align, buf):
    if (align > 1 and (len(buf) + 12) % align):
        buf += struct.pack(str(align - len(buf) % align) + "x")

    return struct.pack(">IBBHI", cmd, 0xc0, 0x00, len(buf) + 12, 0x0000583) + buf

# 0013 - Message
def encode_0013(buf):
    return encode_packet(0x0013, 4, buf)

# 0012 - u32
def encode_0012(i):
    return encode_packet(0x0012, 1, struct.pack("<I", i))

# 0ce4 - encapsulation
def encode_0ce4(buf):
    return encode_packet(0x0ce4, 4, buf)

# 0ce5 - string without hex prefixer
def encode_0ce5(s):
    return encode_packet(0x0ce5, 1, struct.pack(str(len(s)) + "s", s))

# 0ce7 - string with hex prefixer
def encode_0ce7(s):
    return encode_packet(0x0ce7, 1, struct.pack(">I" + str(len(s)) + "sx",
                                0x00058316, s))

# 0cf0 - encapsulation
def encode_0cf0(buf):
    return encode_packet(0x0cf0, 4, buf)

# 0cf1 - string without hex prefixer
def encode_0cf1(s):
    return encode_packet(0x0ce5, 1, struct.pack(str(len(s)) + "s", s))

# 0cf3 - u32
def encode_0cf3(i):
    return encode_packet(0x0013, 1, struct.pack("<I", i))

class tncc(object):
    def __init__(self, vpn_host):
        self.vpn_host = vpn_host

        self.br = mechanize.Browser()

        self.cj = cookielib.LWPCookieJar()
        self.br.set_cookiejar(self.cj)

        # Browser options
        self.br.set_handle_equiv(True)
        self.br.set_handle_redirect(True)
        self.br.set_handle_referer(True)
        self.br.set_handle_robots(False)

        # Follows refresh 0 but not hangs on refresh > 0
        self.br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(),
                              max_time=1)

        # Want debugging messages?
        #self.br.set_debug_http(True)
        #self.br.set_debug_redirects(True)
        #self.br.set_debug_responses(True)

        self.user_agent = 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'
        self.br.addheaders = [('User-agent', self.user_agent)]

    def find_cookie(self, name):
        for cookie in self.cj:
            if cookie.name == name:
                return cookie
        return None

    def parse_response(self):
        # Read in key/token fields in HTTP response
        response = dict()
        last_key = ''
        for line in self.r.readlines():
            line = line.strip()
            # Note that msg is too long and gets wrapped, handle it special
            if last_key == 'msg' and len(line):
                response['msg'] += line
            else:
                key = ''
                try:
                    key, val = line.split('=', 1)
                    response[key] = val
                except:
                    pass
                last_key = key
        return response

    def get_msg_contents(self, msg_value):
        # msg has the stuff we want, it's base64 encoded
        msg_raw = base64.b64decode(msg_value)
        _1, _2, msg_decoded = decode_packet(msg_raw)

        # Within msg, there is a field of data
        compressed = msg_decoded[0x0ce4][0][0x0ce7][0]

        # That field has a field that is compressed, decompress it
        typ, length, data = compressed.split(':', 2)
        if typ == 'COMPRESSED':
            data = zlib.decompress(data)
        else:
            raise Exception("Unknown storage type", typ)
        return data

    def parse_msg(self, msg_data):
        # The decompressed data is HTMLish, decode it. The value="" of each
        # tag is the data we want.
        objs = []
        class ParamHTMLParser(HTMLParser.HTMLParser):
            def handle_starttag(self, tag, attrs):
                for key, value in attrs:
                    if key == 'value':
                        # It's made up of a bunch of key=value pairs separated
                        # by semicolons
                        d = dict()
                        for field in value.split(';'):
                            field = field.strip()
                            try:
                                key, value = field.split('=', 1)
                                d[key] = value
                            except:
                                pass
                        objs.append(d)
        p = ParamHTMLParser()
        p.feed(msg_data)
        p.close()
        return objs

    def get_cookie(self, dspreauth=None, dssignin=None):

        if (dspreauth is None or dssignin is None):
            self.r = self.br.open('https://' + self.vpn_host)
        else:
            self.cj.set_cookie(dspreauth)
            self.cj.set_cookie(dssignin)

        msg_raw = encode_0013(encode_0ce4(encode_0ce7('policy request')) +
            encode_0ce5('Accept-Language: en'))

        msg = base64.b64encode(msg_raw)

        post_data = 'connId=0;msg=' + msg + ';firsttime=1;'

        self.r = self.br.open('https://' + self.vpn_host + '/dana-na/hc/tnchcupdate.cgi', post_data)

        # Parse the data returned into a key/value dict
        response = self.parse_response()

        # Pull the compressed data block out of msg
        data = self.get_msg_contents(response['msg'])

        # Pull the data out of the 'value' key in the htmlish stuff returned
        objs = self.parse_msg(data)

        # Make a set of policies
        policies = set()
        for entry in objs:
            if 'policy' in entry:
                policies.add(entry['policy'])

        # Everything is OK, this may need updating if OK isn't the right answer
        policy_report = ""
        for policy in policies:
            policy_report += '\npolicy:' + policy + '\nstatus:OK\n'

        msg_raw = encode_0013(encode_0ce4(encode_0ce7(policy_report)) +
            encode_0ce5('Accept-Language: en'))

        msg = base64.b64encode(msg_raw)

        post_data = 'connId=1;msg=' + msg + ';firsttime=1;'

        self.r = self.br.open('https://' + self.vpn_host + '/dana-na/hc/tnchcupdate.cgi', post_data)

        # We have a new DSPREAUTH cookie
        return self.find_cookie('DSPREAUTH')

if __name__ == "__main__":
    vpn_host = sys.argv[1]
    if len(sys.argv) == 4:
        dspreauth = sys.argv[2]
        dssignin = sys.argv[3]

        dspreauth_cookie = cookielib.Cookie(version=0, name='DSPREAUTH', value=dspreauth,
                    port=None, port_specified=False, domain='',
                    domain_specified=False, domain_initial_dot=False, path='/',
                    path_specified=False, secure=False, expires=None, discard=True,
                    comment=None, comment_url=None, rest=None, rfc2109=False)
        dssignin_cookie = cookielib.Cookie(version=0, name='DSSIGNIN', value=dssignin,
                    port=None, port_specified=False, domain='',
                    domain_specified=False, domain_initial_dot=False, path='/',
                    path_specified=False, secure=False, expires=None, discard=True,
                    comment=None, comment_url=None, rest=None, rfc2109=False)
    else:
        dspreauth_cookie = None
        dssignin_cookie = None

    t = tncc(vpn_host)
    print t.get_cookie(dspreauth_cookie, dssignin_cookie).value
