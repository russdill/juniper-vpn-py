#!/usr/bin/env python3

import subprocess
import threading
import http.cookiejar
import getpass
import sys
import os
import ssl
import argparse
import signal
import configparser
import time
import binascii
import hmac
import hashlib
import shlex
import platform
import socket
import datetime
import logging
import contextlib
import math
from collections import defaultdict

import mechanize
import netifaces

from junipervpn import tncc

ssl._create_default_https_context = ssl._create_unverified_context

"""
OATH code from https://github.com/bdauvergne/python-oath
Copyright 2010, Benjamin Dauvergne

* All rights reserved.
* Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.'''
"""

def truncated_value(h):
    bytes = list(map(ord, h))
    offset = bytes[-1] & 0xf
    v = (bytes[offset] & 0x7f) << 24 | (bytes[offset+1] & 0xff) << 16 | \
            (bytes[offset+2] & 0xff) << 8 | (bytes[offset+3] & 0xff)
    return v

def dec(h,p):
    v = truncated_value(h)
    v = v % (10**p)
    return '{v:0>{p}}'.format(p=p, v=v)

def int2beint64(i):
    hex_counter = hex(int(i))[2:-1]
    hex_counter = '0' * (16 - len(hex_counter)) + hex_counter
    bin_counter = binascii.unhexlify(hex_counter)
    return bin_counter

def hotp(key):
    key = binascii.unhexlify(key)
    counter = int2beint64(int(time.time()) / 30)
    return dec(hmac.new(key, counter, hashlib.sha256).digest(), 6)


class NetworkMonitorThread(threading.Thread):
    """
    :param rate: Number of packets emitted per second
    :type rate: float

    :param on_disconnect: Callable to call when a network disconnection is
        detected.
    :type on_disconnect: collections.abc.Callable

    :param hosts: List of hosts to ping. The first host is tried, and then the
        others in order until a pingable host is found.
    :type hosts: list(str)

    :param ping: Ping command to use.
    :type ping: str

    :param ping_rate: Ping rate in packet/s
    :type ping_rate: float

    :param ping_duration: Duration of each ping command. A short-enough interval is
        preferred, so that the script can react quickly to network outage
    :type ping_duration: int

    :param connect_timeout: Time to wait in seconds between reconnection
        attempts.
    :type connect_timeout: float

    :param daemon: Passed to threading.Thread.
    :type daemon: bool
    """
    def __init__(self,
        on_disconnect,
        hosts=['8.8.8.8'],
        ping='ping',
        connect_timeout=10,
        ping_rate=1,
        ping_duration=2,
        daemon=True,
    ):
        self.hosts = hosts
        self.ping = ping
        self.ping_rate = ping_rate
        self.ping_duration = ping_duration
        self.connect_timeout = connect_timeout
        self.on_disconnect = on_disconnect

        self._stop = threading.Event()
        super().__init__(name='ping_network_monitor', daemon=daemon)

    def run(self):
        interval = 1 / self.ping_rate
        # interval < 0.2 is not allowed as regular user, so best avoided
        interval = interval if interval >= 0.2 else 0.2
        deadline = int(math.ceil(self.ping_duration))

        def ping():
            # Ping until either one host works, or raise the last exception
            # otherwise
            for host in self.hosts:
                cmd = [self.ping, '-q', '-w', str(deadline), '-i', str(interval), '--', host]
                # Separate ping output by at least an empty line
                print()
                try:
                    subprocess.check_call(cmd)
                except subprocess.CalledProcessError as e:
                    logging.debug('Failed to ping {}: {}'.format(host, e))
                    last_excep = e
                else:
                    return None

            raise last_excep

        # Exit the thread if it needs to be stopped.
        # It is executed before attempting any long command
        def check_stop():
            if self._stop.is_set():
                sys.exit(0)

        def sleep():
            time.sleep(self.connect_timeout)

        get_time = time.monotonic

        check_stop()

        # Sleep before entering the loop, to give time to the VPN to connect
        # for the first time. Otherwise, we risk detecting a dead connection
        # and immediately try to reconnect before it had a chance to establish
        # the connection
        sleep()

        start_time = get_time()
        issues_nr = 0

        while True:
            check_stop()
            try:
                ping()
            except subprocess.CalledProcessError:
                issues_nr += 1
                delta = get_time() - start_time
                # Avoid division by 0
                delta = delta if delta else 1
                delta_h = delta / 3600
                issues_per_h = issues_nr / delta_h

                logging.info("Connection seems to have died (#{issues}, {issues_per_h} issues per hour)".format(
                    issues=issues_nr,
                    issues_per_h=math.ceil(issues_per_h),
                ))
                check_stop()
                self.on_disconnect()
                check_stop()
                sleep()

    def stop(self):
        self._stop.set()


class ActionError(Exception):
    def __init__(self, msg, exit_code=1):
        self.msg = msg
        self.exit_code = exit_code

class JuniperVPN:
    def __init__(self, args, verbose=False):
        self.args = args
        self.verbose = verbose
        self.fixed_password = args.password is not None
        self.last_connect = 0
        self.monitor = None

        self.monitor_hosts = args.ping_host
        self.monitor_connect_timeout = args.connect_timeout
        self.monitor_ping_rate = args.ping_rate

        if args.enable_funk:
            if not args.platform:
                args.platform = platform.system() + ' ' + platform.release()
            if not args.hostname:
                args.hostname = socket.gethostname()
            if not args.hwaddr:
                args.hwaddr = []
                for iface in netifaces.interfaces():
                    try:
                        mac = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
                    except Exception:
                        pass
                    else:
                        if mac != '00:00:00:00:00:00':
                            args.hwaddr.append(mac)
            else:
                args.hwaddr = [n.strip() for n in args.hwaddr.split(',')]

            certs = []
            if args.certs:
                now = datetime.datetime.now()
                for f in args.certs.split(','):
                    cert = tncc.X509Cert(f.strip())
                    if now < cert.not_before:
                        logging.warning('{} is not yet valid'.format(f))
                    if now > cert.not_after:
                        logging.warning('{} is expired'.format(f))
                    certs.append(cert)
                args.certs = [n.strip() for n in args.certs.split(',')]
            args.certs = certs

        self.br = mechanize.Browser()

        self.cj = http.cookiejar.LWPCookieJar()
        self.br.set_cookiejar(self.cj)

        # Browser options
        self.br.set_handle_equiv(True)
        self.br.set_handle_redirect(True)
        self.br.set_handle_referer(True)
        self.br.set_handle_robots(False)

        # Follows refresh 0 but not hangs on refresh > 0
        self.br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(),
                              max_time=1)

        if self.verbose:
            self.br.set_debug_http(True)
            self.br.set_debug_redirects(True)
            self.br.set_debug_responses(True)

        if args.user_agent:
            self.user_agent = args.user_agent
        else:
            self.user_agent = 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'

        self.br.addheaders = [('User-agent', self.user_agent)]

        self.last_action = None
        self.needs_2factor = False
        self.key = None
        self.pass_postfix = None
        self.child = None

    def find_cookie(self, name):
        for cookie in self.cj:
            if cookie.name == name:
                return cookie
        return None

    def next_action(self):
        if self.find_cookie('DSID'):
            return 'connect'

        for form in self.br.forms():
            if form.name == 'frmLogin':
                return 'login'
            elif form.name == 'frmDefender':
                return 'key'
            elif form.name == 'frmNextToken':
                return 'key'
            elif form.name == 'frmConfirmation':
                return 'continue'
            else:
                raise ValueError('Unknown form type: {}'.format(form.name))
        return 'tncc'

    def run(self):
        # Open landing page
        self.r = self.br.open('https://' + self.args.host)
        while True:
            action = self.next_action()
            if action == 'tncc':
                self.action_tncc()
            elif action == 'login':
                self.action_login()
            elif action == 'key':
                self.action_key()
            elif action == 'continue':
                self.action_continue()
            elif action == 'connect':
                self.action_connect()

            self.last_action = action

    def action_tncc(self):
        # Run tncc host checker
        dspreauth_cookie = self.find_cookie('DSPREAUTH')
        if dspreauth_cookie is None:
            raise Exception('Could not find DSPREAUTH key for host checker')

        dssignin_cookie = self.find_cookie('DSSIGNIN')
        args = self.args
        t = tncc.TNCC(args.host, args.device_id, args.enable_funk,
                      args.platform, args.hostname, args.hwaddr, args.certs,
                      self.user_agent, verbose=self.verbose)
        self.cj.set_cookie(t.get_cookie(dspreauth_cookie, dssignin_cookie))

        self.r = self.br.open(self.r.geturl())

    def action_login(self):
        # The token used for two-factor is selected when this form is submitted.
        # If we aren't getting a password, then get the key now, otherwise
        # we could be sitting on the two factor key prompt later on waiting
        # on the user.

        # Enter username/password
        if not self.args.username:
            self.args.username = raw_input('Username: ')
        if self.args.password is None or self.last_action == 'login':
            if self.fixed_password:
                raise ActionError('Login failed (Invalid username or password?)')
            else:
                self.args.password = getpass.getpass('Password: ')
                self.needs_2factor = False
        if self.args.pass_prefix:
            self.pass_postfix = getpass.getpass("Secondary password postfix:")
        if self.needs_2factor:
            if self.args.oath:
                self.key = hotp(self.args.oath)
            else:
                self.key = getpass.getpass('Two-factor key:')
        else:
            self.key = None

        self.br.select_form(nr=0)
        self.br.form['username'] = self.args.username
        self.br.form['password'] = self.args.password
        if self.args.pass_prefix:
            if self.pass_postfix:
                secondary_password = "".join([  self.args.pass_prefix,
                                                self.pass_postfix])
            else:
                raise ActionError('Secondary password postfix not provided')
            self.br.form['password#2'] = secondary_password
        if self.args.realm:
            self.br.form['realm'] = [self.args.realm]
        self.r = self.br.submit()

    def action_key(self):
        # Enter key
        self.needs_2factor = True
        if self.args.oath:
            if self.last_action == 'key':
                raise ActionError('Login failed (Invalid OATH key)')
            self.key = hotp(self.args.oath)
        elif self.key is None:
            self.key = getpass.getpass('Two-factor key:')
        self.br.select_form(nr=0)
        self.br.form['password'] = self.key
        self.key = None
        self.r = self.br.submit()

    def action_continue(self):
        # Yes, I want to terminate the existing connection

        # Fix up the broken HTML
        html = self.r.read().decode('utf-8')
        html = html.replace('onclick="checkSelected()",  name="postfixSID"',
                            'onclick="checkSelected()"  name="postfixSID"')
        self.r.set_data(html.encode('utf-8'))
        self.br.set_response(self.r)

        # Select the existing connection to close
        self.br.select_form(nr=0)
        control = self.br.find_control(name="postfixSID")
        control.set_single(True)

        self.r = self.br.submit()

    def action_connect(self):
        now = time.time()
        delay = 10.0 - (now - self.last_connect)
        if delay > 0:
            logging.info('Waiting {:.0f}...'.format(delay))
            time.sleep(delay)
        self.last_connect = time.time();

        dsid = self.find_cookie('DSID').value
        action = []
        args = self.args
        for arg in args.action:
            arg = arg.replace('%DSID%', dsid).replace('%HOST%', args.host)
            action.append(arg)

        p = subprocess.Popen(action, stdin=subprocess.PIPE)
        self.child = p

        with self.monitor_cm():
            if args.stdin is not None:
                stdin = args.stdin.replace('%DSID%', dsid)
                stdin = stdin.replace('%HOST%', args.host)
                p.communicate(input=stdin.encode('ascii'))
            else:
                ret = p.wait()

        ret = p.returncode
        # Reset child to None so we don't try to kill a completed
        # process:
        self.child = None

        # Openconnect specific
        if ret == 2:
            self.cj.clear(args.host, '/', 'DSID')
            self.r = self.br.open(self.r.geturl())

    def start_monitor(self):
        self.stop_monitor()

        # If rate != 0, start the monitor
        if self.monitor_ping_rate:
            logging.info("Starting network monitoring...")
            monitor = NetworkMonitorThread(
                on_disconnect=self.reconnect,
                hosts=self.monitor_hosts,
                connect_timeout=self.monitor_connect_timeout,
                ping_rate=self.monitor_ping_rate,
            )
            monitor.start()
        else:
            monitor = None

        self.monitor = monitor

    def stop_monitor(self):
        if self.monitor:
            self.monitor.stop()
            logging.info("Stopped network monitoring")

    @contextlib.contextmanager
    def monitor_cm(self):
        """
        Context manager to monitor the connection and send SIGUSR2 to
        openconnect process to attempt reconnecting.
        """
        self.start_monitor()
        try:
            yield
        finally:
            self.stop_monitor()

    def reconnect(self):
        popen = self.child
        if popen:
            logging.info("Sending SIGUSR2 to openconnect to reconnect...")
            popen.send_signal(signal.SIGUSR2)

    def stop(self):
        if self.child:
            logging.info("Interrupt received, ending external program...")
            # Use SIGINT due to openconnect behavior where SIGINT will
            # run the vpnc-compatible script to clean up changes but
            # not upon SIGTERM.
            # http://permalink.gmane.org/gmane.network.vpn.openconnect.devel/2451
            try:
                self.child.send_signal(signal.SIGINT)
                self.child.wait()
            except OSError:
                pass

        self.stop_monitor()


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--host', type=str,
                        help='VPN host name')
    parser.add_argument('-r', '--realm', type=str,
                        help='VPN realm')
    parser.add_argument('-u', '--username', type=str,
                        help='User name')
    parser.add_argument('--pass-prefix', type=str,
                        help="Secondary password prefix")
    # Old spelling for backward compatibility, but undocumented
    parser.add_argument('--pass_prefix', type=str,
                        help=argparse.SUPPRESS)
    parser.add_argument('-o', '--oath', type=str,
                        help='OATH key for two factor authentication (hex)')
    parser.add_argument('--connect-timeout', type=float, default=10,
                        help='Timeout to wait between two connection attempts')
    parser.add_argument('--ping-host', type=str, action='append',
                        help='Host to ping to monitor the connection. Can be repeated to provide fallbacks. Defaults to --host')
    parser.add_argument('--ping-rate', type=float, default=1,
                        help='Rate of network monitoring ping in packet/s. If 0, disable the network monitoring.')
    parser.add_argument('-c', '--config', type=str,
                        help='Config file, in INI style. All CLI options are also available as keys under a [vpn] section.')
    parser.add_argument('-s', '--stdin', type=str,
                        help="String to pass to action's stdin")
    parser.add_argument('-d', '--device-id', type=str,
                        help="Hex device ID")
    parser.add_argument('-f', '--enable-funk', action='store_true',
                        help="Request funk message")
    parser.add_argument('-H', '--hostname', type=str,
                        help="Hostname to pass with funk request")
    parser.add_argument('-p', '--platform', type=str,
                        help="Platform type to pass with funk request")
    parser.add_argument('-a', '--hwaddr', type=str,
                        help="Comma separated list of hwaddrs to pass with funk request")
    parser.add_argument('-C', '--certs', type=str,
                        help="Comma separated list of pem formatted certificates for funk response")
    parser.add_argument('-U', '--user-agent', type=str,
                        help="User agent string")
    parser.add_argument('action', nargs=argparse.REMAINDER,
                        metavar='<action> [<args...>]',
                        help='External command')
    parser.add_argument('--verbose', action='store_true',
                        help="Increase verbosity")
    parser.add_argument('--help', action='help',
                        help="Show help")
    args = parser.parse_args()

    # Load the conf file and use it as defaults, so it can be overridden by the
    # command line
    if args.config is not None:
        # Custom converters accessible as config.get<converter name>()
        converters = dict(
            shell_split=shlex.split,
            str=str.lower,
        )

        # Use the same canonical key name as ArgumentParser.set_defaults()
        def canonical_key(key):
            return key.lower().replace('-', '_')

        key_types = defaultdict(
            # default
            lambda: 'str',

            action='shell_split',
            verbose='boolean',
            enable_funk='boolean',

            ping_host='shell_split',
            ping_rate='float',
            connect_timeout='float',
        )

        # interpolation=None avoids interpolating things like %DSID%
        config = configparser.ConfigParser(
            interpolation=None,
            converters=converters
        )
        config.optionxform = canonical_key
        config.read(args.config)
        vpn_config = config['vpn']

        def parse(arg):
            getter = 'get{}'.format(key_types[arg])
            getter = getattr(vpn_config, getter)
            return getter(arg)

        parsed_conf = {
            arg: parse(arg)
            for arg in vpn_config
        }

        conf_action = parsed_conf.get('action')

        # Update default with conf content and reparse, so that the CLI can
        # override the conf settings
        parser.set_defaults(**parsed_conf)
        args = parser.parse_args()

        # Even with a default, argparse.REMAINDER will give an empty list so we
        # need to explicitly take the one from the conf:
        # https://bugs.python.org/issue35495
        if conf_action and not args.action:
            args.action = conf_action

    # DO NOT USE args BEFORE THIS POINT, otherwise the conf file will be
    # ignored
    args.password = None
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    # Default to trying the VPN server, followed by Google's DNS server as a
    # fallback in case a proxy setup is used, potentially preventing pinging
    # the VPN server name.
    args.ping_host = args.ping_host or [args.host, '8.8.8.8']

    if args.action and args.action[0] == '--':
        args.action = args.action[1:]

    if args.host is None or not args.action:
        parser.error("--host and <action> are required parameters")

    jvpn = JuniperVPN(args, verbose=args.verbose)
    try:
        jvpn.run()
    # ctrl-C need not a backtrace to be displayed.
    except KeyboardInterrupt:
        logging.info('User interrupt, stopping the VPN')
    # Errors raised by JuniperVPN() actions
    except ActionError as e:
        logging.error(e.msg)
        sys.exit(e.exit_code)
    finally:
        jvpn.stop()
