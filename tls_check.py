#!/bin/env python3
'''
This module checks for changed tls certificates and for
certificates about to expire.
'''
# Author: José Fardello <jmfardello@gmail.com>
# based on  ssl_expiry by: Lucas Roelser <roesler.lucas@gmail.com>

import datetime
import fileinput
import logging
import os
import sys
import socket
import ssl
import time
import hashlib

SYNERR = 2
ERRSTAT = 1
OKSTAT = 0
LOGGER = logging.getLogger('TLSCheck')

class TLSCheckError(Exception):
    '''Custom TLS error to catch changed thimbprints numbers.'''

def ssl_expiry_datetime(hostname):
    '''Get expire date and thumbprint for a given host.'''
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

    if ":" in hostname:
        hostname, port = hostname.split(":")
        port = int(port)
    else:
        port = 443
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    # 3 second timeout because Lambda has runtime limitations
    conn.settimeout(3.0)

    LOGGER.debug('Connect to %s', hostname)
    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()
    der_cert_bin = conn.getpeercert(True)
    thumb_sha256 = hashlib.sha256(der_cert_bin).hexdigest()
    # parse the string from the certificate into a Python datetime object
    return (datetime.datetime.strptime(ssl_info['notAfter'],
                                       ssl_date_fmt), thumb_sha256)


def ssl_valid_time_remaining(hostname):
    '''Get the deltsa days left in a cert's lifetime and the thumbprint.'''
    expires, thumb = ssl_expiry_datetime(hostname)
    LOGGER.debug("SSL cert for %s expires at %s", hostname, expires.isoformat())
    return (expires - datetime.datetime.utcnow(), thumb)


def test_host(hostname, thumbs, buffer_days=30):
    """Return test message and status for hostname cert expiration."""
    try:
        will_expire_in, _thumb = ssl_valid_time_remaining(hostname)
        if _thumb not in thumbs:
            raise TLSCheckError("%s not included in %s" % (_thumb, thumbs))
    except ssl.CertificateError as exc:
        return f'{hostname} cert error {exc}', ERRSTAT
    except ssl.SSLError as exc:
        return f'{hostname} cert error {exc}', ERRSTAT
    except socket.timeout as exc:
        return f'{hostname} could not connect', ERRSTAT
    if will_expire_in < datetime.timedelta(days=0):
        return f'{hostname} cert will expire', ERRSTAT
    if will_expire_in < datetime.timedelta(days=buffer_days):
        return f'{hostname} cert will expire in {will_expire_in}', ERRSTAT
    return f'{hostname} cert is fine', OKSTAT


def main():
    '''Main function'''
    loglevel = os.environ.get('LOGLEVEL', 'INFO')
    max_days = os.environ.get('CHECK_DAYS', 10)
    try:
        max_days = int(max_days)
    except ValueError:
        LOGGER.error("Not a numeric value for 'CHECK_DAYS'.")
        sys.exit(SYNERR)
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    logging.basicConfig(level=numeric_level)

    start = time.time()
    status = OKSTAT
    for line in fileinput.input():
        host, thumbs = line.split(maxsplit=1)
        thumbs = thumbs.split()
        LOGGER.debug('Testing host %s', host)
        try:
            message, _status = test_host(host, thumbs)
            LOGGER.info(message)
            status = status | _status
        except TLSCheckError as err:
            LOGGER.error(err.args[0])
            status = ERRSTAT

    LOGGER.debug('Time: %s', time.time() - start)
    sys.exit(status)


if __name__ == '__main__':
    main()
