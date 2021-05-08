import requests
import textwrap

from bottle import HTTPResponse, response, template
from contextlib import contextmanager

from utils.security_headers import SecurityHeadersPlugin


@contextmanager
def relax_requests_ssl():
    default_ciphers = requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS
    requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':@SECLEVEL=1'
    try:
        yield
    finally:
        requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = default_ciphers


def indent(block, indent=2):
    """Indent a multi-line text block by a number of spaces"""
    return textwrap.indent(block.strip(), ' ' * indent)


def set_headers(r, headers):
    if isinstance(r, HTTPResponse):
        r.headers.update(headers)
    else:
        response.headers.update(headers)


csp_updates = {'img-src': "'self'",
               'style-src': "'self' https://necolas.github.io https://fonts.googleapis.com",
               'font-src': "https://fonts.gstatic.com",
               'script-src': "'self'",
               'form-action': "'self'"}
security_headers = SecurityHeadersPlugin(csp_updates=csp_updates)


@security_headers
def html_default_error_hander(res):
    if res.status_code == 404:
        body = template('error_404', error=res)
    else:
        body = template('error', error=res)

    return body
