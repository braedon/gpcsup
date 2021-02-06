import gevent
import idna
import logging
import re
import reppy
import requests
import rfc3339
import sys
import time
import urllib3

from bottle import Bottle, request, response, static_file, template, redirect
from datetime import timedelta
from reppy.robots import Robots
from requests_oauthlib import OAuth1
from urllib.parse import urlsplit

from utils.param_parse import ParamParseError, parse_params, integer_param, string_param

from .misc import html_default_error_hander, security_headers, set_headers


log = logging.getLogger(__name__)

# Domains are a series of one or more names, separated by periods, with an optional trailing period.
# (Note that we actually strip any trailing period during normalization - along with lowercasing
#  characters - but support has been left in the regex for completeness.)
# Each name can contain latin characters (case insensitive), digits, or dashes.
# Names can't be longer than 63 characters, or start/end with a dash.
# The final name - the TLD - can't be numeric (only digits).
DOMAIN_REGEX = re.compile(r'^(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)*(?!\d+\.?$)[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.?$')
DOMAIN_MAX_LENGTH = 253

REQUEST_TIMEOUT_INDIVIDUAL = 10
REQUEST_TIMEOUT_OVERALL = 30
BOT_AGENT = 'GpcSupBot'
HEADERS = {'User-Agent': f'{BOT_AGENT}/0.1 (https://gpcsup.com)'}
GPC_PATH = '/.well-known/gpc.json'

SCAN_TTL = timedelta(minutes=10)

SCAN_RESULT_MAX_AGE_SECS = SCAN_TTL.seconds
SCAN_RESULT_HEADERS = {'Cache-Control': f'max-age={SCAN_RESULT_MAX_AGE_SECS}'}

STATIC_FILE_MAX_AGE_SECS = timedelta(hours=1).seconds
STATIC_FILE_HEADERS = {'Cache-Control': f'max-age={STATIC_FILE_MAX_AGE_SECS}'}

SITES_PAGE_SIZE = 10

SERVER_READY = True


class ScanError(Exception):
    """Indicates the user should be shown the login page"""

    def __init__(self, template):
        self.template = template


def normalise_domain(domain):
    domain = domain.lower()

    # Handle users copying domains with the scheme attached.
    # Only allow these two schemes - GPC is for HTTP(s).
    if domain.startswith('https://'):
        domain = domain[8:]
    elif domain.startswith('http://'):
        domain = domain[7:]

    # Similar to handling schemes, handle one slash at the end of the domain.
    if domain.endswith('/'):
        domain = domain[:-1]

    # Strip any optional trailing period from the domain.
    if domain.endswith('.'):
        domain = domain[:-1]

    try:
        # Convert to and from IDNA encoding with compatibility mapping enabled to normalise.
        domain = idna.decode(idna.encode(domain, uts46=True))
    except idna.IDNAError:
        # Ignore IDNA errors and return the domain without IDNA normalisation.
        # Any IDNA error will cause check_domain() to fail anyway.
        pass

    return domain


def check_domain(domain):
    try:
        # Convert domains to IDNA format before checking length and format.
        idna_domain = idna.encode(domain).decode('ASCII')
    except idna.IDNAError as e:
        log.warning('IDNA error when checking %(domain)s: %(error)s',
                    {'domain': domain, 'error': e})
        return False

    if len(idna_domain) > DOMAIN_MAX_LENGTH:
        return False

    match = DOMAIN_REGEX.fullmatch(idna_domain)
    if match is None:
        return False

    return True


def scan_gpc(domain):
    url = f'https://{domain}{GPC_PATH}'

    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT_INDIVIDUAL)

    # UnicodeError can be raised if the server redirects incorrectly, e.g.
    # https://quickconnect.to/.well-known/gpc.json redirects to
    # https://.well-known.quickconnect.to/https_first/gpc.json, which has an empty first label in
    # the domain, causing the exception.
    except (requests.exceptions.RequestException, UnicodeError) as e:
        log.warning('Error when fetching gpc.json for %(domain)s: %(error)s',
                    {'domain': domain, 'error': e})
        raise ScanError('gpc_error')

    data = {
        'url': resp.url,
        'status_code': resp.status_code,
        'supports_gpc': False,
        'warnings': [],
    }

    if resp.history:
        data['redirects'] = [
            {
                'url': r.url,
                'status_code': r.status_code,
                'location': r.headers.get('Location'),
            }
            for r in resp.history
        ]

    if resp.url != url:
        data['redirect_url'] = resp.url

        resp_split_url = urlsplit(resp.url)

        if resp_split_url.scheme not in ('http', 'https'):
            data['error'] = 'unexpected-scheme-redirect'
            return data

        if resp_split_url.scheme != 'https':
            data['warnings'].append('scheme-redirect')

        resp_domain = resp_split_url.netloc
        if ':' in resp_domain:
            resp_domain = resp_domain.split(':', 1)[0]

        if resp_domain != domain:
            data['redirect_domain'] = resp_domain

            if resp_domain.startswith('www.') and resp_domain[4:] == domain:
                data['www_redirect'] = 'added'
            elif domain.startswith('www.') and domain[4:] == resp_domain:
                data['www_redirect'] = 'removed'
            else:
                data['warnings'].append('domain-redirect')

        if resp_split_url.path != GPC_PATH:
            data['warnings'].append('path-redirect')

    if resp.status_code == 200:
        pass
    elif resp.status_code == 404:
        data['error'] = 'not-found'
        return data
    elif 400 <= resp.status_code < 500:
        log.warning('Client error when fetching GPC support resource for %(domain)s: %(status_code)s',
                    {'domain': domain, 'status_code': resp.status_code})
        data['error'] = 'client-error'
        return data
    elif 500 <= resp.status_code < 600:
        log.warning('Server error when fetching GPC support resource for %(domain)s: %(status_code)s',
                    {'domain': domain, 'status_code': resp.status_code})
        data['error'] = 'server-error'
        return data
    else:
        log.warning('Unexpected status when fetching GPC support resource for %(domain)s: %(status_code)s',
                    {'domain': domain, 'status_code': resp.status_code})
        data['error'] = 'unexpected-status'
        return data

    content_type = resp.headers.get('Content-Type')
    data['content_type'] = content_type
    if content_type:
        content_type = content_type.strip()
        if ';' in content_type:
            content_type = content_type.split(';', 1)[0].strip()

    if content_type != 'application/json':
        data['warnings'].append('wrong-content-type')

    data['text'] = resp.text[:1000]

    try:
        resp_json = resp.json()
    except ValueError:
        data['error'] = 'parse-error'
        return data

    if not isinstance(resp_json, dict):
        data['error'] = 'not-json-object'
        return data

    if resp_json.get('version') != 1:
        data['warnings'].append('invalid-version-field')

    if 'gpc' not in resp_json or not isinstance(resp_json['gpc'], bool):
        data['error'] = 'invalid-gpc-field'
        return data

    data['supports_gpc'] = resp_json['gpc']

    return data


def scan_site(domain):
    try:
        robots = Robots.fetch(f'https://{domain}/robots.txt',
                              headers=HEADERS,
                              timeout=REQUEST_TIMEOUT_INDIVIDUAL)

        if not robots.allowed(GPC_PATH, BOT_AGENT):
            log.info('Scanning blocked by robots.txt for %(domain)s.',
                     {'domain': domain})
            raise ScanError('gpc_blocked')

    except (reppy.exceptions.ReppyException,
            urllib3.exceptions.HTTPError) as e:
        log.warning('Error when fetching robots.txt for %(domain)s: %(error)s',
                    {'domain': domain, 'error': e})

    return scan_gpc(domain)


def construct_app(es_dao, testing_mode, **kwargs):

    app = Bottle()
    app.default_error_handler = html_default_error_hander

    app.install(security_headers)

    @app.get('/-/live')
    def live():
        return 'Live'

    @app.get('/-/ready')
    def ready():
        if SERVER_READY:
            return 'Ready'
        else:
            response.status = 503
            return 'Unavailable'

    @app.get('/main.css')
    def css():
        return static_file('main.css', root='static', headers=STATIC_FILE_HEADERS.copy())

    # Set CORP to allow Firefox for Android to load icons.
    # Firefox for Android seems to consider the icon loader a different origin.
    #
    # Favicon stuff generated at:
    # https://favicon.io/favicon-generator/?t=gs&ff=Roboto Slab&fs=80&fc=%23fff&b=rounded&bc=%2300885D
    @app.get('/favicon.ico',
             sh_updates={'Cross-Origin-Resource-Policy': 'cross-origin'})
    def icon():
        return static_file('favicon.ico', root='static', headers=STATIC_FILE_HEADERS.copy())

    @app.get('/<filename>.png',
             sh_updates={'Cross-Origin-Resource-Policy': 'cross-origin'})
    def root_pngs(filename):
        return static_file(f'{filename}.png', root='static', headers=STATIC_FILE_HEADERS.copy())

    @app.get('/.well-known/gpc.json')
    def global_privacy_control():
        return {'gpc': True, 'version': 1}

    @app.get('/')
    def index():
        try:
            params = parse_params(request.query.decode(),
                                  domain=string_param('domain', strip=True,
                                                      min_length=1, max_length=DOMAIN_MAX_LENGTH))
            domain = params.get('domain')

        except ParamParseError:
            domain = None

        if domain:
            domain = normalise_domain(domain)
            if not check_domain(domain):
                domain = None

        r = template('index', domain=domain)
        set_headers(r, STATIC_FILE_HEADERS)
        return r

    @app.post('/')
    def check_site():
        try:
            params = parse_params(request.forms.decode(),
                                  domain=string_param('domain', required=True, strip=True,
                                                      min_length=1, max_length=DOMAIN_MAX_LENGTH))
        except ParamParseError:
            return template('gpc_invalid', domain=None)

        domain = normalise_domain(params['domain'])
        if not check_domain(domain):
            return template('gpc_invalid', domain=domain)

        site = es_dao.get(domain)
        if site is not None:
            update_dt = rfc3339.parse_datetime(site['update_dt'])
            # If the last scan hasn't expired yet, don't rescan.
            if rfc3339.now() < update_dt + SCAN_TTL:
                if testing_mode:
                    log.info('Would have redirected to existing scan for %(domain)s if on prod.',
                             {'domain': domain})
                else:
                    redirect(f'/sites/{domain}')

        try:
            # scan_site() makes multiple requests, each with their own timeouts.
            # The requests library doesn't always obey its timeout either -
            # e.g. https://crwdcntrl.net/ seems to take 5-6x the specified timeout.
            # Use gevent to add a limit to the overall time taken.
            scan_data = gevent.with_timeout(REQUEST_TIMEOUT_OVERALL, scan_site, domain)

        except ScanError as e:
            return template(e.template, domain=domain)

        except gevent.Timeout:
            return template('gpc_error', domain=domain)

        es_dao.upsert(domain, scan_data, timeout=REQUEST_TIMEOUT_INDIVIDUAL)

        redirect(f'/sites/{domain}')

    @app.get('/sites/')
    def get_sites():
        params = parse_params(request.params.decode(),
                              page=integer_param('page', default=0, positive=True))
        page = params['page']
        offset = page * SITES_PAGE_SIZE

        total, sites = es_dao.find(supports_gpc=True,
                                   sort=['id'], offset=offset, limit=SITES_PAGE_SIZE, timeout=30)
        domains = [site[0]['domain'] for site in sites]

        previous_page = page - 1 if page > 0 else None
        next_page = page + 1
        next_offset = next_page * SITES_PAGE_SIZE
        if next_offset >= total:
            next_page = None

        return template('sites', domains=domains, previous_page=previous_page, next_page=next_page)

    @app.get('/sites/<domain>')
    def get_site(domain):
        domain = normalise_domain(domain)
        if not check_domain(domain):
            return template('gpc_invalid', domain=domain)

        site = es_dao.get(domain)
        if site is None:
            redirect(f'/?domain={domain}')

        scan_data = site['scan_data']

        # If the site redirected to (or from) a www subdomain during the scan, show the user the
        # redirected domain instead of the original - presumably that's the one they should use.
        if scan_data.get('www_redirect'):
            domain = scan_data['redirect_domain']

        error = scan_data.get('error')
        if error:
            message = None
            if error == 'not-found':
                message = 'The GPC support resource was not found.'
            elif error in ('unexpected-scheme-redirect', 'client-error', 'server-error',
                           'unexpected-status'):
                message = 'Server responded unexpectedly when fetching the GPC support resource.'
            elif error in ('parse-error', 'not-json-object', 'invalid-gpc-field'):
                message = 'The GPC support resource is invalid.'
            elif error:
                log.error('Unsupported GPC scan error %(error)s', {'error': error})

            r = template('gpc_unknown', domain=domain, message=message)
            set_headers(r, SCAN_RESULT_HEADERS)
            return r

        else:
            warnings = scan_data.get('warnings')
            message = None
            if warnings:
                bad_fields = []
                for warning in warnings:
                    if warning == 'wrong-content-type':
                        bad_fields.append('content type')
                    elif warning == 'invalid-version-field':
                        bad_fields.append('version field')

                if bad_fields:
                    message = 'incorrect ' + ' and '.join(bad_fields) + '.'

            template_name = 'gpc_supported' if scan_data['supports_gpc'] else 'gpc_unsupported'
            r = template(template_name, domain=domain, message=message)
            set_headers(r, SCAN_RESULT_HEADERS)
            return r

    return app


def run_twitter_worker(es_dao,
                       twitter_consumer_key, twitter_consumer_secret,
                       twitter_token_key, twitter_token_secret,
                       **kwargs):

    oauth = OAuth1(client_key=twitter_consumer_key,
                   client_secret=twitter_consumer_secret,
                   resource_owner_key=twitter_token_key,
                   resource_owner_secret=twitter_token_secret)

    while True:
        domains = es_dao.find_tweetable()

        if domains:
            for domain in domains:
                es_dao.set_tweeting(domain, wait_for=True)

                tweet = f'{domain} is reporting that it supports #GPC'
                r = requests.post('https://api.twitter.com/1.1/statuses/update.json',
                                  data={'status': tweet},
                                  auth=oauth)
                r.raise_for_status()

                r_json = r.json()
                tweet_id = r_json['id_str']

                log.info('Tweeted about `%(domain)s` supporting GPC. Tweet ID: `%(tweet_id)s`',
                         {'domain': domain,
                          'tweet_id': tweet_id,
                          'full_response': r_json})

                es_dao.set_tweeted(domain, wait_for=True)

        else:
            time.sleep(60)


def run_scan(server, skip, **kwargs):
    count = 0
    try:
        for line in sys.stdin:

            # Skip empty lines
            line = line.strip()
            if not line:
                continue

            domain = normalise_domain(line)
            if not check_domain(domain):
                log.warning('Skipping invalid domain %(domain)s.',
                            {'domain': domain})
                continue

            if skip > 0:
                log.debug('Skipping domain %(domain)s.', {'domain': domain})
                skip -= 1
                continue

            log.debug('Scanning domain %(domain)s.', {'domain': domain})
            resp = requests.post(f'https://{server}', data={'domain': domain})

            if resp.status_code != 200:
                log.error('Unexpected status when scanning domain %(domain)s: %(status_code)s',
                          {'domain': domain, 'status_code': resp.status_code})
                break

            log.debug('Scanned domain %(domain)s.', {'domain': domain})
            count += 1

            if count % 10 == 0:
                log.info('Scanned %(count)s domains.', {'count': count})

    finally:
        log.info('Scanned %(count)s domains.', {'count': count})
