import functools
import gevent
import idna
import logging
import re
import requests
import rfc3339
import time

from bottle import Bottle, request, response, static_file, template, redirect
from datetime import timedelta
from publicsuffixlist import PublicSuffixList
from requests_oauthlib import OAuth1
from urllib.parse import urlsplit

from utils.param_parse import ParamParseError, parse_params, string_param, boolean_param

from .misc import html_default_error_hander, security_headers, set_headers


log = logging.getLogger(__name__)

# Disable some logging to reduce log spam.
# Elasticsearch logs all requests at (at least) INFO level.
logging.getLogger('elasticsearch').setLevel(logging.WARNING)

PSL_CACHE_SIZE = 10_000
psl = PublicSuffixList()

# Domains are a series of two or more names, separated by periods, with an optional trailing period.
# (Technically one name is allowed, but TLDs aren't usually HTTP sites.)
# (Note that we actually strip any trailing period during normalization - along with lowercasing
#  characters - but support has been left in the regex for completeness.)
# Each name can contain latin characters (case insensitive), digits, or dashes.
# Names can't be longer than 63 characters, or start/end with a dash.
# The final name - the TLD - can't be numeric (only digits).
DOMAIN_REGEX = re.compile(r'^(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+(?!\d+\.?$)[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.?$')
DOMAIN_MAX_LENGTH = 253

REQUEST_TIMEOUT_INDIVIDUAL = 5

SCAN_START_TIMEOUT = 20
SCAN_TIMEOUT = 30
SCAN_AGENT = 'GpcSupBot'
SCAN_HEADERS = {'User-Agent': f'{SCAN_AGENT}/0.1 (https://gpcsup.com)'}
ROBOTS_MAX_CONTENT_LENGTH = 512 * 1024  # 512kB
GPC_PATH = '/.well-known/gpc.json'
GPC_MAX_CONTENT_LENGTH = 1024  # 1kB

SCAN_TTL = timedelta(minutes=10)
NEXT_SCAN_OFFSET = timedelta(days=7)
SCAN_FAIL_OFFSETS = [
    timedelta(days=1),
    timedelta(days=7),
    timedelta(days=30),
]

SCAN_RESULT_MAX_AGE_SECS = SCAN_TTL.seconds
SCAN_RESULT_HEADERS = {'Cache-Control': f'max-age={SCAN_RESULT_MAX_AGE_SECS}'}

STATIC_FILE_MAX_AGE_SECS = timedelta(hours=1).seconds
STATIC_FILE_HEADERS = {'Cache-Control': f'max-age={STATIC_FILE_MAX_AGE_SECS}'}

SITES_PAGE_SIZE = 8

SERVER_READY = True


class ScanError(Exception):
    """The scan has failed, and the user should be shown the specified template."""

    def __init__(self, template, **kwargs):
        self.template = template
        self.kwargs = kwargs


@functools.lru_cache(maxsize=PSL_CACHE_SIZE)
def extract_base_domain(domain, return_unknown=True):
    base_domain = psl.privatesuffix(domain)
    # If return_unknown is set, return the domain if its eTLD isn't known.
    if base_domain is None and return_unknown:
        base_domain = domain
    return base_domain


def domain_is_www_subdomain(domain):
    base_domain = extract_base_domain(domain)
    return domain == f'www.{base_domain}'


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


def extract_domain_from_url(url):
    split_url = urlsplit(url)
    domain = split_url.netloc
    if ':' in domain:
        domain = domain.split(':', 1)[0]

    return normalise_domain(domain)


def construct_app(es_dao,
                  service_protocol, service_hostname,
                  service_port, service_path,
                  well_known_service, testing_mode,
                  **kwargs):

    app = Bottle()
    app.default_error_handler = html_default_error_hander

    app.install(security_headers)

    service_address = f'{service_protocol}://{service_hostname}'
    if service_port:
        service_address += f':{service_port}'
    if service_path:
        service_address += service_path

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

    @app.get('/<filename>.js')
    def root_js(filename):
        return static_file(f'{filename}.js', root='static', headers=STATIC_FILE_HEADERS.copy())

    @app.get('/.well-known/gpc.json')
    def global_privacy_control():
        return {'gpc': True, 'lastUpdate': '2021-07-17'}

    @app.get('/sitemap.xml')
    def sitemap():

        total, results = es_dao.find(supports_gpc=True, is_base_domain=True,
                                     sort=['rank', 'domain'], limit=1000, source=['domain'])
        domains = [result[0]['domain'] for result in results]

        for header, value in STATIC_FILE_HEADERS.items():
            response.set_header(header, value)
        response.set_header('Content-Type', 'text/xml')
        return template('sitemap', service_address=service_address, domains=domains)

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

        scanned_count_gl = gevent.spawn(es_dao.count_scanned, timeout=30)
        reporting_count_gl = gevent.spawn(es_dao.count_reporting, timeout=30)

        gevent.joinall([scanned_count_gl, reporting_count_gl], timeout=30)
        scanned_count = scanned_count_gl.get()
        supporting_count, _ = reporting_count_gl.get()

        well_known_search = f'{well_known_service}/?q=resource%3Agpc+gpc_support%3Atrue+is_base_domain%3Atrue#results'

        r = template('index', domain=domain,
                     scanned_count=scanned_count,
                     supporting_count=supporting_count,
                     well_known_search=well_known_search)
        set_headers(r, STATIC_FILE_HEADERS)
        return r

    @app.post('/')
    def check_site():
        try:
            params = parse_params(request.forms.decode(),
                                  domain=string_param('domain', required=True, strip=True,
                                                      min_length=1, max_length=DOMAIN_MAX_LENGTH),
                                  no_rescan=boolean_param('no_rescan', default=False, empty=True,
                                                          strip=True))
        except ParamParseError:
            return template('gpc_invalid', domain=None)

        domain = normalise_domain(params['domain'])
        if not check_domain(domain):
            return template('gpc_invalid', domain=domain)

        result = es_dao.get(domain)
        if result is not None:
            if params['no_rescan'] or result['status'] == 'pending':
                redirect(f'/sites/{domain}')

            # Non-pending scans should have a scan datetime.
            last_scan_dt = rfc3339.parse_datetime(result['last_scan_dt'])
            # If the last scan hasn't expired yet, don't rescan.
            if rfc3339.now() < last_scan_dt + SCAN_TTL:
                if testing_mode:
                    log.info('Would have redirected to existing scan for %(domain)s if on prod.',
                             {'domain': domain})
                else:
                    redirect(f'/sites/{domain}')

        r = requests.post(well_known_service + '/sites/', data={'domain': domain, 'rescan': 'true'})
        r.raise_for_status()

        redirect(f'/sites/{domain}')

    @app.get('/sites/<domain>')
    def get_site(domain):
        domain = normalise_domain(domain)
        if not check_domain(domain):
            return template('gpc_invalid', domain=domain)

        # Well-Known doesn't scan www subdomains - redirect to the base domain instead.
        if domain_is_www_subdomain(domain):
            base_domain = extract_base_domain(domain)
            redirect(f'/sites/{base_domain}')

        result = es_dao.get(domain)
        if result is None:
            redirect(f'/?domain={domain}')

        status = result['status']
        scan_data = result.get('scan_data')
        if status == 'pending':
            return template('gpc_pending', domain=domain)
        elif status == 'blocked':
            return template('gpc_blocked', domain=domain)
        elif status == 'failed' and not scan_data:
            return template('gpc_error', domain=domain)

        # Status should be `ok`, or `failed` but with a previously successful scan.
        # In either case, `scan_data` should be present.
        assert scan_data

        scheme = scan_data['scheme']

        scan_dt = rfc3339.parse_datetime(scan_data['scan_dt'])

        if result['scan_priority'] == 0:
            rescan_queued = True
            can_rescan = False
        else:
            rescan_queued = False
            last_scan_dt = rfc3339.parse_datetime(result['last_scan_dt'])
            can_rescan = (last_scan_dt + SCAN_TTL) < rfc3339.now()

        error = scan_data.get('error')
        if error:
            message = None
            if error == 'not-found':
                message = 'The GPC support resource was not found.'
            elif error in ('unexpected-scheme-redirect', 'unexpected-status',
                           'client-error', 'server-error', 'unexpected-status'):
                message = 'Server responded unexpectedly when fetching the GPC support resource.'
            elif error in ('parse-error', 'json-parse-error', 'unexpected-json-root-type',
                           'content-too-long', 'content-length-too-long', 'bad-content'):
                message = 'The GPC support resource is invalid.'
            elif error:
                log.error('Unsupported GPC scan error %(error)s', {'error': error})

            r = template('gpc_unknown', scheme=scheme, domain=domain,
                         message=message, scan_dt=scan_dt,
                         rescan_queued=rescan_queued, can_rescan=can_rescan)
            set_headers(r, SCAN_RESULT_HEADERS)
            return r

        else:
            assert scan_data['found'], 'gpc.json should have been found if no error.'
            gpc_data = scan_data['gpc']

            warnings = scan_data.get('warnings') or []
            warnings += gpc_data.get('warning_codes') or []
            message = None
            if warnings:
                message_parts = []
                for warning in warnings:
                    if warning == 'wrong-content-type':
                        message_parts.append('incorrect content type')
                    elif warning == 'invalid-update-field':
                        message_parts.append('invalid last update field')

                if message_parts:
                    message = ' and '.join(message_parts) + '.'

            last_update = gpc_data['parsed'].get('lastUpdate')
            template_name = 'gpc_supported' if gpc_data['parsed']['gpc'] else 'gpc_unsupported'
            r = template(template_name, scheme=scheme, domain=domain,
                         last_update=last_update, message=message, scan_dt=scan_dt,
                         rescan_queued=rescan_queued, can_rescan=can_rescan)
            set_headers(r, SCAN_RESULT_HEADERS)
            return r

    return app


def run_report(es_dao,
               twitter_consumer_key, twitter_consumer_secret,
               twitter_token_key, twitter_token_secret,
               well_known_service, testing_mode, **kwargs):

    oauth = OAuth1(client_key=twitter_consumer_key,
                   client_secret=twitter_consumer_secret,
                   resource_owner_key=twitter_token_key,
                   resource_owner_secret=twitter_token_secret)

    well_known_search = f'{well_known_service}/?q=resource%3Agpc+gpc_support%3Atrue+is_base_domain%3Atrue#results'

    report_dt = rfc3339.now()

    last_report = es_dao.find_last_report()

    if last_report:
        last_report_dt = rfc3339.parse_datetime(last_report['report_dt'])
        if report_dt - last_report_dt < timedelta(hours=16):
            log.warning('Last report less than 16 hours ago: %(last_report_dt)s',
                        {'last_report_dt': rfc3339.datetimetostr(last_report_dt)})
            return False

    supported, unsupported = es_dao.count_reporting()
    scanned = es_dao.count_scanned()

    tweeting = bool(supported or unsupported)

    if last_report:

        if supported == last_report['supported'] and \
           unsupported == last_report['unsupported'] and \
           scanned == last_report['scanned']:
            # Don't tweet if nothing has changed since the last report.
            tweeting = False
            log.warning('No change in stats since last report: '
                        '%(supported_count)d:%(unsupported_count)d/%(scanned_count)d',
                        {'supported_count': supported,
                         'unsupported_count': unsupported,
                         'scanned_count': scanned})

        if last_report['twitter_bot']['tweeting'] and not last_report['twitter_bot']['tweeted']:
            log.warning('Last report wasn\'t tweeted: %(last_report_dt)s',
                        {'last_report_dt': rfc3339.datetimetostr(last_report_dt)})

    tweet = None
    if tweeting:
        tweet_lines = []

        if supported:
            tweet_line = f'{supported:,d} sites report they support #GPC'
            if last_report:
                last_supported = last_report['supported']
                supported_change = supported - last_supported
                if last_supported > 0:
                    supported_change_percent = abs(supported_change / last_supported) * 100
                    if supported_change > 0:
                        tweet_line += f' (+{supported_change_percent:.3g}%)'
                    elif supported_change < 0:
                        tweet_line += f' (-{supported_change_percent:.3g}%)'
            tweet_line += '.'
            tweet_lines.append(tweet_line)

        if unsupported:
            tweet_line = f'{unsupported:,d} sites report they don\'t support #GPC'
            if last_report:
                last_unsupported = last_report['unsupported']
                unsupported_change = unsupported - last_unsupported
                if last_unsupported > 0:
                    unsupported_change_percent = abs(unsupported_change / last_unsupported) * 100
                    if unsupported_change > 0:
                        tweet_line += f' (+{unsupported_change_percent:.3g}%)'
                    elif unsupported_change < 0:
                        tweet_line += f' (-{unsupported_change_percent:.3g}%)'
            tweet_line += '.'
            tweet_lines.append(tweet_line)

        # Only report number of sites scanned if some reporting sites were found.
        if scanned and (supported or unsupported):
            tweet_line = f'{scanned:,d} sites scanned'
            if last_report:
                last_scanned = last_report['scanned']
                scanned_change = scanned - last_scanned
                if last_scanned > 0:
                    scanned_change_percent = abs(scanned_change / last_scanned) * 100
                    if scanned_change > 0:
                        tweet_line += f' (+{scanned_change_percent:.3g}%)'
                    elif scanned_change < 0:
                        tweet_line += f' (-{scanned_change_percent:.3g}%)'
            tweet_line += '.'
            tweet_lines.append(tweet_line)

        if supported:
            tweet_lines.append(well_known_search)

        tweet = '\n'.join(tweet_lines)

    if testing_mode:
        if tweeting:
            log.info('Would tweet:\n%(tweet)s', {'tweet': tweet})
    else:
        es_dao.create_report(report_dt, supported, unsupported, scanned,
                             tweeting=tweeting, wait_for=True)

        if tweeting:
            r = requests.post('https://api.twitter.com/2/tweets',
                              json={'text': tweet},
                              auth=oauth)
            r.raise_for_status()

            r_json = r.json()
            tweet_id = r_json['data']['id']

            log.info('Tweeted report %(report_dt)s. Tweet ID: `%(tweet_id)s`',
                     {'report_dt': rfc3339.datetimetostr(report_dt),
                      'tweet_id': tweet_id,
                      'full_response': r_json})

            es_dao.set_tweeted(report_dt, tweet_id, wait_for=True)

    return True
