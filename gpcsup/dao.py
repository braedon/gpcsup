import rfc3339

from elasticsearch_dsl import Search, Q


SITE_SORTABLE_FIELDS = {
    'id': 'domain.keyword',
    '-id': '-domain.keyword',
    'created': 'create_dt',
    '-created': '-create_dt',
    'updated': 'update_dt',
    '-updated': '-update_dt',
    'relevance': '_score',  # this is actually score descending
    '-relevance': '_score',  # for compatibility with clients, -_score isn't allowed
}


def get_now_dts():
    # NOTE: rfc3339.now() doesn't give us fractional seconds. This is less precise, but using
    #       fractional seconds complicates specifying datetime ranges when searching.
    #       e.g. 23:59:59.001 is after 23:59:59, but before 00:00:00
    return rfc3339.datetimetostr(rfc3339.now())


def set_date_range(field, search, date_from, date_to):
    date_range = {}

    if date_from:
        date_range['gte'] = rfc3339.datetimetostr(date_from)

    if date_to:
        date_range['lte'] = rfc3339.datetimetostr(date_to)

    if date_range:
        search = search.filter('range', **{field: date_range})

    return search


def apply_filters(s, domain=None, query_string=None,
                  supports_gpc=None, www_redirect=None,
                  created_from=None, created_to=None,
                  updated_from=None, updated_to=None,
                  cursor_dt=None, cursor_id=None, cursor_sort=None):

    if domain is not None:
        s = s.filter('ids', values=domain)

    if query_string is not None:
        s = s.query('simple_query_string',
                    query=query_string,
                    fields=['domain'])

    if supports_gpc is not None:
        s = s.filter('term', **{'scan_data.supports_gpc': supports_gpc})

    if www_redirect is not None:
        if www_redirect:
            s = s.filter('exists', field='scan_data.www_redirect')
        else:
            s = s.exclude('exists', field='scan_data.www_redirect')

    s = set_date_range('create_dt', s, created_from, created_to)

    s = set_date_range('update_dt', s, updated_from, updated_to)

    if cursor_dt is not None or cursor_id is not None:
        assert cursor_dt is not None and cursor_id is not None, \
            'cursor_dt and cursor_id must be specified together'

        cursor_dt_s = rfc3339.datetimetostr(cursor_dt)
        f_eq_dt = Q('term', **{'create_dt': cursor_dt_s})
        comparitor = 'lt' if cursor_sort == 'desc' else 'gt'
        f_lt_id = Q('range', **{'domain.keyword': {comparitor: cursor_id}})
        f_lt_dt = Q('range', **{'create_dt': {comparitor: cursor_dt_s}})

        # Filter to sites created at the cursor datetime with a ID lower than the cursor_id,
        # or created before the cursor datetime.
        s = s.filter((f_eq_dt & f_lt_id) | f_lt_dt)

    return s


def build_sort(sort, cursor_dt=None, cursor_id=None, cursor_sort=None, dict_form=False):

    # Override sort if using a cursor.
    if cursor_dt is not None and cursor_id is not None:
        sort = ['-created', '-id'] if cursor_sort == 'desc' else ['created', 'id']

    if sort:
        sort = [SITE_SORTABLE_FIELDS[f] for f in sort]

        if dict_form:
            sort = [{f[1:]: 'desc'} if f[0] == '-' else f for f in sort]

    return sort


class GpcSupDao(object):

    def __init__(self, es_client, scan_result_index):
        self.es_client = es_client
        self.scan_result_index = scan_result_index

    def upsert(self, domain, scan_data, next_scan_dt, timeout=30, wait_for=False):
        now_dts = get_now_dts()
        body = {
            # Full doc to insert if it doesn't exist.
            'upsert': {
                'domain': domain,
                'create_dt': now_dts,
                'update_dt': now_dts,
                'scan_fails': 0,
                'next_scan_dt': now_dts,
                'scan_data': scan_data,
                'history': [
                    {
                        'update_dt': now_dts,
                        'scan_data': scan_data,
                    }
                ],
                'tweeting': False,  # Have we started tweeting about this domain.
                'tweeted': False    # Have we finished tweeting about this domain.
            },
            # Scripted update if the doc already exists.
            'script': {
                'source': (
                    'ctx._source.update_dt = params.update_dt;'
                    'ctx._source.scan_fails = 0;'
                    'ctx._source.next_scan_dt = params.next_scan_dt;'
                    # Only add a history entry if this update changes whether the site supports GPC.
                    'if (ctx._source.scan_data.supports_gpc != params.scan_data.supports_gpc) {'
                    '  ctx._source.history.add(['
                    '    \'update_dt\': params.update_dt,'
                    '    \'scan_data\': params.scan_data'
                    '  ]);'
                    '}'
                    # Only update the current scan data after checking if we need to add a history
                    # entry - otherwise we wouldn't be able to check the old scan data.
                    'ctx._source.scan_data = params.scan_data;'
                ),
                'lang': 'painless',
                'params': {
                    'update_dt': now_dts,
                    'next_scan_dt': rfc3339.datetimetostr(next_scan_dt),
                    'scan_data': scan_data
                }
            }
        }
        self.es_client.update(index=self.scan_result_index, id=domain, body=body,
                              request_timeout=timeout, refresh='wait_for' if wait_for else 'false')

    def set_tweeting(self, domain, timeout=30, wait_for=False):
        body = {
            'script': {
                'source': (
                    'ctx._source.tweeting = true;'
                ),
                'lang': 'painless'
            }
        }
        self.es_client.update(index=self.scan_result_index, id=domain, body=body,
                              request_timeout=timeout, refresh='wait_for' if wait_for else 'false')

    def set_tweeted(self, domain, timeout=30, wait_for=False):
        now_dts = get_now_dts()
        body = {
            'script': {
                'source': (
                    'ctx._source.tweeted = true;'
                    'ctx._source.tweet_dt = params.tweet_dt;'
                ),
                'lang': 'painless',
                'params': {
                    'tweet_dt': now_dts
                }
            }
        }
        self.es_client.update(index=self.scan_result_index, id=domain, body=body,
                              request_timeout=timeout, refresh='wait_for' if wait_for else 'false')

    def set_scan_failed(self, domain, next_scan_dt, timeout=30, wait_for=False):
        body = {
            'script': {
                'source': (
                    'ctx._source.scan_fails += 1;'
                    'ctx._source.next_scan_dt = params.next_scan_dt;'
                ),
                'lang': 'painless',
                'params': {
                    'next_scan_dt': rfc3339.datetimetostr(next_scan_dt)
                }
            }
        }
        self.es_client.update(index=self.scan_result_index, id=domain, body=body,
                              request_timeout=timeout, refresh='wait_for' if wait_for else 'false')

    def get(self, domain, timeout=30):
        resp = self.es_client.get(index=self.scan_result_index, id=domain,
                                  request_timeout=timeout, ignore=404)
        if resp['found']:
            return resp['_source']
        else:
            return None

    def find(self,
             sort=None, offset=0, limit=10,
             timeout=30, **filter_params):

        s = Search(using=self.es_client, index=self.scan_result_index)

        s = apply_filters(s, **filter_params)

        sort = build_sort(sort,
                          cursor_dt=filter_params.get('cursor_dt'),
                          cursor_id=filter_params.get('cursor_id'),
                          cursor_sort=filter_params.get('cursor_sort'))
        if sort:
            s = s.sort(*sort)

        s = s[offset:offset + limit]

        s = s.params(request_timeout=timeout)

        response = s.execute()

        sites = [(r.to_dict(), r.meta.score) for r in response]

        return response.hits.total.value, sites

    def find_tweetable(self, limit=10, timeout=30):

        s = Search(using=self.es_client, index=self.scan_result_index)

        # Only tweet about sites that support GPC.
        s = s.filter('term', **{'scan_data.supports_gpc': True})
        # Don't tweet about sites that redirect from/to a www subdomain.
        # We should tweet about the version that is redirected to instead.
        s = s.exclude('exists', field='scan_data.www_redirect')
        # Don't tweet about sites we're previously tweeted about (or may have).
        # We may have set `tweeting` and failed before we could set `tweeted`. In this case, it's
        # unclear if the tweet went out or not - needs to be checked manually.
        s = s.exclude('term', **{'tweeting': True})
        s = s.exclude('term', **{'tweeted': True})

        s = s.sort('update_dt')
        s = s[:limit]
        s = s.params(request_timeout=timeout)

        response = s.execute()

        return [r.domain for r in response]

    def find_rescanable(self, limit=10, timeout=30):

        s = Search(using=self.es_client, index=self.scan_result_index)

        s = set_date_range('next_scan_dt', s, None, rfc3339.now())

        s = s.sort('next_scan_dt')
        s = s[:limit]
        s = s.params(request_timeout=timeout)

        response = s.execute()

        return [(r.domain, r.scan_fails) for r in response]
