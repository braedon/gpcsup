import rfc3339

from elasticsearch.exceptions import NotFoundError
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
        search = search.filter(Q('range', **{field: date_range}))

    return search


def apply_filters(s, domain=None, query_string=None,
                  supports_gpc=None,
                  created_from=None, created_to=None,
                  updated_from=None, updated_to=None,
                  cursor_dt=None, cursor_id=None, cursor_sort=None):

    if domain is not None:
        s = s.filter(Q('ids', values=domain))

    if query_string is not None:
        s = s.query('simple_query_string',
                    query=query_string,
                    fields=['domain'])

    if supports_gpc is not None:
        s = s.filter(Q('term', **{'scan_data.supports_gpc': supports_gpc}))

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

    def upsert(self, domain, scan_data, timeout=30, wait_for=False):
        now_dts = get_now_dts()
        body = {
            # Full doc to insert if it doesn't exist.
            'upsert': {
                'domain': domain,
                'create_dt': now_dts,
                'update_dt': now_dts,
                'scan_data': scan_data,
                'history': [
                    {
                        'update_dt': now_dts,
                        'scan_data': scan_data,
                    }
                ]
            },
            # Scripted update if the doc already exists.
            'script': {
                'source': (
                    'ctx._source.update_dt = params.update_dt;'
                    'ctx._source.scan_data = params.scan_data;'
                    "ctx._source.history.add(["
                    '  \'update_dt\': params.update_dt,'
                    '  \'scan_data\': params.scan_data'
                    ']);'
                ),
                'lang': 'painless',
                'params': {
                    'update_dt': now_dts,
                    'scan_data': scan_data,
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
