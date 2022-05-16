import rfc3339

from elasticsearch_dsl import Search


SITE_SORTABLE_FIELDS = {
    'id': 'domain.keyword',
    '-id': '-domain.keyword',
}


def get_now_dts():
    # NOTE: rfc3339.now() doesn't give us fractional seconds. This is less precise, but using
    #       fractional seconds complicates specifying datetime ranges when searching.
    #       e.g. 23:59:59.001 is after 23:59:59, but before 00:00:00
    return rfc3339.datetimetostr(rfc3339.now())


def doc_id(domain):
    return f'{domain}:gpc'


def apply_filters(s, domain=None, supports_gpc=None,
                  status=None, found=None,
                  www_redirect=None, is_base_domain=None):

    if domain is not None:
        s = s.filter('terms', **{'domain.keyword': domain})

    if supports_gpc is not None:
        s = s.filter('term', **{'scan_data.gpc.parsed.gpc': supports_gpc})

    if status is not None:
        s = s.filter('terms', **{'status.keyword': status})

    if found is not None:
        s = s.filter('term', **{'scan_data.found': found})

    if www_redirect is not None:
        if www_redirect:
            s = s.filter('exists', field='scan_data.www_redirect')
        else:
            s = s.exclude('exists', field='scan_data.www_redirect')

    if is_base_domain is not None:
        s = s.filter('term', **{'is_base_domain': is_base_domain})

    return s


def build_sort(sort, dict_form=False):

    if sort:
        sort = [SITE_SORTABLE_FIELDS[f] for f in sort]

        if dict_form:
            sort = [{f[1:]: 'desc'} if f[0] == '-' else f for f in sort]

    return sort


class GpcSupDao(object):

    def __init__(self, es_client, site_index, resource_index):
        self.es_client = es_client
        self.site_index = site_index
        self.resource_index = resource_index

    def set_tweeting(self, domain, timeout=30, wait_for=False):
        body = {
            'script': {
                'source': (
                    'if (!ctx._source.containsKey("gpcsup")) {'
                    '  ctx._source.gpcsup = new HashMap();'
                    '}'
                    'ctx._source.gpcsup.tweeting = true;'
                    'ctx._source.gpcsup.tweeted = false;'
                    'ctx._source.gpcsup.tweet_dt = null;'
                ),
                'lang': 'painless'
            }
        }
        self.es_client.update(index=self.resource_index, id=doc_id(domain), body=body,
                              request_timeout=timeout, refresh='wait_for' if wait_for else 'false')

    def set_tweeted(self, domain, timeout=30, wait_for=False):
        now_dts = get_now_dts()
        body = {
            'script': {
                'source': (
                    'ctx._source.gpcsup.tweeted = true;'
                    'ctx._source.gpcsup.tweet_dt = params.tweet_dt;'
                ),
                'lang': 'painless',
                'params': {
                    'tweet_dt': now_dts
                }
            }
        }
        self.es_client.update(index=self.resource_index, id=doc_id(domain), body=body,
                              request_timeout=timeout, refresh='wait_for' if wait_for else 'false')

    def get(self, domain, timeout=30):

        site_resp = self.es_client.get(index=self.site_index, id=domain,
                                       request_timeout=timeout, ignore=404)
        if not site_resp['found']:
            return None

        site_doc = site_resp['_source']

        resource_resp = self.es_client.get(index=self.resource_index, id=doc_id(domain),
                                           request_timeout=timeout, ignore=404)
        if resource_resp['found']:
            resource_doc = resource_resp['_source']

            # Don't need any site doc resource results.
            del site_doc['results']

        else:

            if site_doc['status'] == 'pending':
                # Initial scan is pending, so no resource results yet.
                # Don't return None as that indicates the site hasn't been scanned.
                # Callers should handle pending scans differently.
                resource_doc = {}

            else:
                # Scan has completed at least once, so extract last results.
                scan_results = {r['resource']: r for r in site_doc['results']}
                # GPC might not have been checked last scan in certain cases.
                # Treat as if the site hasn't been scanned.
                if 'gpc' not in scan_results:
                    return None
                # Not the full resource doc, but will do for our purposes.
                resource_doc = scan_results['gpc']

                # Drop results for other resources.
                del site_doc['results']

        return {**site_doc, **resource_doc}

    def find(self,
             sort=None, offset=0, limit=10,
             count=False, timeout=30, **filter_params):

        s = Search(using=self.es_client, index=self.resource_index)
        s = s.filter('term', **{'resource.keyword': 'gpc'})

        s = apply_filters(s, **filter_params)

        sort = build_sort(sort)
        if sort:
            s = s.sort(*sort)

        s = s[offset:offset + limit]

        s = s.params(request_timeout=timeout)

        if count:
            s = s.extra(track_total_hits=count)

        response = s.execute()

        sites = [(r.to_dict(), r.meta.score) for r in response]

        return response.hits.total.value, sites

    def count(self, timeout=30):

        s = Search(using=self.es_client, index=self.resource_index)
        s = s.filter('term', **{'resource.keyword': 'gpc'})

        # Only count completed scans.
        s = s.filter('terms', **{'status.keyword': ['ok', 'failed']})
        # Only count base domains.
        s = s.filter('term', **{'is_base_domain': True})

        # Don't need any actual results - just the count and aggregations.
        s = s[0:0]

        # Use aggregation to count subset that reports support.
        supporting_filters = [{'term': {'scan_data.found': True}},
                              {'term': {'scan_data.gpc.parsed.gpc': True}}]
        s.aggs.bucket('supporting', 'filter', bool={'filter': supporting_filters})

        s = s.extra(track_total_hits=True)
        s = s.params(request_timeout=timeout)

        response = s.execute()

        supporting_count = response.aggregations.supporting.doc_count

        return response.hits.total.value, supporting_count

    def find_tweetable(self, limit=10, timeout=30):

        s = Search(using=self.es_client, index=self.resource_index)
        s = s.filter('term', **{'resource.keyword': 'gpc'})

        # Only tweet about sites where the last scan succeded, a gpc.json was
        # found, and it indicates support for GPC.
        s = s.filter('term', **{'status.keyword': 'ok'})
        s = s.filter('term', **{'scan_data.found': True})
        s = s.filter('term', **{'scan_data.gpc.parsed.gpc': True})
        # Only tweet about base domains, not subdomains.
        s = s.filter('term', **{'is_base_domain': True})
        # Don't tweet about sites we're previously tweeted about (or may have).
        # We may have set `tweeting` and failed before we could set `tweeted`. In this case, it's
        # unclear if the tweet went out or not - needs to be checked manually.
        s = s.exclude('term', **{'gpcsup.tweeting': True})
        s = s.exclude('term', **{'gpcsup.tweeted': True})

        s = s.sort('update_dt')
        s = s[:limit]
        s = s.params(request_timeout=timeout)

        response = s.execute()

        return [r.domain for r in response]
