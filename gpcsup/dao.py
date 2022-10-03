import rfc3339

from elasticsearch.exceptions import NotFoundError
from elasticsearch_dsl import Search


SITE_SORTABLE_FIELDS = {
    'domain': 'domain.keyword',
    '-domain': '-domain.keyword',
    'rank': 'domain_rank.rank',
    '-rank': '-domain_rank.rank',
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

    def __init__(self, es_client, report_index, site_index, resource_index):
        self.es_client = es_client
        self.report_index = report_index
        self.site_index = site_index
        self.resource_index = resource_index

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
             source=None, count=False, timeout=30,
             **filter_params):

        s = Search(using=self.es_client, index=self.resource_index)
        s = s.filter('term', **{'resource.keyword': 'gpc'})

        s = apply_filters(s, **filter_params)

        sort = build_sort(sort)
        if sort:
            s = s.sort(*sort)

        s = s[offset:offset + limit]

        if source:
            s = s.source(source)

        s = s.params(request_timeout=timeout)

        if count:
            s = s.extra(track_total_hits=count)

        response = s.execute()

        sites = [(r.to_dict(), r.meta.score) for r in response]

        return response.hits.total.value, sites

    def count_scanned(self, timeout=30):

        s = Search(using=self.es_client, index=self.site_index)
        s = s.filter('term', **{'results.resource.keyword': 'gpc'})

        # Only count completed scans.
        s = s.filter('term', **{'status.keyword': 'scanned'})
        # Only count base domains.
        s = s.filter('term', **{'is_base_domain': True})

        # Don't need any actual results - just the count.
        s = s[0:0]
        s = s.extra(track_total_hits=True)
        s = s.params(request_timeout=timeout)

        response = s.execute()

        return response.hits.total.value

    def count_reporting(self, timeout=30):

        s = Search(using=self.es_client, index=self.resource_index)
        s = s.filter('term', **{'resource.keyword': 'gpc'})

        # Only count completed scans.
        s = s.filter('terms', **{'status.keyword': ['ok', 'failed']})
        # Only count base domains.
        s = s.filter('term', **{'is_base_domain': True})
        # Only count sites that report whether they support GPC.
        s = s.filter('term', **{'scan_data.found': True})

        # Don't need any actual results - just the count.
        s = s[0:0]
        s = s.extra(track_total_hits=True)
        s = s.params(request_timeout=timeout)

        s.aggs.bucket('supported', 'filter', term={'scan_data.gpc.parsed.gpc': True})

        response = s.execute()

        supported = response.aggregations.supported.doc_count
        unsupported = response.hits.total.value - supported
        return supported, unsupported

    def create_report(self, report_dt, supported, unsupported, scanned, tweeting,
                      timeout=30, wait_for=False):
        report_dts = rfc3339.datetimetostr(report_dt)
        report_doc = {
            'report_dt': report_dts,
            'supported': supported,
            'unsupported': unsupported,
            'found': supported + unsupported,
            'scanned': scanned,
            'twitter_bot': {
                'tweeting': bool(tweeting),
                'tweeted': False
            }
        }
        self.es_client.create(index=self.report_index, id=report_dts,
                              body=report_doc, request_timeout=timeout,
                              refresh='wait_for' if wait_for else 'false')

    def find_last_report(self, timeout=30):

        s = Search(using=self.es_client, index=self.report_index)

        s = s.sort('-report_dt')
        s = s[:1]
        s = s.params(request_timeout=timeout)

        try:
            response = s.execute()
        except NotFoundError:
            return None

        reports = [r.to_dict() for r in response]

        return reports[0] if reports else None

    def set_tweeted(self, report_dt, tweet_id, timeout=30, wait_for=False):
        report_dts = rfc3339.datetimetostr(report_dt)
        now_dts = get_now_dts()
        body = {
            'script': {
                'source': (
                    'ctx._source.twitter_bot.tweeted = true;'
                    'ctx._source.twitter_bot.tweet_id = params.tweet_id;'
                    'ctx._source.twitter_bot.tweet_dt = params.tweet_dt;'
                ),
                'lang': 'painless',
                'params': {
                    'tweet_id': tweet_id,
                    'tweet_dt': now_dts
                }
            }
        }
        self.es_client.update(index=self.report_index, id=report_dts,
                              body=body, request_timeout=timeout,
                              refresh='wait_for' if wait_for else 'false')
