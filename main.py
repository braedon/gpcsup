#!/usr/bin/python3
from gevent import monkey; monkey.patch_all()

import bottle
import click
import gevent
import logging
import time
import sys
import gpcsup

from elasticsearch import Elasticsearch
from gevent.pool import Pool

from utils import log_exceptions, nice_shutdown
from utils.logging import configure_logging, wsgi_log_middleware

from gpcsup import construct_app, run_twitter_worker, run_scan
from gpcsup.dao import GpcSupDao

CONTEXT_SETTINGS = {
    'help_option_names': ['-h', '--help']
}

log = logging.getLogger(__name__)

# Use an unbounded pool to track gevent greenlets so we can
# wait for them to finish on shutdown.
gevent_pool = Pool()


@click.group(context_settings=CONTEXT_SETTINGS)
def main():
    pass


@click.command()
@click.option('--es-node', '-e', default=['localhost'], multiple=True,
              help='Address of a node in a Elasticsearch cluster to use. '
                   'Specify multiple nodes by providing the option multiple times. '
                   'A port can be provided if non-standard (9200) e.g. es1:9999. '
                   '(default: localhost)')
@click.option('--es-scan-result-index', default='gpcsup-scan',
              help='Elasticsearch scan result index. (default=gpcsup-scan)')
@click.option('--port', '-p', default=8080,
              help='Port to serve on (default=8080).')
@click.option('--shutdown-sleep', default=10,
              help='How many seconds to sleep during graceful shutdown. (default=10)')
@click.option('--shutdown-wait', default=10,
              help='How many seconds to wait for active connections to close during graceful '
                   'shutdown (after sleeping). (default=10)')
@click.option('--testing-mode', default=False, is_flag=True,
              help='Change settings to simplify testing, e.g. ignore scan ttl.')
@click.option('--json', '-j', default=False, is_flag=True,
              help='Log in json.')
@click.option('--verbose', '-v', default=False, is_flag=True,
              help='Log debug messages.')
@log_exceptions(exit_on_exception=True)
def server(**options):

    def shutdown():
        gpcsup.SERVER_READY = False

        def wait():
            # Sleep for a few seconds to allow for race conditions between sending
            # the SIGTERM and load balancers stopping sending traffic here.
            log.info('Shutdown: Sleeping %(sleep_s)s seconds.',
                     {'sleep_s': options['shutdown_sleep']})
            time.sleep(options['shutdown_sleep'])

            log.info('Shutdown: Waiting up to %(wait_s)s seconds for connections to close.',
                     {'wait_s': options['shutdown_sleep']})
            gevent_pool.join(timeout=options['shutdown_wait'])

            log.info('Shutdown: Exiting.')
            sys.exit()

        # Run in greenlet, as we can't block in a signal hander.
        gevent.spawn(wait)

    configure_logging(json=options['json'], verbose=options['verbose'])

    es_client = Elasticsearch(options['es_node'], verify_certs=False)
    es_dao = GpcSupDao(es_client, options['es_scan_result_index'])

    app = construct_app(es_dao, **options)
    app = wsgi_log_middleware(app)

    with nice_shutdown(shutdown):
        bottle.run(app,
                   host='0.0.0.0', port=options['port'],
                   server='gevent', spawn=gevent_pool,
                   # Disable default request logging - we're using middleware
                   quiet=True, error_log=None)


@click.command()
@click.option('--twitter-consumer-key', required=True,
              help='Twitter consumer API key.')
@click.option('--twitter-consumer-secret', required=True,
              help='Twitter consumer API secret key.')
@click.option('--twitter-token-key', required=True,
              help='Twitter access token.')
@click.option('--twitter-token-secret', required=True,
              help='Twitter access token secret.')
@click.option('--es-node', '-e', default=['localhost'], multiple=True,
              help='Address of a node in a Elasticsearch cluster to use. '
                   'Specify multiple nodes by providing the option multiple times. '
                   'A port can be provided if non-standard (9200) e.g. es1:9999. '
                   '(default: localhost)')
@click.option('--es-scan-result-index', default='gpcsup-scan',
              help='Elasticsearch scan result index. (default=gpcsup-scan)')
@click.option('--json', '-j', default=False, is_flag=True,
              help='Log in json.')
@click.option('--verbose', '-v', default=False, is_flag=True,
              help='Log debug messages.')
@log_exceptions(exit_on_exception=True)
def twitter_worker(**options):

    configure_logging(json=options['json'], verbose=options['verbose'])

    es_client = Elasticsearch(options['es_node'], verify_certs=False)
    es_dao = GpcSupDao(es_client, options['es_scan_result_index'])

    with nice_shutdown():
        run_twitter_worker(es_dao, **options)


@click.command()
@click.option('--server', '-s', default='gpcsup.com',
              help='The domain of the GPC Sup instance to run checks on. '
                   '(default: gpcsup.com)')
@click.option('--skip', default=0,
              help='How many domains to skip from the start of the input (default=0).')
@click.option('--json', '-j', default=False, is_flag=True,
              help='Log in json.')
@click.option('--verbose', '-v', default=False, is_flag=True,
              help='Log debug messages.')
@log_exceptions(exit_on_exception=True)
def scan(**options):

    configure_logging(json=options['json'], verbose=options['verbose'])

    with nice_shutdown():
        run_scan(**options)


main.add_command(server)
main.add_command(twitter_worker)
main.add_command(scan)


if __name__ == '__main__':
    main(auto_envvar_prefix='SITE_SUP_OPT')
