#!/usr/bin/python
# -*- coding: utf-8 -*-

# thumbor imaging service
# https://github.com/globocom/thumbor/wiki

# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license
# Copyright (c) 2011 globo.com timehome@corp.globo.com

import sys
import logging
import logging.config

import os
import socket
import signal
import time
from os.path import expanduser, dirname

import tornado.ioloop
from tornado.httpserver import HTTPServer

from thumbor.console import get_server_parameters
from thumbor.config import Config
from thumbor.importer import Importer
from thumbor.context import Context
from thumbor.utils import which


def get_as_integer(value):
    try:
        return int(value)
    except ValueError:
        return None


def main(arguments=None):
    '''Runs thumbor server with the specified arguments.'''

    server_parameters = get_server_parameters(arguments)

    lookup_paths = [os.curdir,
                    expanduser('~'),
                    '/etc/',
                    dirname(__file__)]

    config = Config.load(server_parameters.config_path, conf_name='thumbor.conf', lookup_paths=lookup_paths)

    if (config.THUMBOR_LOG_CONFIG and config.THUMBOR_LOG_CONFIG != '') :
      logging.config.dictConfig(config.THUMBOR_LOG_CONFIG)
    else:
      logging.basicConfig(
          level=getattr(logging, server_parameters.log_level.upper()),
          format=config.THUMBOR_LOG_FORMAT,
          datefmt=config.THUMBOR_LOG_DATE_FORMAT,
          filename=server_parameters.log_file
      )

    importer = Importer(config)
    importer.import_modules()

    if importer.error_handler_class is not None:
        importer.error_handler = importer.error_handler_class(config)

    if server_parameters.security_key is None:
        server_parameters.security_key = config.SECURITY_KEY

    if not isinstance(server_parameters.security_key, basestring):
        raise RuntimeError(
            'No security key was found for this instance of thumbor. ' +
            'Please provide one using the conf file or a security key file.')

    if config.USE_GIFSICLE_ENGINE:
        server_parameters.gifsicle_path = which('gifsicle')
        if server_parameters.gifsicle_path is None:
            raise RuntimeError('If using USE_GIFSICLE_ENGINE configuration to True, the `gifsicle` binary must be in the PATH and must be an executable.')

    context = Context(
        server=server_parameters,
        config=config,
        importer=importer
    )


    application = importer.import_class(server_parameters.app_class)(context)

    server = HTTPServer(application)

    if context.server.fd is not None:
        fd_number = get_as_integer(context.server.fd)
        if fd_number is None:
            with open(context.server.fd, 'r') as sock:
                fd_number = sock.fileno()

        sock = socket.fromfd(fd_number,
                             socket.AF_INET | socket.AF_INET6,
                             socket.SOCK_STREAM)
        server.add_socket(sock)
    else:
        server.bind(context.server.port, context.server.ip)

    server.start(1)

    # Adapted from gist.github.com/mywaiting/4643396.  Note: This function is
    # only ever executed as a callback by the main IO loop.  Therefore all
    # calls to it are guaranteed to be serialized, so it doesn't have to be
    # either thread-safe or reentrant.
    global shutting_down
    shutting_down = False
    def shutdown():
        global shutting_down
        if shutting_down:
            return
        shutting_down = True
        logging.critical('Stopping server. No longer accepting connections')
        server.stop()
        logging.critical('Shutdown in at most %d seconds',
                         config.MAX_WAIT_BEFORE_SHUTDOWN)
        io_loop = tornado.ioloop.IOLoop.instance()
        deadline = time.time() + config.MAX_WAIT_BEFORE_SHUTDOWN
        def stop_loop():
            now = time.time()
            if now < deadline and (io_loop._callbacks or io_loop._timeouts):
                io_loop.add_timeout(min(now + 1, deadline), stop_loop)
            else:
                logging.critical('Stopping IO loop and exiting')
                io_loop.stop()
        stop_loop()

    def sig_handler(sig, frame):
        # Stdlib Logging functions are not reentrant.
        # logging.warning('Caught signal: %s', sig)
        tornado.ioloop.IOLoop.instance().add_callback_from_signal(shutdown)
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    try:
        logging.debug('thumbor running at %s:%d' % (context.server.ip, context.server.port))
        tornado.ioloop.IOLoop.instance().start()
    except KeyboardInterrupt:
        print
        print "-- thumbor closed by user interruption --"
    finally:
        context.thread_pool.cleanup()

if __name__ == "__main__":
    main(sys.argv[1:])
