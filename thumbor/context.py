#!/usr/bin/python
# -*- coding: utf-8 -*-

# thumbor imaging service
# https://github.com/globocom/thumbor/wiki

# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license
# Copyright (c) 2011 globo.com timehome@corp.globo.com

from os.path import abspath, exists

from thumbor.filters import FiltersFactory
from thumbor.utils import logger
from thumbor.url import Url
import statsd

class ThumborStatsClient(statsd.StatsClient):

  def __init__(self, config):
    self.config = config
    if config and config.STATSD_HOST:
      self.enabled = True
      host = config.STATSD_HOST
      prefix = config.STATSD_PREFIX
    else:
      self.enabled = False
      # Just setting this so we can initialize the client -
      # we never send any data if enabled is false
      host = 'localhost'
      prefix=None
    super(ThumborStatsClient, self).__init__(host, 8125, prefix)

  def _send(self, data):
    logger.debug("STATSD: %s", data)
    if self.enabled:
      super(ThumborStatsClient, self)._send(data)


class Context:
    '''
    Class responsible for containing:
    * Server Configuration Parameters (port, ip, key, etc);
    * Configurations read from config file (or defaults);
    * Importer with imported modules (engine, filters, detectors, etc);
    * Request Parameters (width, height, smart, meta, etc).

    Each instance of this class MUST be unique per request. This class should not be cached in the server.
    '''

    def __init__(self, server=None, config=None, importer=None, request_handler=None):
        self.server = server
        self.config = config
        if importer:
            self.modules = ContextImporter(self, importer)
        else:
            self.modules = None
        self.filters_factory = FiltersFactory(self.modules.filters if self.modules else [])
        self.request_handler = request_handler
        self.statsd_client = ThumborStatsClient(config)



class ServerParameters(object):
    def __init__(self, port, ip, config_path, keyfile, log_level, app_class, fd=None, gifsicle_path=None, log_file=None):
        self.port = port
        self.ip = ip
        self.config_path = config_path
        self.keyfile = keyfile
        self.log_level = log_level
        self.app_class = app_class
        self._security_key = None
        self.fd = fd
        self.load_security_key()
        self.gifsicle_path = gifsicle_path
        self.log_file = log_file

    @property
    def security_key(self):
        return self._security_key

    @security_key.setter
    def security_key(self, key):
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        self._security_key = key

    def load_security_key(self):
        if not self.keyfile:
            return

        path = abspath(self.keyfile)
        if not exists(path):
            raise ValueError('Could not find security key file at %s. Please verify the keypath argument.' % path)

        with open(path, 'r') as f:
            security_key = f.read().strip()

        self.security_key = security_key


class RequestParameters:

    def __init__(self,
                 debug=False,
                 meta=False,
                 trim=None,
                 crop_left=None,
                 crop_top=None,
                 crop_right=None,
                 crop_bottom=None,
                 crop=None,
                 adaptive=False,
                 full=False,
                 fit_in=False,
                 width=0,
                 height=0,
                 horizontal_flip=False,
                 vertical_flip=False,
                 halign='center',
                 valign='middle',
                 filters=None,
                 smart=False,
                 quality=80,
                 image=None,
                 url=None,
                 extension=None,
                 buffer=None,
                 focal_points=None,
                 unsafe=False,
                 hash=None,
                 accepts_webp=False,
                 request=None,
                 max_age=None):

        self.debug = bool(debug)
        self.meta = bool(meta)
        self.trim = trim
        if trim is not None:
            trim_parts = trim.split(':')
            self.trim_pos = trim_parts[1] if len(trim_parts) > 1 else "top-left"
            self.trim_tolerance = int(trim_parts[2]) if len(trim_parts) > 2 else 0

        if crop is not None:
            self.crop = crop
        else:
            self.crop = {
                'left': self.int_or_0(crop_left),
                'right': self.int_or_0(crop_right),
                'top': self.int_or_0(crop_top),
                'bottom': self.int_or_0(crop_bottom)
            }

        self.should_crop = \
            self.crop['left'] > 0 or \
            self.crop['top'] > 0 or \
            self.crop['right'] > 0 or \
            self.crop['bottom'] > 0

        self.adaptive = bool(adaptive)
        self.full = bool(full)
        self.fit_in = bool(fit_in)

        self.width = width == "orig" and "orig" or self.int_or_0(width)
        self.height = height == "orig" and "orig" or self.int_or_0(height)
        self.horizontal_flip = bool(horizontal_flip)
        self.vertical_flip = bool(vertical_flip)
        self.halign = halign or 'center'
        self.valign = valign or 'middle'
        self.smart = bool(smart)

        if filters is None:
            filters = []

        self.filters = filters
        self.image_url = image
        self.url = url
        self.detection_error = None
        self.quality = quality
        self.buffer = None

        if focal_points is None:
            focal_points = []

        self.focal_points = focal_points
        self.hash = hash
        self.prevent_result_storage = False
        self.unsafe = unsafe == 'unsafe' or unsafe is True
        self.format = None
        self.accepts_webp = accepts_webp
        self.max_bytes = None
        self.max_age = max_age

        if request:
            if request.query:
                self.image_url += '?%s' % request.query
            self.url = request.path
            self.accepts_webp = 'image/webp' in request.headers.get('Accept', '')
            self.image_url = Url.encode_url(self.image_url.encode('utf-8'))

    def int_or_0(self, value):
        return 0 if value is None else int(value)


class ContextImporter:
    def __init__(self, context, importer):
        self.context = context
        self.importer = importer

        self.engine = None
        if importer.engine:
            self.engine = importer.engine(context)

        self.gif_engine = None
        if importer.gif_engine:
            self.gif_engine = importer.gif_engine(context)

        self.storage = None
        if importer.storage:
            self.storage = importer.storage(context)

        self.result_storage = None
        if importer.result_storage:
            self.result_storage = importer.result_storage(context)

        self.upload_photo_storage = None
        if importer.upload_photo_storage:
            self.upload_photo_storage = importer.upload_photo_storage(context)

        self.loader = importer.loader
        self.detectors = importer.detectors
        self.filters = importer.filters
        self.optimizers = importer.optimizers
