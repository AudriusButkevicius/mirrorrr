#!/usr/bin/env python
# Copyright 2008-2014 Brett Slatkin
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__author__ = "Brett Slatkin (bslatkin@gmail.com)"

import logging
import os
import requests
import urllib
import wsgiref.handlers

import webapp2
from jinja2 import Environment, FileSystemLoader

import transform_content

templates = Environment(loader=FileSystemLoader(os.path.dirname(__file__)))

###############################################################################

DEBUG = True

HTTP_PREFIX = "http://"

IGNORE_HEADERS = frozenset([
  "set-cookie",
  "expires",
  "cache-control",

  # Ignore hop-by-hop headers
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "transfer-encoding",
  "upgrade",

])

TRANSFORMED_CONTENT_TYPES = frozenset([
  "text/html",
  "text/css",
])

MAX_CONTENT_SIZE = 10 ** 6

###############################################################################

class MirroredContent(object):
  def __init__(self, original_address, translated_address,
               status, headers, data, base_url):
    self.original_address = original_address
    self.translated_address = translated_address
    self.status = status
    self.headers = headers
    self.data = data
    self.base_url = base_url

  @staticmethod
  def fetch(base_url, translated_address, mirrored_url):
    """Fetch a page.

    Args:
      base_url: The hostname of the page that's being mirrored.
      translated_address: The URL of the mirrored page on this site.
      mirrored_url: The URL of the original page. Hostname should match
        the base_url.

    Returns:
      A new MirroredContent object, if the page was successfully retrieved.
      None if any errors occurred or the content could not be retrieved.
    """
    logging.debug("Fetching '%s'", mirrored_url)
    try:
      response = requests.get(mirrored_url)
    except Exception as e:
      logging.exception("Could not fetch URL: %s (%s)" % (mirrored_url, e))
      return None

    adjusted_headers = {}
    for key, value in response.headers.iteritems():
      adjusted_key = key.lower()
      if adjusted_key not in IGNORE_HEADERS:
        adjusted_headers[adjusted_key] = value

    content = response.content
    page_content_type = adjusted_headers.get("content-type", "")
    for content_type in TRANSFORMED_CONTENT_TYPES:
      # startswith() because there could be a 'charset=UTF-8' in the header.
      if page_content_type.startswith(content_type):
        content = transform_content.TransformContent(base_url, mirrored_url,
                                                     content)
        break

    # If the transformed content is over 1MB, truncate it (yikes!)
    if len(content) > MAX_CONTENT_SIZE:
      logging.warning("Content is over 1MB; truncating")
      content = content[:MAX_CONTENT_SIZE]

    new_content = MirroredContent(
      base_url=base_url,
      original_address=mirrored_url,
      translated_address=translated_address,
      status=response.status_code,
      headers=adjusted_headers,
      data=content)

    return new_content

###############################################################################

class WarmupHandler(webapp2.RequestHandler):
  def get(self):
    pass


class BaseHandler(webapp2.RequestHandler):
  def get_relative_url(self):
    slash = self.request.url.find("/", len(self.request.scheme + "://"))
    if slash == -1:
      return "/"
    return self.request.url[slash:]

  def is_recursive_request(self):
    if "AppEngine-Google" in self.request.headers.get("User-Agent", ""):
      logging.warning("Ignoring recursive request by user-agent=%r; ignoring")
      self.error(404)
      return True
    return False


class HomeHandler(BaseHandler):
  def get(self):
    if self.is_recursive_request():
      return

    # Handle the input form to redirect the user to a relative url
    form_url = self.request.get("url")
    if form_url:
      # Accept URLs that still have a leading 'http://'
      inputted_url = urllib.unquote(form_url)
      if inputted_url.startswith(HTTP_PREFIX):
        inputted_url = inputted_url[len(HTTP_PREFIX):]
      return self.redirect("/" + inputted_url)

    # Do this dictionary construction here, to decouple presentation from
    # how we store data.
    secure_url = None
    if self.request.scheme == "http":
      secure_url = "https://%s%s" % (self.request.host, self.request.path_qs)
    context = {
      "secure_url": secure_url,
    }
    self.response.out.write(templates.get_template("main.html").render(context))


class MirrorHandler(BaseHandler):
  def get(self, base_url):
    if self.is_recursive_request():
      return

    assert base_url

    # Log the user-agent and referrer, to see who is linking to us.
    logging.debug('User-Agent = "%s", Referrer = "%s"',
                  self.request.user_agent,
                  self.request.referer)
    logging.debug('Base_url = "%s", url = "%s"', base_url, self.request.url)

    translated_address = self.get_relative_url()[1:]  # remove leading /
    mirrored_url = HTTP_PREFIX + translated_address


    content = MirroredContent.fetch(base_url, translated_address, mirrored_url)
    if content is None:
      return self.error(404)

    for key, value in content.headers.iteritems():
      self.response.headers[key] = value
    if not DEBUG:
      self.response.headers["cache-control"] = \
        "max-age=%d" % EXPIRATION_DELTA_SECONDS

    self.response.out.write(content.data)

###############################################################################

app = webapp2.WSGIApplication([
  (r"/", HomeHandler),
  (r"/main", HomeHandler),
  (r"/([^/]+).*", MirrorHandler),
], debug=DEBUG)


from paste.urlparser import StaticURLParser
from paste.cascade import Cascade
from paste import httpserver

static_app = StaticURLParser(".")
app = Cascade([static_app, app])

httpserver.serve(app, host='127.0.0.1', port='8787')
