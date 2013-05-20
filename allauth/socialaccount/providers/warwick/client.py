"""
Parts derived from socialregistration and authorized by: alen, pinda
Inspired by:
    http://github.com/leah/python-oauth/blob/master/oauth/example/client.py
    http://github.com/facebook/tornado/blob/master/tornado/auth.py
"""

import urllib
import urllib2

from django.http import HttpResponseRedirect
from django.utils.translation import gettext as _

from allauth.socialaccount.providers.oauth.client import OAuthError, \
                                                        get_token_prefix, \
                                                        OAuthClient

# parse_qsl was moved from the cgi namespace to urlparse in Python2.6.
# this allows backwards compatibility
try:
    from urlparse import parse_qsl
except ImportError:
    from cgi import parse_qsl

import requests
from requests_oauthlib import OAuth1
import certifi

import logging
logger = logging.getLogger(__name__)

def _get_client(self, request, callback_url):
    provider = self.adapter.get_provider()
    app = provider.get_app(request)
    scope = '+'.join(provider.get_scope())
    parameters = {}
    # if scope:
    #             parameters['scope'] = scope
    client = OAuthClient(request, app.client_id, app.secret,
                         self.adapter.request_token_url,
                         self.adapter.access_token_url,
                         self.adapter.authorize_url,
                         callback_url,
                         parameters=parameters,
                         scope=scope)
    return client

class OAuthClient(OAuthClient):

    def __init__(self, *args, **kwargs):

        self.scope = kwargs['scope']
        del kwargs['scope']

        super(OAuthClient, self).__init__(*args, **kwargs)

    def _get_request_token(self):
        """
        Obtain a temporary request token to authorize an access token and to
        sign the request to obtain the access token
        """
        if self.request_token is None:
            get_params = {}
            if self.parameters:
                get_params.update(self.parameters)
            get_params['oauth_callback'] \
                = self.request.build_absolute_uri(self.callback_url)
            rt_url = self.request_token_url

            scope = ''
            if self.scope:
                scope = {'scope': self.scope}
            oauth = OAuth1(self.consumer_key, client_secret=self.consumer_secret)

            logging.debug('Requesting token with scope %s' % scope)

            response = requests.post(url=rt_url, auth=oauth, params=scope)
            logging.debug('Request content: %s' % response.request.body)
            if response.status_code != 200:
                logging.warn('Invalid response while obtaining request token from "%s".' % get_token_prefix(self.request_token_url))
                logging.warn(response.text)
                raise OAuthError(
                    _('Invalid response while obtaining request token from "%s".') % get_token_prefix(self.request_token_url))
            self.request_token = dict(parse_qsl(response.text))

            self.request.session['oauth_%s_request_token' % get_token_prefix(self.request_token_url)] = self.request_token
        return self.request_token

    # def get_access_token(self):
    #     """
    #     Obtain the access token to access private resources at the API endpoint.
    #     """
    #     if self.access_token is None:
    #         request_token = self._get_rt_from_session()
    #         oauth = OAuth1(self.consumer_key,
    #                        client_secret=self.consumer_secret,
    #                        resource_owner_key=request_token['oauth_token'],
    #                        resource_owner_secret=request_token['oauth_token_secret'])
    #         at_url = self.access_token_url

    #         # Passing along oauth_verifier is required according to:
    #         # http://groups.google.com/group/twitter-development-talk/browse_frm/thread/472500cfe9e7cdb9#
    #         # Though, the custom oauth_callback seems to work without it?
    #         if 'oauth_verifier' in self.request.REQUEST:
    #             at_url = at_url + '?' + urlencode({'oauth_verifier': self.request.REQUEST['oauth_verifier']})
    #         response = requests.post(url=at_url, auth=oauth)
    #         if response.status_code != 200:
    #             raise OAuthError(
    #                 _('Invalid response while obtaining access token from "%s".') % get_token_prefix(self.request_token_url))
    #         self.access_token = dict(parse_qsl(response.text))

    #         self.request.session['oauth_%s_access_token' % get_token_prefix(self.request_token_url)] = self.access_token
    #     return self.access_token
