"""
Custom Authenticator to use Azure AD with JupyterHub

"""

import json
import jwt
import os
import re
import string
import urllib

from tornado.auth import OAuth2Mixin
from tornado.log import app_log
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import List, Set, Unicode

from .common import next_page_from_links
from .oauth2 import OAuthLoginHandler, OAuthenticator

def _api_headers(access_token):
    return {"Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "token {}".format(access_token)
            }

# we need this, as microsoft expects '&' not to be encoded in the POST body
def dictToQuery(d):
    query = ''
    for key in d.keys():
        query += str(key) + '=' + str(d[key]) + "&"
    return query

class AzureAdMixin(OAuth2Mixin):
    _OAUTH_ACCESS_TOKEN_URL = os.environ.get('OAUTH2_TOKEN_URL', '')
    _OAUTH_AUTHORIZE_URL =  os.environ.get('OAUTH2_AUTHORIZE_URL', '')
    
class AzureAdLoginHandler(OAuthLoginHandler, AzureAdMixin):
    pass

class AzureAdOAuthenticator(OAuthenticator):

    login_service = "Azure AD"

    login_handler = AzureAdLoginHandler

    authorize_url = Unicode(
        os.environ.get('OAUTH_AUTHORIZE_URL', ''),
        config=True,
        help="Authorize url"
    )

    token_url = Unicode(
        os.environ.get('OAUTH2_TOKEN_URL', ''),
        config=True,
        help="Token url"
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):
        """We set up auth_state based on additional GitHub info if we
        receive it.
        """
        code = handler.get_argument("code")
        http_client = AsyncHTTPClient()

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type = 'authorization_code',
            code=code,
            resource='a67c1e23-de97-4783-99f3-db500c34982c',
            redirect_uri=self.get_callback_url(handler)
        )

        data = urllib.parse.urlencode(params, doseq=True, encoding='utf-8', safe='=')

        url = self.token_url
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded; ; charset=UTF-8"'}
        req = HTTPRequest(url,
                          method = "POST",
                          headers = headers,
                          body = data   # Body is required for a POST...
                          )


        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        app_log.info("Response %s", resp_json)
        access_token = resp_json['access_token']

        id_token = resp_json['id_token']
        decoded = jwt.decode(id_token, verify=False)

        userdict = {"name": decoded['name']}
        # Now we set up auth_state
        userdict["auth_state"] = auth_state = {}
        auth_state['access_token'] = access_token
        # store the whole user model in auth_state.github_user
        auth_state['user'] = decoded
        
        return userdict

class LocalAzureAdOAuthenticator(LocalAuthenticator, AzureAdOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
