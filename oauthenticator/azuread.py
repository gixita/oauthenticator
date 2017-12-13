"""
Custom Authenticator to use Azure AD with JupyterHub

"""

import json
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

    login_service = "AzureAD"

    #c.AzureAdOAuthenticator.scope = ""

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
            redirect_uri=self.get_callback_url(handler)
        )

        url = self.token_url
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        req = HTTPRequest(url,
                          method="POST",
                          headers = headers,
                          body= dictToQuery(params)#urllib.parse.urlencode(params)   # Body is required for a POST...
                          )

        app_log.info("Request body %s", req.body)

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        app_log.info("Response %s", resp_json)
        access_token = resp_json['access_token']
        #context = adal.AuthenticationContext(authority_url, validate_authority=True, api_version=None)

        #token = context.acquire_token_with_client_credentials(
        #    RESOURCE,
        #    sample_parameters['clientId'],
        #    sample_parameters['clientSecret'])
        
        userdict = {"name": username}
        # Now we set up auth_state
        userdict["auth_state"] = auth_state = {}
        # Save the access token and full GitHub reply (name, id, email) in auth state
        # These can be used for user provisioning in the Lab/Notebook environment.
        # e.g.
        #  1) stash the access token
        #  2) use the GitHub ID as the id
        #  3) set up name/email for .gitconfig
        auth_state['access_token'] = access_token
        # store the whole user model in auth_state.github_user
        auth_state['github_user'] = resp_json
        # A public email will return in the initial query (assuming default scope).
        # Private will not.

        return userdict

class LocalAzureAdOAuthenticator(LocalAuthenticator, AzureAdOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
