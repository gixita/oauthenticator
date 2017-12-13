"""
Custom Authenticator to use Azure AD with JupyterHub

"""

import json
import os
import re
import string

from tornado.auth import OAuth2Mixin
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


class AzureAdMixin(OAuth2Mixin):
    _OAUTH_ACCESS_TOKEN_URL = os.environ.get('OAUTH2_TOKEN_URL', '')
    _OAUTH_AUTHORIZE_URL = os.environ.get('OAUTH2_AUTHORIZE_URL', '')
    
class AzureAdLoginHandler(OAuthLoginHandler, AzureAdMixin):
    pass


class AzureAdOAuthenticator(OAuthenticator):

    login_service = "AzureAD"

    #c.AzureAdOAuthenticator.scope = ""

    login_handler = AzureAdLoginHandler

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

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code
        )

        url = url_concat(self.token_url, params)

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body=''  # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        print(resp_json)

        #context = adal.AuthenticationContext(authority_url, validate_authority=True, api_version=None)

        #token = context.acquire_token_with_client_credentials(
        #    RESOURCE,
        #    sample_parameters['clientId'],
        #    sample_parameters['clientSecret'])

        return None
#            import os
#from azure.common.credentials import ServicePrincipalCredentials
#from azure.mgmt.resource import ResourceManagementClient
#from azure.mgmt.web import WebSiteManagementClient

#subscription_id = os.environ['AZURE_SUBSCRIPTION_ID']

#credentials = ServicePrincipalCredentials(
#    client_id=os.environ['AZURE_CLIENT_ID'],
#    secret=os.environ['AZURE_CLIENT_SECRET'],
#    tenant=os.environ['AZURE_TENANT_ID']
#)
#resource_client = ResourceManagementClient(credentials, subscription_id)
#web_client = WebSiteManagementClient(credentials, subscription_id)

        username = resp_json["login"]
        # username is now the GitHub userid.
        if not username:
            return None
        
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
