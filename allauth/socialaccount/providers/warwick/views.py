import re

from django.utils import simplejson

from allauth.account.models import EmailAddress
from allauth.socialaccount.providers.oauth.client import OAuth
from allauth.socialaccount.providers.oauth.views import (OAuthAdapter,
                                                         OAuthLoginView,
                                                         OAuthCallbackView)
from allauth.socialaccount.models import SocialLogin, SocialAccount
from allauth.utils import get_user_model

from provider import WarwickProvider

from client import _get_client

User = get_user_model()

class WarwickAPI(OAuth):
    """
    Grab user information
    """
    url = 'https://websignon.warwick.ac.uk/oauth/authenticate/attributes'
    regex = re.compile('(.+?)=(.+)')

    def get_user_info(self):
        user = dict(self.regex.findall(self.query(self.url, "POST")))
        return user


class WarwickOAuthAdapter(OAuthAdapter):
    provider_id = WarwickProvider.id
    request_token_url = 'https://websignon.warwick.ac.uk/oauth/requestToken'
    access_token_url = 'https://websignon.warwick.ac.uk/oauth/accessToken'
    authorize_url = 'https://websignon.warwick.ac.uk/oauth/authenticate'

    def complete_login(self, request, app, token):
        client = WarwickAPI(request, app.client_id, app.secret,
                            self.request_token_url)
        extra_data = client.get_user_info()
        uid = extra_data['id']
        user = User(username=extra_data['user'],
                    email=extra_data.get('email', ''),
                    first_name=extra_data.get('firstname', ''),
                    last_name=extra_data.get('lastname', ''))
                    
        email_addresses = []
        if user.email:
            email_addresses.append(EmailAddress(email=user.email,
                                                verified=True,
                                                primary=True))
                                                
        account = SocialAccount(user=user,
                                uid=uid,
                                provider=WarwickProvider.id,
                                extra_data=extra_data)
        return SocialLogin(account, email_addresses=email_addresses)

OAuthLoginView._get_client = _get_client
OAuthCallbackView._get_client = _get_client

oauth_login = OAuthLoginView.adapter_view(WarwickOAuthAdapter)
oauth_callback = OAuthCallbackView.adapter_view(WarwickOAuthAdapter)

