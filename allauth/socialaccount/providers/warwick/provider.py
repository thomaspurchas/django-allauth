from allauth.socialaccount import providers
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth.provider import OAuthProvider


class WarwickAccount(ProviderAccount):
    def get_screen_name(self):
        first = self.account.extra_data.get('firstname')
        last = self.account.extra_data.get('lastname')
        return ' '.join([first,last])

    def get_profile_url(self):
        ret = None
        screen_name = self.get_screen_name()
        if screen_name:
            ret = '' + screen_name
        return ret

    def get_avatar_url(self):
        ret = None
        profile_image_url = self.account.extra_data.get('profile_image_url')
        if profile_image_url:
            # Hmm, hack to get our hands on the large image.  Not
            # really documented, but seems to work.
            ret = profile_image_url.replace('_normal', '')
        return ret

    def __unicode__(self):
        screen_name = self.get_screen_name()
        return screen_name or super(WarwickAccount, self).__unicode__()


class WarwickProvider(OAuthProvider):
    id = 'warwick'
    name = 'University of Warwick'
    package = 'allauth.socialaccount.providers.warwick'
    account_class = WarwickAccount
        
        
providers.registry.register(WarwickProvider)
