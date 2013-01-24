from allauth.socialaccount.providers.oauth.urls import default_urlpatterns
from provider import WarwickProvider

urlpatterns = default_urlpatterns(WarwickProvider)
