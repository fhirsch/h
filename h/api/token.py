import urlparse

from annotator import auth
from pyramid.authentication import RemoteUserAuthenticationPolicy
from pyramid.security import authenticated_userid
from pyramid.view import view_config, view_defaults

from h import interfaces, views


@view_defaults(renderer='string', route_name='token')
class TokenController(views.BaseController):
    @view_config(request_method="GET")
    def __call__(self):
        request = self.request

        consumer = self.Consumer.get_by_key(self.settings['api.key'])
        assert(consumer)

        message = {
            'consumerKey': str(consumer.key),
            'ttl': consumer.ttl,
        }

        userid = authenticated_userid(request)

        if isinstance(userid, basestring):
            message['userId'] = userid
        elif request.user:
            message['userId'] = "acct:%(username)s@%(provider)s" % {
                'username': request.user.username,
                'provider': request.server_name
            }

        return auth.encode_token(message, consumer.secret)

    @classmethod
    def __json__(cls, request):
        return cls(request)()


class AuthTokenAuthenticationPolicy(RemoteUserAuthenticationPolicy):
    def __init__(self, debug=False):
        super(AuthTokenAuthenticationPolicy, self).__init__(
            environ_key='HTTP_X_ANNOTATOR_AUTH_TOKEN',
            callback=self.callback,
            debug=debug,
        )

    def callback(self, userid, request):
        Consumer = request.registry.queryUtility(interfaces.IConsumerClass)
        user = auth.Authenticator(Consumer.get_by_key).request_user(request)
        if user:
            # effective_principals will include the userid by default
            return []
        return None

    def unauthenticated_userid(self, request):
        token = request.environ.get(self.environ_key)
        try:
            unsafe = auth.decode_token(token, verify=False)
        except auth.TokenInvalid:
            return None
        else:
            return unsafe.get('userId')


def includeme(config):
    """Include an auth token generator.

    Example INI file:

    .. code-block:: ini
        [app:h]
        api.token_endpoint: /api/token
    """

    token_endpoint = config.registry.settings.get(
        'api.token_endpoint',
        '/api/token'
    ).strip('/')
    config.add_route('token', token_endpoint)
    config.scan(__name__)

    authn_debug = config.registry.settings.get('pyramid.debug_authorization') \
        or config.registry.settings.get('debug_authorization')
    authn_policy = AuthTokenAuthenticationPolicy(debug=authn_debug)
    config.set_authentication_policy(authn_policy)

    if not config.registry.queryUtility(interfaces.ITokenClass):
        config.registry.registerUtility(
            TokenController,
            interfaces.ITokenClass
        )
