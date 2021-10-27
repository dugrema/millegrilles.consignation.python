from requests import HTTPError
import requests
import json
import urllib

import logging


class RabbitMQAPI:
    """
    Provient de https://pypi.org/project/rabbitmq-admin/
    Copie pour ajouter handling cert CA pour https (verify)
    """

    def __init__(self, docker_nodename, password, ca_certs, port=8443, guest=False):
        self.logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        if guest:
            self.url = 'https://%s:%d' % (docker_nodename, port)
            self.auth = ('guest', 'guest')
            self.verify = False
            self.ca_cert_path = False  # Desactive verify pour le compte guest (localhost)
        else:
            self.url = 'https://%s:%d' % (docker_nodename, port)
            self.auth = ('admin', password)
            self.ca_cert_path = ca_certs

        self.headers = {
            'Content-type': 'application/json',
        }

    def get_overview(self):
        overview = self._api_get('/api/overview')
        self.logger.debug("Overview:\n%s" % json.dumps(overview, indent=4))
        return overview

    def get_vhost(self, name):
        """
        Details about an individual vhost.

        :param name: The vhost name
        :type name: str
        """
        return self._api_get('/api/vhosts/{0}'.format(
            urllib.parse.quote_plus(name)
        ))

    def create_vhost(self, name, tracing=False):
        """
        Create an individual vhost.

        :param name: The vhost name
        :type name: str

        :param tracing: Set to ``True`` to enable tracing
        :type tracing: bool
        """
        data = {'tracing': True} if tracing else {}
        return self._api_put(
            '/api/vhosts/{0}'.format(urllib.parse.quote_plus(name)),
            data=data,
        )

    def get_user(self, name):
        """
        Details about an individual user.

        :param name: The user's name
        :type name: str
        """
        return self._api_get('/api/users/{0}'.format(
            urllib.parse.quote_plus(name)
        ))

    def create_user(self, name, password=None):
        """
        Create a user

        :param name: The user's name
        :type name: str
        """
        data = {
            'tags': '',

        }
        if password is None:
            data['password_hash']: ''  # Desactive auth par mot de passe
        else:
            data['password'] = password

        return self._api_put(
            '/api/users/{0}'.format(urllib.parse.quote_plus(name)),
            data=data,
        )

    def delete_user(self, name):
        """
        Delete a user.

        :param name: The user's name
        :type name: str
        """
        self._api_delete('/api/users/{0}'.format(
            urllib.parse.quote_plus(name)
        ))

    def create_admin(self, name, password):
        """
        Create a user

        :param name: The user's name
        :type name: str
        """
        data = {
            'tags': 'administrator',
        }
        if password is None:
            data['password_hash']: ''  # Desactive auth par mot de passe
        else:
            data['password'] = password

        self._api_put(
            '/api/users/{0}'.format(urllib.parse.quote_plus(name)),
            data=data,
        )

    def create_user_permission(self,
                               name,
                               vhost,
                               configure=None,
                               write=None,
                               read=None):
        """
        Create a user permission
        :param name: The user's name
        :type name: str
        :param vhost: The vhost to assign the permission to
        :type vhost: str

        :param configure: A regex for the user permission. Default is ``.*``
        :type configure: str
        :param write: A regex for the user permission. Default is ``.*``
        :type write: str
        :param read: A regex for the user permission. Default is ``.*``
        :type read: str
        """
        data = {
            'configure': configure or 'amq\\..*',
            'write': write or 'amq\\..*',
            'read': read or 'amq\\..*',
        }
        return self._api_put(
            '/api/permissions/{0}/{1}'.format(
                urllib.parse.quote_plus(vhost),
                urllib.parse.quote_plus(name)
            ),
            data=data
        )

    def create_user_topic(self, name, vhost, exchange, write=None, read=None):
        data = {
            'exchange': exchange,
            'write': '',
            'read': '',
        }
        if write != '':
            data['write'] = write or '.*'
        if read != '':
            data['read'] = read or '.*'
        return self._api_put(
            '/api/topic-permissions/{0}/{1}'.format(
                urllib.parse.quote_plus(vhost),
                urllib.parse.quote_plus(name)
            ),
            data=data
        )

    def create_exchange_for_vhost(self, exchange, vhost, body):
        """
        Create an individual exchange.
        The body should look like:
        ::

            {
                "type": "direct",
                "auto_delete": false,
                "durable": true,
                "internal": false,
                "arguments": {}
            }

        The type key is mandatory; other keys are optional.

        :param exchange: The exchange name
        :type exchange: str

        :param vhost: The vhost name
        :type vhost: str

        :param body: A body for the exchange.
        :type body: dict
        """
        self._api_put(
            '/api/exchanges/{0}/{1}'.format(
                urllib.parse.quote_plus(vhost),
                urllib.parse.quote_plus(exchange)),
            data=body
        )

    def healthchecks(self):
        return self._api_get('/api/healthchecks/node')

    def aliveness(self, vhost):
        return self._api_get('/api/aliveness-test/%s' % vhost)

    def _api_get(self, url, **kwargs):
        """
        A convenience wrapper for _get. Adds headers, auth and base url by
        default
        """
        kwargs['url'] = self.url + url
        kwargs['auth'] = self.auth

        headers = dict()
        headers.update(self.headers)
        headers.update(kwargs.get('headers', {}))
        kwargs['headers'] = headers
        kwargs['verify'] = self.ca_cert_path

        return self.__get(**kwargs)

    def __get(self, *args, **kwargs):
        """
        :returns:
        """
        response = requests.get(*args, **kwargs)
        response.raise_for_status()
        return response.json()

    def _api_put(self, url, **kwargs):
        """
        A convenience wrapper for _put. Adds headers, auth and base url by
        default
        """
        kwargs['url'] = self.url + url
        kwargs['auth'] = self.auth

        headers = dict()
        headers.update(self.headers)
        headers.update(kwargs.get('headers', {}))
        kwargs['headers'] = headers
        kwargs['verify'] = self.ca_cert_path
        return self._put(**kwargs)

    def _put(self, *args, **kwargs):
        """
        A wrapper for putting things. It will also json encode your 'data' parameter

        :returns: The response of your put
        :rtype: dict
        """
        if 'data' in kwargs:
            kwargs['data'] = json.dumps(kwargs['data'])
        response = requests.put(*args, **kwargs)
        # print(str(response))
        response.raise_for_status()

        return response

    def _api_post(self, url, **kwargs):
        """
        A convenience wrapper for _post. Adds headers, auth and base url by
        default
        """
        kwargs['url'] = self.url + url
        kwargs['auth'] = self.auth

        headers = dict()
        headers.update(self.headers)
        headers.update(kwargs.get('headers', {}))
        kwargs['headers'] = headers
        kwargs['verify'] = self.ca_cert_path
        self._post(**kwargs)

    def _post(self, *args, **kwargs):
        """
        A wrapper for posting things. It will also json encode your 'data' parameter

        :returns: The response of your post
        :rtype: dict
        """
        if 'data' in kwargs:
            kwargs['data'] = json.dumps(kwargs['data'])
        response = requests.post(*args, **kwargs)
        response.raise_for_status()

    def _api_delete(self, url, **kwargs):
        """
        A convenience wrapper for _delete. Adds headers, auth and base url by
        default
        """
        kwargs['url'] = self.url + url
        kwargs['auth'] = self.auth

        headers = dict()
        headers.update(self.headers)
        headers.update(kwargs.get('headers', {}))
        kwargs['headers'] = headers
        kwargs['verify'] = self.ca_cert_path
        self._delete(**kwargs)

    def _delete(self, *args, **kwargs):
        """
        A wrapper for deleting things

        :returns: The response of your delete
        :rtype: dict
        """
        response = requests.delete(*args, **kwargs)
        response.raise_for_status()