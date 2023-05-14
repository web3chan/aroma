import asyncio
import uuid
import logging
import orjson
import urllib
from datetime import datetime, timezone

from collections import UserList

import websockets
import dateutil.parser

__useragent__ = "aroma/1.x; (+https://github.com/web3chan/aroma)"
SCOPES = 'read write follow'
REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'


def str_bool(b):
    """Convert boolean to a string, in the way expected by the API."""
    return "true" if b else "false"


def get_id(item):
    """Return id of an item if it's a dict"""
    if type(item) == dict and "id" in item:
        return item["id"]
    else:
        return item


class ResponseList(UserList):
    """List-like datatype for Mastodon API results pagination"""

    def __init__(self, data, method=None, kwargs={}):
        self.data = data
        self.method = method
        self.kwargs = kwargs
        self.next = None
        self.previous = None


class MastodonAPI:

    @staticmethod
    async def create_app(client, api_base_url, scopes=SCOPES, client_name="aroma", client_website=None):
        url = f"{api_base_url}/api/v1/apps"
        data = {'client_name': client_name, "scopes": scopes, "redirect_uris": REDIRECT_URI}
        resp = await client.post(url, data=data)
        resp_data = orjson.loads(resp.text)
        return (resp_data["client_id"], resp_data["client_secret"])

    @staticmethod
    async def log_in(client, api_base_url, client_id, client_secret,
                     username=None, password=None, oauth_code=None,
                     scope=SCOPES):
        data = {
            "client_id": client_id, "client_secret": client_secret,
            "redirect_uri": REDIRECT_URI, "scope": scope,
        }
        if username and password:
            data["grant_type"] = "password"
            data['username'] = username
            data['password'] = password
        elif oauth_code:
            data["grant_type"] = "authorization_code"
            data["code"] = oauth_code
        else:
            data["grant_type"] = "client_credentials"

        url = f"{api_base_url}/oauth/token"
        resp = await client.post(url, data=data)
        resp_data = orjson.loads(resp.text)
        return resp_data["access_token"]

    def __init__(self, client, api_base_url, client_id=None, client_secret=None, access_token=None, auto_ratelimit=False):
        self.client = client
        self.api_base_url = api_base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = access_token
        self.user_agent = __useragent__
        self.authorization = f"Bearer {self.access_token}" if self.access_token else None
        self.auto_ratelimit = auto_ratelimit

        self._ratelimit_lock = asyncio.Lock()
        self._ratelimit_remaining = "300"
        self._ratelimit_reset = None

    async def __api_request(self, method, url, **kwargs):
        url = self.api_base_url + url

        if "headers" not in kwargs:
            kwargs["headers"] = {}

        kwargs["headers"]["User-Agent"] = self.user_agent
        if self.authorization:
            kwargs["headers"]["Authorization"] = self.authorization

        if self.auto_ratelimit:
            async with self._ratelimit_lock:
                if self._ratelimit_remaining == "0":
                    sleep_time = dateutil.parser.parse(self._ratelimit_reset) - datetime.now(timezone.utc)
                    logging.debug(f"Hit the rate limit! waiting for {sleep_time}")
                    await asyncio.sleep(sleep_time.total_seconds())

                try:
                    resp = await self.client.request(method, url, **kwargs)
                except Exception as e:
                    raise NetworkError(f"Could not complete request: {e}")

                # save ratelimit values
                if "x-ratelimit-remaining" in resp.headers:
                    self._ratelimit_remaining = resp.headers["x-ratelimit-remaining"]
                if "x-ratelimit-reset" in resp.headers:
                    self._ratelimit_reset = resp.headers["x-ratelimit-reset"]
        else:
            try:
                resp = await self.client.request(method, url, **kwargs)
            except Exception as e:
                raise NetworkError(f"Could not complete request: {type(e)}: {e}")

        # raise exceptions
        if resp.status_code >= 400:
            raise_exception(resp)

        try:
            content = orjson.loads(resp.text)
        except Exception as e:
            raise MastodonError(f"Can't parse JSON content: {e}")

        if type(content) == list:
            content = ResponseList(content, method=method, kwargs=kwargs)

            if "next" in resp.links:
                content.next = resp.links["next"]["url"]
            if "previous" in resp.links:
                content.previous = resp.links["previous"]["url"]

        return content

    async def get_next(self, content):
        if not content.next:
            return None
        url = urllib.parse.urlparse(content.next)
        return await self.__api_request(content.method, f"{url.path}?{url.query}", **content.kwargs)

    async def get_previous(self, content):
        if not content.previous:
            return None
        url = urllib.parse.urlparse(content.previous)
        return await self.__api_request(content.method, f"{url.path}?{url.query}", **content.kwargs)

    async def get_all(self, task):
        """A shortcut function to get all results from a paginated task.

        :param task: a coroutine which returns a paginated list of objects

        Usage::

        >>> notifs = await client.get_all(client.get_notifications())
        """
        results = await task

        limit = None
        if "params" in results.kwargs and "limit" in results.kwargs["params"]:
            limit = results.kwargs["params"]["limit"]

        all_results = results.copy()

        while results is not None and results.next:
            if limit and len(results) < limit:
                # skip fetching next page if results list is not full
                break
            results = await self.get_next(results)
            all_results.extend(results)

        return all_results

    async def account_verify_credentials(self):
        return await self.__api_request('GET', '/api/v1/accounts/verify_credentials')

    async def instance(self):
        return await self.__api_request('GET', '/api/v1/instance')

    async def account(self, account_id):
        return await self.__api_request('GET', f'/api/v1/accounts/{account_id}')

    async def account_followers(self, account_id, params={}):
        return await self.__api_request('GET', f'/api/v1/accounts/{account_id}/followers', params=params)

    async def account_following(self, account_id, params={}):
        return await self.__api_request('GET', f'/api/v1/accounts/{account_id}/following', params=params)

    async def account_follow(self, account_id):
        return await self.__api_request('POST', f'/api/v1/accounts/{account_id}/follow')

    async def account_unfollow(self, account_id):
        return await self.__api_request('POST', f'/api/v1/accounts/{account_id}/unfollow')

    async def account_block(self, account_id):
        return await self.__api_request('POST', f'/api/v1/accounts/{account_id}/block')

    async def account_unblock(self, account_id):
        return await self.__api_request('POST', f'/api/v1/accounts/{account_id}/unblock')

    async def follow_requests(self, params={}):
        return await self.__api_request('GET', '/api/v1/follow_requests', params=params)

    async def follow_request_authorize(self, object_id):
        return await self.__api_request('POST', f'/api/v1/follow_requests/{object_id}/authorize')

    async def follow_request_reject(self, object_id):
        return await self.__api_request('POST', f'/api/v1/follow_requests/{object_id}/reject')

    async def account_relationships(self, *account_ids):
        params = {'q': account_ids}
        return await self.__api_request('GET', '/api/v1/accounts/relationships', params=params)

    async def remove_from_followers(self, account_id):
        return await self.__api_request('POST', f'/api/v1/accounts/{account_id}/remove_from_followers')

    async def account_search(self, q, resolve=False, params={}):
        params["q"] = q
        params["resolve"] = resolve
        return await self.__api_request('POST', '/api/v1/accounts/search', params=params)

    async def status_create(self, status, data={}):
        data["status"] = status

        # Idempotency key assures the same status is not posted multiple times
        # if the request is retried.
        headers = {"Idempotency-Key": uuid.uuid4().hex}

        return await self.__api_request('POST', '/api/v1/statuses', data=data, headers=headers)

    async def status_delete(self, status_id):
        return await self.__api_request('DELETE', f'/api/v1/statuses/{status_id}')

    async def status_reblog(self, status_id):
        return await self.__api_request('POST', f'/api/v1/statuses/{status_id}/reblog')

    async def status_unreblog(self, status_id):
        return await self.__api_request('POST', f'/api/v1/statuses/{status_id}/unreblog')

    async def public_timeline(self, params={}):
        return await self.__api_request('GET', '/api/v1/timelines/public', params=params)

    async def notifications(self, params={}):
        return await self.__api_request('GET', '/api/v1/notifications', params=params)

    async def notification_dismiss(self, notification_id):
        return await self.__api_request('POST', f'/api/v1/notifications/{notification_id}/dismiss')

    async def search(self, query, resolve=False, params={}):
        params["q"] = query
        params["resolve"] = resolve
        return await self.__api_request('GET', '/api/v2/search', params=params)

    def stream(self, ws_url=None):
        if ws_url is None:
            ws_url = self.api_base_url.replace("http", "ws", 1)

        return websockets.connect(
            ws_url + '/api/v1/streaming',
            extra_headers={"Authorization": self.authorization},
            origin=self.api_base_url
        )


def raise_exception(r):
    error_message = "Exception has occured"
    try:
        content = orjson.loads(r.text)
        error_message = content["error"]
    except:
        try:
            error_message = r.text
        except:
            pass

    if r.status_code == 401:
        ExceptionType = UnauthorizedError
    elif r.status_code == 403:
        ExceptionType = ForbiddenError
    elif r.status_code == 404:
        ExceptionType = NotFoundError
    elif r.status_code == 409:
        ExceptionType = ConflictError
    elif r.status_code == 410:
        ExceptionType = GoneError
    elif r.status_code == 422:
        ExceptionType = UnprocessedError
    elif r.status_code == 429:
        ExceptionType = RatelimitError
    elif r.status_code == 503:
        ExceptionType = UnavailableError
    elif r.status_code < 500:
        ExceptionType = ClientError
    else:
        ExceptionType = ServerError

    raise ExceptionType(r.status_code, r.reason_phrase, error_message)


class MastodonError(Exception):
    """Generic MastodonAPI exception"""

class NetworkError(MastodonError):
    """httpx client could not complete request"""

class ApiError(MastodonError):
    pass

class ClientError(MastodonError):
    pass

class UnauthorizedError(ClientError):
    pass

class ForbiddenError(ClientError):
    pass

class NotFoundError(ClientError):
    pass

class ConflictError(ClientError):
    pass

class GoneError(ClientError):
    pass

class UnprocessedError(ClientError):
    pass

class RatelimitError(ClientError):
    pass

class ServerError(MastodonError):
    pass

class UnavailableError(MastodonError):
    pass
