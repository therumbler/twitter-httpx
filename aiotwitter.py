"""asyncio TWitter library using HTTPX"""
import asyncio
import base64
import hashlib
import hmac
import logging
import os
import random
import string
import sys
import time
from urllib.parse import urlparse, quote, urlencode

import httpx

__all__ = ['get_status', 'lookup']

BASE_URL = "https://api.twitter.com/1.1"

logger = logging.getLogger(__name__)

def _create_parameter_string(parameters):
    parameter_string = ""
    for k, v in sorted(parameters.items()):
        if len(str(v)) > 0:
            parameter_string += "%s=%s&" % (quote(k), quote(str(v), ""))
        
    parameter_string = parameter_string[:-1]

    return parameter_string

def _get_base_url(full_url):
    """returns a URL without query string parameters"""
    parse = urlparse(full_url)
    return "%s://%s%s" % (parse.scheme, parse.netloc, parse.path)

def _create_signature(parameters, http_method, resource_url):
    """
    https://dev.twitter.com/docs/auth/creating-signature
    """
    parameter_string = _create_parameter_string(parameters)
    base_url = _get_base_url(resource_url)
    signature_base_string = "%s&%s&%s" % (http_method.upper(), quote(base_url, ""), quote(parameter_string, ""))

    signing_key = os.environ['TWITTER_CONSUMER_SECRET'] + "&" + os.environ['TWITTER_OAUTH_TOKEN_SECRET']

    return base64.b64encode(hmac.new(signing_key.encode(), signature_base_string.encode(), hashlib.sha1).digest())

def _create_header_string(params: dict, resource_url):
    """
    https://developer.twitter.com/en/docs/basics/authentication/oauth-1-0a/authorizing-a-request
    """
    oauth_nonce = "".join(
        random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase)
        for _ in range(32)
    )
    oauth_timestamp = str(int(time.time()))

    parameters = {}
    parameters["oauth_nonce"] = oauth_nonce
    parameters["oauth_signature_method"] = "HMAC-SHA1"
    parameters["oauth_timestamp"] = oauth_timestamp
    parameters["oauth_consumer_key"] = os.environ['TWITTER_CONSUMER_KEY']
    parameters["oauth_version"] = "1.0"
    parameters["oauth_token"] = os.environ['TWITTER_OAUTH_TOKEN']

    for k, v in params.items():
        parameters[k] = v

    parameters["oauth_signature"] = _create_signature(parameters, http_method='GET', resource_url=resource_url)

    header_string = "OAuth "
    for k, v in sorted(parameters.items()):
        if k[:6] == "oauth_" and len(str(v)) > 0 and "callback" not in str(v):
            header_string += '%s="%s", ' % (quote(k), quote(v, ""))

    # get rid of last comma & space
    header_string = header_string[:-2]
    return header_string


def _check_rate_limiting(headers):
    """returns a number of seconds to sleep"""
    rate_limit_remaining = int(headers["x-rate-limit-remaining"])
    rate_limit_reset = int(headers["x-rate-limit-reset"])
    if rate_limit_remaining > 100:
        return 0

    seconds_remaining = rate_limit_reset - int(time.time())
    sleep_seconds = int(seconds_remaining / rate_limit_remaining)
    logger.debug("rate_limit_remaining: %d, seconds_remaining: %d, sleep_seconds: %d", rate_limit_remaining, seconds_remaining, sleep_seconds)
    if rate_limit_remaining < 20:
        logger.warning("%d remaining requests for the next %d seconds", rate_limit_remaining, seconds_remaining)

    return sleep_seconds

async def _call(client: httpx.AsyncClient, endpoint: str, **params):
    resource_url = f'{BASE_URL}/{endpoint}'
    headers = {
        "Authorization": _create_header_string(params, resource_url),
    }
    resp = await client.get(f"{BASE_URL}/{endpoint}", params=params, headers=headers)
    logger.info("got %s response from %s", resp.status_code, resp.url)
    if resp.status_code >= 400:
        logger.error('resp = %s', resp.json())
    if resp.status_code == 429:
        logger.error('rate limited')
        resp.raise_for_status()

    sleep_seconds = _check_rate_limiting(resp.headers)
    if sleep_seconds > 0:
        logger.warn('Slowing things down by %d seconds', sleep_seconds)
        await asyncio.sleep(sleep_seconds)

    return resp.json()


async def get_status(client, id: int):
    return await _call(client, "statuses/show.json", id=id)

async def lookup(client, ids: list):
    """lookup a bunch of ids at once"""
    if len(ids) > 100:
        raise ValueError('you cannot look up more than 100 ids')
    ids_str = ','.join(ids)
    return await _call(client, "statuses/lookup.json", id=ids_str)

async def main():
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    async with httpx.AsyncClient() as client:
        status = await get_status(client, 1172798764408614912)
        logger.debug(status)


if __name__ == "__main__":
    from asyncio import run

    run(main())
