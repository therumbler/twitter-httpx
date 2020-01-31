"""asyncio TWitter library using HTTPX"""
import logging
import os
import random
import string
import sys
import time

import httpx

BASE_URL = "https://api.twitter.com/1.1"

logger = logging.getLogger(__name__)

def _get_base_url(self, full_url):
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

    signing_key = self.consumer_secret + "&" + os.environ['TWITTER_OAUTH_TOEKN_SECRET']

    return base64.b64encode(hmac.new(signing_key, signature_base_string, hashlib.sha1).digest())

def _create_header_string(params: dict):
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

    parameters["oauth_signature"] = _create_signature(parameters)

    header_string = "OAuth "
    for k, v in sorted(parameters.items()):
        if k[:6] == "oauth_" and len(v) > 0 and "callback" not in v:
            header_string += '%s="%s", ' % (quote(k), quote(v, ""))

    # get rid of last comma & space
    header_string = header_string[:-2]
    return header_string


async def _call(client: httpx.AsyncClient, endpoint: str, **params):
    headers = {
        "Authorization": _create_header_string(params),
    }
    resp = await client.get(f"{BASE_URL}/{endpoint}", params=params, headers=headers)
    logger.debug("got response from %s", str(dir(resp)))
    logger.debug("got %s response from %s", resp.status_code, resp.url)

    return resp.json()


async def get_status(client, id: int):
    return await _call(client, "statuses/show.json", id=id)


async def main():
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    async with httpx.AsyncClient() as client:
        status = await get_status(client, 1172798764408614912)
        logger.debug(status)


if __name__ == "__main__":
    from asyncio import run

    run(main())
