import re
import constants
import aiohttp
import logging

async def _check_hash(hash_str: str) -> str:
    """
    Checks whether the given hash is a valid MD5 or SHA-256 hash.
    Returns the hash type as a string ('md5', 'sha256') or 'invalid' if not valid.
    """
    hash_str = hash_str.lower()
    if re.fullmatch(r'[a-f0-9A-F]{32}', hash_str):
        return 'md5_hash'
    elif re.fullmatch(r'[a-f0-9A-F]{64}', hash_str):
        return 'sha256_hash'
    else:
        return 'invalid'
    
async def _format_url(url: str) -> str:
    if not re.match(r'^http.*?\:\/\/', url, re.IGNORECASE):
        url = 'http://' + url
    return url

async def _make_abusech_http_request(
    url: str,
    req_params: dict = None,
    req_data: dict = None,
    req_headers: dict = None,
    is_req_data_json: bool = False,
) -> dict:
    
    headers = {
        'User-Agent': 'abusech-mcp-server/1.0',
        'Accept': 'application/json',
        'Auth-Key': constants.ABUSECH_API_KEY,
    }
    if req_headers:
        headers.update(req_headers)

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            logging.debug(f"Making POST request to {url} with params: {req_params} and data: {req_data}")

            if is_req_data_json:
                async with session.post(url, params=req_params, json=req_data, ssl=False) as response:
                    return await response.json()
            else:
                async with session.post(url, params=req_params, data=req_data, ssl=False) as response:
                    return await response.json()
    
    except aiohttp.ClientError as e:
        logging.error(f"HTTP request failed to abusech url {url}: {e}")
        return {
            'error': f'Network/API error: {e}'
        }
    
    except Exception as e:
        logging.error(f"Unexpected error during HTTP request to abusech url {url}: {e}")
        return {
            'error': f'Unexpected error: {e}'
        }