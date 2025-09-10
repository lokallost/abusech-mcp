import schemas
import utils
import constants

async def _get_malwarebazaar_hash_report(
    hash_value: str
) -> schemas.MalwareBazaarHashReport | dict:
    """
        Fetches the MalwareBazaar report for a given hash value.
    """
    response = await utils._make_abusech_http_request(
        url=f'{constants.MALWAREBAZAAR_API_URL}/',
        req_data={
            'query': 'get_info',
            'hash': hash_value
        },
        is_req_data_json=False
    )
    
    query_status = response.get('query_status')
    if query_status != 'ok':
        return schemas.MalwareBazaarHashReport()
    
    file_info = response.get('data', [None])[0]
    if not file_info:
        return schemas.MalwareBazaarHashReport()
    
    malwarebazaar_report = schemas.MalwareBazaarHashReport(**file_info)
    return malwarebazaar_report

async def _get_urlhaus_hash_report(
    hash_type: str,
    hash_value: str,
) -> schemas.URLhausHashReport | dict:
    """
        Fetches the URLhaus report for a given hash value.
    """
    response = await utils._make_abusech_http_request(
        url=f'{constants.URLHAUS_API_URL}/payload/',
        req_data={
            hash_type: hash_value
        },
        is_req_data_json=False
    )

    query_status = response.get('query_status')
    if query_status != 'ok':
        return schemas.URLhausHashReport()
    
    urlhaus_report = schemas.URLhausHashReport(**response)

    # only keeping the first 20 items in the urls list to avoid large responses
    if urlhaus_report.urls and len(urlhaus_report.urls) > 20:
        urlhaus_report.urls = urlhaus_report.urls[:20]

    return urlhaus_report

async def _get_threatfox_hash_report(
    hash_value: str,
) -> schemas.ThreatFoxHashReport:
    """
        Fetches the ThreatFox report for a given hash value.
    """
    response = await utils._make_abusech_http_request(
        url=f'{constants.THREATFOX_API_URL}/',
        req_data={
            'query': 'search_hash',
            'hash': hash_value
        },
        is_req_data_json=True
    )
    
    query_status = response.get('query_status')
    if query_status != 'ok':
        return schemas.ThreatFoxHashReport()

    hash_info = response.get('data')
    if not hash_info:
        return schemas.ThreatFoxHashReport()
    
    threatfox_report = schemas.ThreatFoxHashReport(**response)
    # only keeping the first 20 items in the urls list to avoid large responses
    if threatfox_report.data and len(threatfox_report.data) > 20:
        threatfox_report.data = threatfox_report.data[:20]

    return threatfox_report

