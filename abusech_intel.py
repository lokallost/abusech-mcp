import asyncio
import file_helpers
import schemas
import utils
import ioc_helpers


async def _get_file_report(
    hash_value: str
) -> dict:
    """
        Name: Get File Report
        Description: Get a comprehensive file report using its hash (MD5/SHA-1/SHA-256) from MalwareBazaar, URLhaus (only MD5/SHA-256), and ThreatFox
        Parameters:
            - hash: The hash of the file to retrieve the report for (MD5/SHA-1/SHA-256)
    """

    hash_type = await utils._check_hash(hash_value)
    if hash_type == 'invalid':
        return {
            'error': 'Invalid hash format. Please provide a valid MD5 or SHA-256 hash.'
        }

    malwarebazaar_task = file_helpers._get_malwarebazaar_hash_report(
        hash_value=hash_value
    )

    urlhaus_task = file_helpers._get_urlhaus_hash_report(
        hash_type=hash_type,
        hash_value=hash_value
    )

    threatfox_task = file_helpers._get_threatfox_hash_report(
        hash_value=hash_value
    )

    malwarebazaar_report, urlhaus_report, threatfox_report = await asyncio.gather(
        malwarebazaar_task, urlhaus_task, threatfox_task
    )

    print(malwarebazaar_report.model_dump())
    print(urlhaus_report.model_dump())
    print(threatfox_report.model_dump())

    file_report = schemas.FileReport(
        md5_hash=malwarebazaar_report.md5_hash or urlhaus_report.md5_hash,
        sha256_hash=malwarebazaar_report.sha256_hash or urlhaus_report.sha256_hash,
        file_name=malwarebazaar_report.file_name,
        file_size=malwarebazaar_report.file_size or urlhaus_report.file_size,
        file_type=malwarebazaar_report.file_type or urlhaus_report.file_type,
        file_type_mime=malwarebazaar_report.file_type_mime,
        signature=malwarebazaar_report.signature,
        imphash=malwarebazaar_report.imphash or urlhaus_report.imphash,
        tlsh=malwarebazaar_report.tlsh or urlhaus_report.tlsh,
        ssdeep=malwarebazaar_report.ssdeep or urlhaus_report.ssdeep,
        magika=malwarebazaar_report.magika or urlhaus_report.magika,
        trid=malwarebazaar_report.trid,
        archive_pw=malwarebazaar_report.archive_pw,
        code_sign=malwarebazaar_report.code_sign,
        delivery_method=malwarebazaar_report.delivery_method,
        virustotal=urlhaus_report.virustotal,
        malwarebazaar_yara_rules=malwarebazaar_report.yara_rules,
        malwarebazaar_vendor_intel=malwarebazaar_report.vendor_intel,
        malwarebazaar_comments=malwarebazaar_report.comments,
        urlhaus_url_count=urlhaus_report.url_count,
        urlhaus_download=urlhaus_report.urlhaus_download,
        urlhaus_related_urls=urlhaus_report.urls,
        threatfox_related_iocs=threatfox_report.data,   
    )

    return file_report.model_dump()

async def _get_url_report(
    url: str
) -> dict:
    """
        Name: Get URL Report
        Description: Get a comprehensive URL report from URLhaus and ThreatFox
        Parameters:
            - url: The URL to retrieve the report for
    """

    url = await utils._format_url(url)

    urlhaus_report = await ioc_helpers._get_urlhaus_url_report(
        url=url
    )

    url_report = schemas.UrlReport(
        url=urlhaus_report.url,
        url_status=urlhaus_report.url_status,
        host=urlhaus_report.host,
        date_added=urlhaus_report.date_added,
        last_online=urlhaus_report.last_online,
        threat=urlhaus_report.threat,
        blacklists=urlhaus_report.blacklists,
        urlhaus_tags=urlhaus_report.tags,
        related_payloads=urlhaus_report.payloads
    )

    return url_report.model_dump()

async def _get_ip_report(
    ip: str
) -> dict:
    """
        Name: Get IP Report
        Description: Get a comprehensive IP report from URLhaus and ThreatFox
        Parameters:
            - ip: The IP address to retrieve the report for
    """

    urlhaus_task = ioc_helpers._get_urlhaus_host_report(
        ioc=ip
    )
    threatfox_task = ioc_helpers._get_threatfox_ioc_report(
        ioc=ip
    )
    urlhaus_report, threatfox_report = await asyncio.gather(
        urlhaus_task, threatfox_task
    )

    ip_report = schemas.IpReport(
        urlhaus_host=urlhaus_report.host,
        urlhaus_firstseen=urlhaus_report.firstseen,
        urlhaus_url_count=urlhaus_report.url_count,
        urlhaus_blacklists=urlhaus_report.blacklists,
        urlhaus_related_urls=urlhaus_report.urls,
        threatfox_related_iocs=threatfox_report.data,
    )
    return ip_report.model_dump()

async def _get_domain_report(
    domain: str
) -> dict:
    """
        Name: Get Domain Report
        Description: Get a comprehensive Domain report from URLhaus and ThreatFox
        Parameters:
            - domain: The domain to retrieve the report for
    """

    urlhaus_task = ioc_helpers._get_urlhaus_host_report(
        ioc=domain
    )
    threatfox_task = ioc_helpers._get_threatfox_ioc_report(
        ioc=domain
    )
    urlhaus_report, threatfox_report = await asyncio.gather(
        urlhaus_task, threatfox_task
    )

    domain_report = schemas.DomainReport(
        urlhaus_host=urlhaus_report.host,
        urlhaus_firstseen=urlhaus_report.firstseen,
        urlhaus_url_count=urlhaus_report.url_count,
        urlhaus_blacklists=urlhaus_report.blacklists,
        urlhaus_related_urls=urlhaus_report.urls,
        threatfox_related_iocs=threatfox_report.data,
    )
    return domain_report.model_dump()
