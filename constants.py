import sys
import logging
import os

ABUSECH_API_KEY = os.environ.get('ABUSECH_API_KEY')

if not ABUSECH_API_KEY:
    logging.error("ABUSECH_API_KEY environment variable not set.")
    sys.exit(1)

MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1"
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1"