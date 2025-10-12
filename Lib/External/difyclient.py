from typing import Dict, Any

import requests

from CONFIG import DIFY_BASE_URL, DIFY_PROXY
from Lib.log import logger

requests.packages.urllib3.disable_warnings()


class DifyClient(object):
    def __init__(self):
        self.base_url = DIFY_BASE_URL

    def run_workflow(self, api_key: str, inputs: Dict[str, Any], user: str = "default_user") -> Dict[str, Any]:
        url = f"{self.base_url}/workflows/run"
        headers = {
            "Authorization": f"Bearer {api_key}",
        }
        payload = {
            "inputs": inputs,
            "response_mode": "blocking",
            "user": user
        }
        proxies = None
        if DIFY_PROXY:
            proxies = {
                "http": DIFY_PROXY,
                "https": DIFY_PROXY,
            }
        try:
            response = requests.post(url,
                                     headers=headers,
                                     json=payload,
                                     proxies=proxies,
                                     )
            response.raise_for_status()

            response_data = response.json()
            logger.debug(f"Dify API response: {response_data}")

            data = response_data.get("data", {})
            if data and data.get("status") == "succeeded":
                outputs = data.get("outputs")
                return outputs
            else:
                return {}
        except Exception as e:
            raise
