import requests

from CONFIG import NOCODB_URL, NOCODB_TOKEN, NOCODB_ALERT_TABLE_ID


class NocodbClient(object):
    def __init__(self):
        pass

    @staticmethod
    def create_alert(record: dict):
        headers = {"xc-token": NOCODB_TOKEN}
        url = f"{NOCODB_URL}/api/v2/tables/{NOCODB_ALERT_TABLE_ID}/records"

        try:
            response = requests.post(url,
                                     headers=headers,
                                     json=record)
            response.raise_for_status()

            response_data = response.json()
            return response_data
        except Exception as e:
            raise
