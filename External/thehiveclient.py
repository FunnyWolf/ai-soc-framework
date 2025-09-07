from thehive4py import TheHiveApi
from thehive4py.types.alert import InputAlert, OutputAlert

from CONFIG import THEHIVE_URL, THEHIVE_API_KEY


class TheHiveClient(object):
    def __init__(self):
        self.hive = TheHiveApi(
            url=THEHIVE_URL,
            apikey=THEHIVE_API_KEY,
            verify=False
        )

    def alert_create(self, alert_data: InputAlert):
        try:
            ouput_alert: OutputAlert = self.hive.alert.create(alert=alert_data)
            return ouput_alert
        except Exception as e:
            print(f"Error creating alert: {e}")
            return None
