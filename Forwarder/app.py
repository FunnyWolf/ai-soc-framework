from flask import Flask, request, jsonify

from CONFIG import FLASK_LISTEN_PORT, FLASK_LISTEN_HOST
from Forwarder.log import logger
from Lib.redis_stream_api import RedisStreamAPI

redis_stream_api = RedisStreamAPI()
app = Flask(__name__)


@app.route("/api/v1/webhook/splunk", methods=["POST"])
def receive_splunk_webhook():
    if not request.is_json:
        return jsonify({"status": "error", "message": "Request must be JSON"}), 400

    data = request.get_json()

    result = data.pop('result', {})
    search_name = data.get('search_name')
    sid = data.get('sid')
    host = data.get('app')
    owner = data.get('owner')
    results_link = data.get('results_link')

    logger.info(f"Splunk webhook: {data}")
    redis_stream_api.send_message(search_name, result)
    logger.info("Message sent to Redis stream")
    # 5. 返回成功响应
    return jsonify({"status": "success", "message": "Webhook received"}), 200


@app.route("/api/v1/webhook/kibana", methods=["POST"])
def receive_kibana_webhook():
    if not request.is_json:
        return jsonify({"status": "error", "message": "Request must be JSON"}), 400

    data = request.get_json()
    rule_name = data.get('rule').get("name")
    hits = data.get('context').get("hits")
    for hit in hits:
        _source = hit.pop('_source', {})
        logger.info(f"elasticsearch webhook: {hit}")
        redis_stream_api.send_message(rule_name, _source)
        logger.info("Message sent to Redis stream")
    # 5. 返回成功响应
    return jsonify({"status": "success", "message": "Webhook received"}), 200


@app.route("/")
def index():
    return "Forwarder is running"


if __name__ == '__main__':
    logger.info(f"Starting Flask server on http://{FLASK_LISTEN_HOST}:{FLASK_LISTEN_PORT}")
    logger.info(f"Splunk Webhook URL : http://{FLASK_LISTEN_HOST}:{FLASK_LISTEN_PORT}/api/v1/webhook/splunk")
    logger.info(f"Kibana Webhook URL : http://{FLASK_LISTEN_HOST}:{FLASK_LISTEN_PORT}/api/v1/webhook/kibana")
    app.run(host=FLASK_LISTEN_HOST, port=FLASK_LISTEN_PORT)
