import requests

from PLUGINS.AlienVaultOTX.CONFIG import API_KEY, HTTP_PROXY


class AlienVaultOTX(object):
    def __init__(self):
        """初始化 AlienVaultOTX，设置 API 密钥和基础 URL"""
        self.api_key = API_KEY
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {
            "accept": "application/json",
            "X-OTX-API-KEY": self.api_key
        }

    def query_ip(self, ip: str) -> dict:
        """查询 IP 的情报信息"""
        url = f"{self.base_url}/indicators/IPv4/{ip}/general"
        req_result = self._get(url)
        req_result["reputation_score"] = self.calculate_reputation_score(req_result)  # 在返回结果中添加
        return req_result

    def query_url(self, url: str) -> dict:
        """查询 URL 的情报信息（不主动请求目标 URL）"""
        try:
            # URL 编码避免路径参数导致接口异常
            encoded_url = requests.utils.quote(url, safe='')
            otx_url = f"{self.base_url}/indicators/url/{encoded_url}/general"

            # 在返回结果中额外保存原始URL
            result = self._get(otx_url)
            if result and not result.get('error'):
                result['original_url'] = url
            return result
        except Exception as e:
            return {"error": str(e)}

    def query_file(self, file_hash: str) -> dict:
        """查询文件哈希的情报信息（支持 MD5、SHA1、SHA256）"""
        # 根据哈希长度确定类型
        hash_length = len(file_hash)
        if hash_length == 32:
            hash_type = "MD5"
        elif hash_length == 40:
            hash_type = "SHA1"
        elif hash_length == 64:
            hash_type = "SHA256"
        else:
            return {"error": "Invalid hash length. Must be 32 (MD5), 40 (SHA1), or 64 (SHA256)."}

        url = f"{self.base_url}/indicators/file/{file_hash}/general"
        req_result = self._get(url)
        req_result["reputation_score"] = self.calculate_reputation_score(req_result)  # 在返回结果中添加
        return req_result

    def _get(self, url: str) -> dict:
        """通用 GET 请求方法"""
        try:
            if HTTP_PROXY is not None:
                proxies = {
                    "http": HTTP_PROXY,
                    "https": HTTP_PROXY,
                }
            else:
                proxies = None
            resp = requests.get(url, headers=self.headers, proxies=proxies, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            return {"error": str(e)}

    def calculate_reputation_score(self, attributes: dict) -> int:
        """
        重新计算OTX的reputation分值（简化版）

        Returns:
            int: reputation分值
            - 负数: 有风险
            - 0或正数: 无风险/低风险
        """
        score = 0

        # 1. 脉冲信息分析（核心指标）
        pulse_info = attributes.get('pulse_info', {})
        pulse_count = pulse_info.get('count', 0)
        pulses = pulse_info.get('pulses', [])

        # 脉冲数量越多说明被更多威胁情报引用
        score -= pulse_count * 10  # 每个脉冲 -10分

        # 2. 相关威胁信息
        related = pulse_info.get('related', {})

        # 恶意软件家族
        malware_families = related.get('alienvault', {}).get('malware_families', []) + \
                           related.get('other', {}).get('malware_families', [])
        score -= len(malware_families) * 15  # 每个恶意软件家族 -15分

        # 对手/攻击者
        adversaries = related.get('alienvault', {}).get('adversary', []) + \
                      related.get('other', {}).get('adversary', [])
        score -= len(adversaries) * 12  # 每个攻击者 -12分

        # 3. 验证信息
        validation = attributes.get('validation', [])
        for val in validation:
            if val.get('name') == 'whitelist':
                score += 20  # 白名单 +20分
            elif val.get('name') == 'blacklist':
                score -= 25  # 黑名单 -25分

        # 4. 误报标记
        false_positive = attributes.get('false_positive', [])
        if false_positive:
            score += len(false_positive) * 10  # 每个误报标记 +10分

        # 5. 脉冲详细分析
        for pulse in pulses:
            # 检查脉冲标签中的威胁关键词
            tags = pulse.get('tags', [])
            threat_tags = ['malware', 'trojan', 'backdoor', 'botnet', 'apt', 'exploit']
            for tag in tags:
                if tag.lower() in threat_tags:
                    score -= 8  # 每个威胁标签 -8分

        return -score


def ip_reputation_by_alien_vault(ip: str) -> int:
    """使用 AlienVaultOTX 查询 IP 的威胁情报分数,分数越高风险越大"""
    score = AlienVaultOTX().query_ip(ip)
    return score


if __name__ == "__main__":
    avotx = AlienVaultOTX()
    target_ip = "66.240.205.34"
    result = avotx.query_ip(target_ip)
