"""
utils/virustotal.py
Проверка IP-адресов через VirusTotal API v3.
"""

import requests
import time
from typing import Optional

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Таймаут запроса в секундах
REQUEST_TIMEOUT = 10

# Лимит: бесплатный ключ = 4 запроса/мин
RATE_LIMIT_DELAY = 15  # секунд между запросами при батч-проверке


def check_ip(ip: str, api_key: str) -> dict:
    """
    Проверяет один IP-адрес через VirusTotal API v3.
    
    Возвращает словарь:
    {
        "ip": str,
        "malicious": int,       — кол-во движков, считающих вредоносным
        "suspicious": int,
        "harmless": int,
        "undetected": int,
        "total_votes_malicious": int,
        "country": str,
        "as_owner": str,        — провайдер / ASN owner
        "reputation": int,      — оценка сообщества (-100..100)
        "last_analysis_date": str,
        "error": str | None,
        "verdict": str,         — "clean" | "suspicious" | "malicious"
        "vt_link": str,
    }
    """
    result = {
        "ip": ip,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "total_votes_malicious": 0,
        "country": "N/A",
        "as_owner": "N/A",
        "reputation": 0,
        "last_analysis_date": "N/A",
        "error": None,
        "verdict": "unknown",
        "vt_link": f"https://www.virustotal.com/gui/ip-address/{ip}",
    }

    if not api_key or api_key.strip() == "":
        result["error"] = "API-ключ не указан"
        return result

    headers = {
        "x-apikey": api_key.strip(),
        "Accept": "application/json",
    }

    try:
        url = f"{VT_BASE_URL}/ip_addresses/{ip}"
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        
        if resp.status_code == 401:
            result["error"] = "Неверный API-ключ VirusTotal"
            return result
        if resp.status_code == 404:
            result["error"] = f"IP {ip} не найден в базе VirusTotal"
            return result
        if resp.status_code == 429:
            result["error"] = "Превышен лимит запросов VirusTotal (4/мин для бесплатного ключа)"
            return result
        if resp.status_code != 200:
            result["error"] = f"Ошибка API: HTTP {resp.status_code}"
            return result

        data = resp.json().get("data", {}).get("attributes", {})

        # Статистика движков
        stats = data.get("last_analysis_stats", {})
        result["malicious"]   = stats.get("malicious", 0)
        result["suspicious"]  = stats.get("suspicious", 0)
        result["harmless"]    = stats.get("harmless", 0)
        result["undetected"]  = stats.get("undetected", 0)

        # Голоса сообщества
        votes = data.get("total_votes", {})
        result["total_votes_malicious"] = votes.get("malicious", 0)

        # Геоданные и ASN
        result["country"]    = data.get("country", "N/A")
        result["as_owner"]   = data.get("as_owner", "N/A")
        result["reputation"] = data.get("reputation", 0)

        # Дата последнего анализа
        epoch = data.get("last_analysis_date")
        if epoch:
            from datetime import datetime
            result["last_analysis_date"] = datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%d %H:%M UTC")

        # Вердикт
        if result["malicious"] > 0:
            result["verdict"] = "malicious"
        elif result["suspicious"] > 0:
            result["verdict"] = "suspicious"
        else:
            result["verdict"] = "clean"

    except requests.Timeout:
        result["error"] = f"Таймаут запроса к VirusTotal (>{REQUEST_TIMEOUT}с)"
    except requests.ConnectionError:
        result["error"] = "Нет соединения с VirusTotal. Проверьте интернет."
    except Exception as e:
        result["error"] = f"Неожиданная ошибка: {e}"

    return result


def check_multiple_ips(ip_list: list, api_key: str, progress_callback=None) -> list:
    """
    Проверяет список IP-адресов с задержкой между запросами.
    
    progress_callback(i, total) — опциональный колбэк прогресса.
    Возвращает список словарей из check_ip().
    """
    results = []
    unique_ips = list(dict.fromkeys(ip_list))  # дедупликация с сохранением порядка

    for i, ip in enumerate(unique_ips):
        if progress_callback:
            progress_callback(i + 1, len(unique_ips))
        
        result = check_ip(ip, api_key)
        results.append(result)
        
        # Задержка, чтобы не превысить лимит бесплатного ключа
        if i < len(unique_ips) - 1:
            time.sleep(RATE_LIMIT_DELAY)

    return results


def verdict_badge(verdict: str) -> tuple[str, str]:
    """
    Возвращает (эмодзи, цвет) для вердикта.
    Используется в Streamlit для st.markdown / st.metric.
    """
    mapping = {
        "malicious":  ("🔴 Вредоносный", "#FF4B4B"),
        "suspicious": ("🟡 Подозрительный", "#FFA500"),
        "clean":      ("🟢 Чистый", "#00C896"),
        "unknown":    ("⚪ Неизвестно", "#808080"),
    }
    return mapping.get(verdict, mapping["unknown"])
