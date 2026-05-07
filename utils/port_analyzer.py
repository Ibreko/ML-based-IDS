"""
utils/port_analyzer.py
Анализ портов: подсветка критически важных портов и категоризация угроз.
"""

import pandas as pd
from typing import Optional

# ------------------------------------------------------------------ #
#  База данных критических портов                                     #
# ------------------------------------------------------------------ #

CRITICAL_PORTS = {
    # === Удалённый доступ ===
    22:    {"name": "SSH",          "category": "Remote Access",    "risk": "HIGH",     "icon": "🔐", "color": "#FF6347",
            "note": "Брутфорс, несанкционированный доступ"},
    23:    {"name": "Telnet",       "category": "Remote Access",    "risk": "CRITICAL", "icon": "⚠️", "color": "#FF0000",
            "note": "Незашифрованный протокол. Использование крайне нежелательно"},
    3389:  {"name": "RDP",          "category": "Remote Access",    "risk": "CRITICAL", "icon": "🖥️", "color": "#FF0000",
            "note": "BlueKeep, DejaBlue — частая цель для ransomware"},
    5900:  {"name": "VNC",          "category": "Remote Access",    "risk": "HIGH",     "icon": "🔐", "color": "#FF6347",
            "note": "Уязвимости аутентификации, перехват сессий"},

    # === Файловый обмен / SMB ===
    445:   {"name": "SMB",          "category": "File Sharing",     "risk": "CRITICAL", "icon": "📁", "color": "#FF0000",
            "note": "EternalBlue, WannaCry, NotPetya — критический вектор"},
    139:   {"name": "NetBIOS",      "category": "File Sharing",     "risk": "HIGH",     "icon": "📁", "color": "#FF6347",
            "note": "NetBIOS-атаки, перечисление ресурсов"},
    2049:  {"name": "NFS",          "category": "File Sharing",     "risk": "MEDIUM",   "icon": "📂", "color": "#FFA500",
            "note": "Монтирование чужих файловых систем"},

    # === База данных ===
    1433:  {"name": "MSSQL",        "category": "Database",         "risk": "HIGH",     "icon": "🗄️", "color": "#FF6347",
            "note": "SQL-инъекции, брутфорс учётных данных"},
    1521:  {"name": "Oracle DB",    "category": "Database",         "risk": "HIGH",     "icon": "🗄️", "color": "#FF6347",
            "note": "Удалённые эксплойты Oracle"},
    3306:  {"name": "MySQL",        "category": "Database",         "risk": "HIGH",     "icon": "🗄️", "color": "#FF6347",
            "note": "Прямой доступ к БД без авторизации"},
    5432:  {"name": "PostgreSQL",   "category": "Database",         "risk": "MEDIUM",   "icon": "🗄️", "color": "#FFA500",
            "note": "Несанкционированное чтение/запись данных"},
    6379:  {"name": "Redis",        "category": "Database",         "risk": "HIGH",     "icon": "🗄️", "color": "#FF6347",
            "note": "Redis без пароля — частый вектор компрометации"},
    27017: {"name": "MongoDB",      "category": "Database",         "risk": "HIGH",     "icon": "🗄️", "color": "#FF6347",
            "note": "Открытые MongoDB-инстансы — утечки данных"},

    # === Веб ===
    80:    {"name": "HTTP",         "category": "Web",              "risk": "MEDIUM",   "icon": "🌐", "color": "#FFA500",
            "note": "XSS, SQLi, незашифрованная передача данных"},
    443:   {"name": "HTTPS",        "category": "Web",              "risk": "LOW",      "icon": "🔒", "color": "#4CAF50",
            "note": "Стандартный веб-трафик; внимание на TLS-версии"},
    8080:  {"name": "HTTP Alt",     "category": "Web",              "risk": "MEDIUM",   "icon": "🌐", "color": "#FFA500",
            "note": "Часто используется прокси и dev-серверами"},
    8443:  {"name": "HTTPS Alt",    "category": "Web",              "risk": "LOW",      "icon": "🔒", "color": "#4CAF50",
            "note": "Альтернативный HTTPS"},

    # === Почта ===
    25:    {"name": "SMTP",         "category": "Mail",             "risk": "MEDIUM",   "icon": "📧", "color": "#FFA500",
            "note": "Open Relay, спам-рассылки, фишинг"},
    110:   {"name": "POP3",         "category": "Mail",             "risk": "MEDIUM",   "icon": "📧", "color": "#FFA500",
            "note": "Перехват почты, brute-force"},
    143:   {"name": "IMAP",         "category": "Mail",             "risk": "MEDIUM",   "icon": "📧", "color": "#FFA500",
            "note": "Перехват сессий, кража почты"},

    # === DNS / SNMP ===
    53:    {"name": "DNS",          "category": "Network",          "risk": "MEDIUM",   "icon": "🌍", "color": "#FFA500",
            "note": "DNS Amplification DDoS, DNS Cache Poisoning"},
    161:   {"name": "SNMP",         "category": "Network",          "risk": "HIGH",     "icon": "📡", "color": "#FF6347",
            "note": "Community string brute-force, утечка конфигурации"},

    # === Другое ===
    21:    {"name": "FTP",          "category": "File Transfer",    "risk": "HIGH",     "icon": "📤", "color": "#FF6347",
            "note": "Незашифрованная передача, Anonymous FTP"},
    69:    {"name": "TFTP",         "category": "File Transfer",    "risk": "HIGH",     "icon": "📤", "color": "#FF6347",
            "note": "Без аутентификации, загрузка произвольных файлов"},
    2375:  {"name": "Docker API",   "category": "Infrastructure",   "risk": "CRITICAL", "icon": "🐳", "color": "#FF0000",
            "note": "Открытый Docker socket — полный контроль хоста"},
    6443:  {"name": "Kubernetes API","category": "Infrastructure",  "risk": "CRITICAL", "icon": "☸️", "color": "#FF0000",
            "note": "Несанкционированный доступ к K8s кластеру"},
}

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


# ------------------------------------------------------------------ #
#  Основные функции                                                   #
# ------------------------------------------------------------------ #

def get_port_info(port: int) -> Optional[dict]:
    """
    Возвращает информацию о порте или None, если порт не критический.
    """
    return CRITICAL_PORTS.get(port)


def is_critical_port(port: int) -> bool:
    """Проверяет, является ли порт критически важным."""
    return port in CRITICAL_PORTS


def analyze_ports(df: pd.DataFrame,
                  src_port_col: str = "_src_port",
                  dst_port_col: str = "_dst_port") -> pd.DataFrame:
    """
    Принимает DataFrame с колонками портов и добавляет информацию об угрозах.
    
    Анализирует dst_port (целевой порт), так как именно он определяет атаку.
    Возвращает DataFrame только с критическими соединениями.
    """
    port_col = dst_port_col if dst_port_col in df.columns else src_port_col
    if port_col not in df.columns:
        return pd.DataFrame()

    # Фильтруем критические порты
    mask = df[port_col].apply(lambda p: is_critical_port(int(p)) if pd.notna(p) else False)
    critical_df = df[mask].copy()

    if critical_df.empty:
        return critical_df

    # Добавляем информацию о порте
    port_details = critical_df[port_col].apply(lambda p: get_port_info(int(p)) or {})
    detail_df = pd.DataFrame(port_details.tolist(), index=critical_df.index)

    for col in ["name", "category", "risk", "icon", "note"]:
        if col in detail_df.columns:
            critical_df[f"port_{col}"] = detail_df[col]

    critical_df["target_port"] = critical_df[port_col]
    return critical_df.sort_values("target_port")


def port_risk_summary(df: pd.DataFrame, dst_port_col: str = "_dst_port") -> list[dict]:
    """
    Возвращает список уникальных атакованных критических портов с метрикой.
    Отсортирован по уровню риска (CRITICAL → LOW).
    """
    if dst_port_col not in df.columns:
        return []

    counts = df[dst_port_col].value_counts()
    result = []

    for port, count in counts.items():
        try:
            port_int = int(port)
        except (ValueError, TypeError):
            continue

        info = get_port_info(port_int)
        if info:
            result.append({
                "port":     port_int,
                "count":    count,
                **info,
            })

    result.sort(key=lambda x: RISK_ORDER.get(x["risk"], 99))
    return result


def get_all_critical_ports_df() -> pd.DataFrame:
    """
    Возвращает справочник всех критических портов в виде DataFrame.
    Полезно для отображения в UI.
    """
    rows = []
    for port, info in CRITICAL_PORTS.items():
        rows.append({"port": port, **info})
    return pd.DataFrame(rows).sort_values("risk", key=lambda s: s.map(RISK_ORDER))
