"""
utils/mitre_mapper.py
Маппинг аномалий IDS на техники MITRE ATT&CK.
"""

# Словарь: тип атаки (из датасета KDD/NSL-KDD) -> техники MITRE ATT&CK
MITRE_MAPPING = {
    # DoS-атаки
    "neptune":   {"id": "T1498",   "name": "Network Denial of Service",          "tactic": "Impact",            "url": "https://attack.mitre.org/techniques/T1498/"},
    "smurf":     {"id": "T1498",   "name": "Network Denial of Service",          "tactic": "Impact",            "url": "https://attack.mitre.org/techniques/T1498/"},
    "pod":       {"id": "T1499",   "name": "Endpoint Denial of Service",         "tactic": "Impact",            "url": "https://attack.mitre.org/techniques/T1499/"},
    "teardrop":  {"id": "T1499",   "name": "Endpoint Denial of Service",         "tactic": "Impact",            "url": "https://attack.mitre.org/techniques/T1499/"},
    "land":      {"id": "T1498",   "name": "Network Denial of Service",          "tactic": "Impact",            "url": "https://attack.mitre.org/techniques/T1498/"},
    "back":      {"id": "T1499",   "name": "Endpoint Denial of Service",         "tactic": "Impact",            "url": "https://attack.mitre.org/techniques/T1499/"},
    "apache2":   {"id": "T1499.002","name": "Service Exhaustion Flood",          "tactic": "Impact",            "url": "https://attack.mitre.org/techniques/T1499/002/"},
    "udpstorm":  {"id": "T1498.001","name": "Direct Network Flood",              "tactic": "Impact",            "url": "https://attack.mitre.org/techniques/T1498/001/"},
    "processtable":{"id": "T1499", "name": "Endpoint Denial of Service",         "tactic": "Impact",            "url": "https://attack.mitre.org/techniques/T1499/"},
    "mailbomb":  {"id": "T1498",   "name": "Network Denial of Service",          "tactic": "Impact",            "url": "https://attack.mitre.org/techniques/T1498/"},

    # Probe / Reconnaissance
    "satan":     {"id": "T1046",   "name": "Network Service Discovery",          "tactic": "Discovery",         "url": "https://attack.mitre.org/techniques/T1046/"},
    "ipsweep":   {"id": "T1046",   "name": "Network Service Discovery",          "tactic": "Discovery",         "url": "https://attack.mitre.org/techniques/T1046/"},
    "portsweep": {"id": "T1046",   "name": "Network Service Discovery",          "tactic": "Discovery",         "url": "https://attack.mitre.org/techniques/T1046/"},
    "nmap":      {"id": "T1595.001","name": "Active Scanning: Scanning IP Blocks","tactic": "Reconnaissance",   "url": "https://attack.mitre.org/techniques/T1595/001/"},
    "mscan":     {"id": "T1595",   "name": "Active Scanning",                    "tactic": "Reconnaissance",    "url": "https://attack.mitre.org/techniques/T1595/"},
    "saint":     {"id": "T1595",   "name": "Active Scanning",                    "tactic": "Reconnaissance",    "url": "https://attack.mitre.org/techniques/T1595/"},

    # R2L — Remote to Local
    "guess_passwd":{"id": "T1110", "name": "Brute Force",                        "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1110/"},
    "ftp_write": {"id": "T1190",   "name": "Exploit Public-Facing Application",  "tactic": "Initial Access",    "url": "https://attack.mitre.org/techniques/T1190/"},
    "imap":      {"id": "T1110",   "name": "Brute Force",                        "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1110/"},
    "phf":       {"id": "T1190",   "name": "Exploit Public-Facing Application",  "tactic": "Initial Access",    "url": "https://attack.mitre.org/techniques/T1190/"},
    "multihop":  {"id": "T1090",   "name": "Proxy",                              "tactic": "Command and Control","url": "https://attack.mitre.org/techniques/T1090/"},
    "warezmaster":{"id": "T1105",  "name": "Ingress Tool Transfer",              "tactic": "Command and Control","url": "https://attack.mitre.org/techniques/T1105/"},
    "warezclient":{"id": "T1105",  "name": "Ingress Tool Transfer",              "tactic": "Command and Control","url": "https://attack.mitre.org/techniques/T1105/"},
    "spy":       {"id": "T1056",   "name": "Input Capture",                      "tactic": "Collection",        "url": "https://attack.mitre.org/techniques/T1056/"},
    "snmpgetattack":{"id": "T1602","name": "Data from Configuration Repository", "tactic": "Collection",        "url": "https://attack.mitre.org/techniques/T1602/"},
    "named":     {"id": "T1190",   "name": "Exploit Public-Facing Application",  "tactic": "Initial Access",    "url": "https://attack.mitre.org/techniques/T1190/"},
    "xlock":     {"id": "T1190",   "name": "Exploit Public-Facing Application",  "tactic": "Initial Access",    "url": "https://attack.mitre.org/techniques/T1190/"},
    "xsnoop":    {"id": "T1125",   "name": "Video Capture",                      "tactic": "Collection",        "url": "https://attack.mitre.org/techniques/T1125/"},
    "sendmail":  {"id": "T1534",   "name": "Internal Spearphishing",             "tactic": "Lateral Movement",  "url": "https://attack.mitre.org/techniques/T1534/"},
    "httptunnel":{"id": "T1572",   "name": "Protocol Tunneling",                 "tactic": "Command and Control","url": "https://attack.mitre.org/techniques/T1572/"},
    "worm":      {"id": "T1587.001","name": "Malware Development",               "tactic": "Resource Development","url": "https://attack.mitre.org/techniques/T1587/001/"},

    # U2R — User to Root (Privilege Escalation)
    "buffer_overflow":{"id": "T1203","name": "Exploitation for Client Execution","tactic": "Execution",         "url": "https://attack.mitre.org/techniques/T1203/"},
    "loadmodule":{"id": "T1547",   "name": "Boot or Logon Autostart Execution",  "tactic": "Persistence",       "url": "https://attack.mitre.org/techniques/T1547/"},
    "perl":      {"id": "T1059.006","name": "Command and Scripting: Perl",       "tactic": "Execution",         "url": "https://attack.mitre.org/techniques/T1059/006/"},
    "rootkit":   {"id": "T1014",   "name": "Rootkit",                            "tactic": "Defense Evasion",   "url": "https://attack.mitre.org/techniques/T1014/"},
    "ps":        {"id": "T1057",   "name": "Process Discovery",                  "tactic": "Discovery",         "url": "https://attack.mitre.org/techniques/T1057/"},
    "sqlattack": {"id": "T1190",   "name": "Exploit Public-Facing Application",  "tactic": "Initial Access",    "url": "https://attack.mitre.org/techniques/T1190/"},
    "xterm":     {"id": "T1059",   "name": "Command and Scripting Interpreter",  "tactic": "Execution",         "url": "https://attack.mitre.org/techniques/T1059/"},

    # Общая аномалия (когда тип атаки неизвестен)
    "anomaly":   {"id": "T1040",   "name": "Network Sniffing / Unknown Anomaly", "tactic": "Discovery",         "url": "https://attack.mitre.org/techniques/T1040/"},
}

# Цвета для тактик
TACTIC_COLORS = {
    "Impact":              "#FF4B4B",
    "Discovery":           "#FFA500",
    "Reconnaissance":      "#FFD700",
    "Credential Access":   "#FF69B4",
    "Initial Access":      "#FF6347",
    "Command and Control": "#9370DB",
    "Collection":          "#20B2AA",
    "Lateral Movement":    "#4169E1",
    "Execution":           "#DC143C",
    "Persistence":         "#8B4513",
    "Defense Evasion":     "#2E8B57",
    "Resource Development":"#708090",
    "Unknown":             "#808080",
}


def map_to_mitre(attack_type: str) -> dict:
    """
    Возвращает словарь с деталями MITRE ATT&CK для заданного типа атаки.
    Если тип не найден — возвращает запись для общей аномалии.
    """
    key = attack_type.strip().lower()
    result = MITRE_MAPPING.get(key, MITRE_MAPPING["anomaly"])
    result = dict(result)  # копия, чтобы не менять оригинал
    result["attack_type"] = attack_type
    result["color"] = TACTIC_COLORS.get(result["tactic"], TACTIC_COLORS["Unknown"])
    return result


def enrich_dataframe(df, attack_col: str = "attack_type"):
    """
    Принимает DataFrame с колонкой типов атак и добавляет колонки MITRE.
    Возвращает обогащённый DataFrame.
    """
    import pandas as pd

    if attack_col not in df.columns:
        raise ValueError(f"Колонка '{attack_col}' не найдена в DataFrame.")

    mapped = df[attack_col].apply(map_to_mitre)
    mitre_df = pd.DataFrame(mapped.tolist())

    enriched = pd.concat([
        df.reset_index(drop=True),
        mitre_df[["id", "name", "tactic", "url", "color"]].rename(columns={
            "id":     "mitre_id",
            "name":   "mitre_technique",
            "tactic": "mitre_tactic",
            "url":    "mitre_url",
            "color":  "tactic_color",
        })
    ], axis=1)

    return enriched


def get_tactic_summary(df, tactic_col: str = "mitre_tactic") -> dict:
    """
    Возвращает словарь {тактика: количество} для визуализации.
    """
    if tactic_col not in df.columns:
        return {}
    return df[tactic_col].value_counts().to_dict()
