"""
utils/pcap_converter.py
Конвертация PCAP-файлов в CSV-формат, совместимый с IDS-моделью.
Использует scapy для разбора пакетов.
"""

import io
import pandas as pd
import numpy as np

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def check_scapy() -> bool:
    """Проверяет доступность scapy."""
    return SCAPY_AVAILABLE


def pcap_bytes_to_dataframe(pcap_bytes: bytes) -> pd.DataFrame:
    """
    Принимает байты PCAP-файла, возвращает DataFrame с признаками сессий.
    
    Признаки совместимы с NSL-KDD / KDD Cup (числовые поля).
    """
    if not SCAPY_AVAILABLE:
        raise ImportError(
            "Библиотека scapy не установлена. "
            "Установите её командой: pip install scapy"
        )

    # Загружаем пакеты из байтового буфера
    buf = io.BytesIO(pcap_bytes)
    try:
        packets = rdpcap(buf)
    except Exception as e:
        raise ValueError(f"Не удалось разобрать PCAP-файл: {e}")

    if len(packets) == 0:
        raise ValueError("PCAP-файл не содержит пакетов.")

    records = []
    for pkt in packets:
        record = _extract_features(pkt)
        records.append(record)

    df = pd.DataFrame(records)
    return df


def _extract_features(pkt) -> dict:
    """
    Извлекает числовые признаки из одного пакета scapy.
    Возвращает словарь, приближённый к KDD-формату.
    """
    features = {
        # Базовые
        "duration":         0,
        "protocol_type":    0,   # 0=tcp, 1=udp, 2=icmp, 3=other
        "src_bytes":        0,
        "dst_bytes":        0,
        "land":             0,   # src==dst ip+port
        "wrong_fragment":   0,
        "urgent":           0,

        # Контент
        "hot":              0,
        "num_failed_logins":0,
        "logged_in":        0,
        "num_compromised":  0,
        "root_shell":       0,
        "su_attempted":     0,
        "num_root":         0,
        "num_file_creations": 0,
        "num_shells":       0,
        "num_access_files": 0,
        "num_outbound_cmds":0,
        "is_host_login":    0,
        "is_guest_login":   0,

        # Трафик (окно по времени)
        "count":            1,
        "srv_count":        1,
        "serror_rate":      0.0,
        "srv_serror_rate":  0.0,
        "rerror_rate":      0.0,
        "srv_rerror_rate":  0.0,
        "same_srv_rate":    1.0,
        "diff_srv_rate":    0.0,
        "srv_diff_host_rate": 0.0,

        # Хост
        "dst_host_count":       0,
        "dst_host_srv_count":   0,
        "dst_host_same_srv_rate": 0.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,

        # Мета (для отображения, не для модели)
        "_src_ip":  "",
        "_dst_ip":  "",
        "_src_port": 0,
        "_dst_port": 0,
        "_proto":   "other",
        "_pkt_len": 0,
    }

    if not pkt.haslayer(IP):
        return features

    ip = pkt[IP]
    features["_src_ip"]  = str(ip.src)
    features["_dst_ip"]  = str(ip.dst)
    features["src_bytes"] = int(ip.len) if ip.len else 0
    features["_pkt_len"]  = int(ip.len) if ip.len else 0

    # Определяем протокол
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        features["protocol_type"] = 0
        features["_proto"]        = "tcp"
        features["_src_port"]     = int(tcp.sport)
        features["_dst_port"]     = int(tcp.dport)
        features["urgent"]        = 1 if (tcp.flags & 0x20) else 0  # URG flag
        features["land"]          = 1 if (ip.src == ip.dst and tcp.sport == tcp.dport) else 0

        # SYN без ACK — потенциальный SYN-флуд
        if (tcp.flags & 0x02) and not (tcp.flags & 0x10):
            features["serror_rate"] = 1.0

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        features["protocol_type"] = 1
        features["_proto"]        = "udp"
        features["_src_port"]     = int(udp.sport)
        features["_dst_port"]     = int(udp.dport)

    elif pkt.haslayer(ICMP):
        features["protocol_type"] = 2
        features["_proto"]        = "icmp"

    # Фрагментация
    if ip.flags and (ip.flags & 0x1):   # MF bit
        features["wrong_fragment"] = 1

    return features


def dataframe_to_csv_bytes(df: pd.DataFrame) -> bytes:
    """Конвертирует DataFrame в байты CSV для скачивания."""
    return df.to_csv(index=False).encode("utf-8")


def get_meta_columns() -> list:
    """Возвращает список мета-колонок (не используются моделью)."""
    return ["_src_ip", "_dst_ip", "_src_port", "_dst_port", "_proto", "_pkt_len"]


def drop_meta_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Удаляет мета-колонки перед передачей в модель."""
    meta = get_meta_columns()
    return df.drop(columns=[c for c in meta if c in df.columns])
