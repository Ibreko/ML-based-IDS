"""
utils/whitelist.py
Управление белым списком IP-адресов.
Доверенные IP исключаются из анализа ИИ даже при аномальном поведении.
"""

import ipaddress
import pandas as pd
from typing import Optional


class IPWhitelist:
    """
    Хранит и проверяет белый список IP-адресов и подсетей.
    Поддерживает единичные адреса (192.168.1.1) и CIDR-нотацию (10.0.0.0/8).
    """

    def __init__(self):
        self._exact: set[str] = set()
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._raw_entries: list[str] = []

    # ------------------------------------------------------------------ #
    #  Загрузка                                                            #
    # ------------------------------------------------------------------ #

    def load_from_text(self, text: str) -> tuple[int, list[str]]:
        """
        Парсит текст (по одной записи на строку).
        Возвращает (кол-во успешно загруженных, список ошибок).
        """
        errors = []
        count = 0

        for raw_line in text.splitlines():
            entry = raw_line.strip()
            if not entry or entry.startswith("#"):
                continue

            ok, err = self._add_entry(entry)
            if ok:
                count += 1
            else:
                errors.append(err)

        return count, errors

    def load_from_uploaded_file(self, file_obj) -> tuple[int, list[str]]:
        """
        Принимает объект файла (из st.file_uploader) и загружает содержимое.
        """
        try:
            content = file_obj.read().decode("utf-8", errors="replace")
        except Exception as e:
            return 0, [f"Не удалось прочитать файл: {e}"]
        return self.load_from_text(content)

    # ------------------------------------------------------------------ #
    #  Добавление / удаление                                              #
    # ------------------------------------------------------------------ #

    def _add_entry(self, entry: str) -> tuple[bool, Optional[str]]:
        """Добавляет одну запись. Возвращает (успех, сообщение_об_ошибке)."""
        try:
            if "/" in entry:
                net = ipaddress.ip_network(entry, strict=False)
                self._networks.append(net)
            else:
                ipaddress.ip_address(entry)   # валидация
                self._exact.add(entry)
            self._raw_entries.append(entry)
            return True, None
        except ValueError:
            return False, f"Неверный IP или подсеть: '{entry}'"

    def add(self, entry: str) -> tuple[bool, Optional[str]]:
        """Добавляет одну запись вручную."""
        return self._add_entry(entry)

    def remove(self, entry: str) -> bool:
        """Удаляет запись. Возвращает True если запись была найдена."""
        if entry in self._exact:
            self._exact.discard(entry)
            self._raw_entries = [e for e in self._raw_entries if e != entry]
            return True
        # Для сетей — сравниваем строково
        before = len(self._networks)
        self._networks = [n for n in self._networks if str(n) != entry]
        if len(self._networks) < before:
            self._raw_entries = [e for e in self._raw_entries if e != entry]
            return True
        return False

    def clear(self):
        """Очищает весь белый список."""
        self._exact.clear()
        self._networks.clear()
        self._raw_entries.clear()

    # ------------------------------------------------------------------ #
    #  Проверка                                                            #
    # ------------------------------------------------------------------ #

    def is_whitelisted(self, ip: str) -> bool:
        """
        Проверяет, входит ли IP в белый список.
        Возвращает True если да (доверенный).
        """
        if not ip or ip in ("N/A", "", "nan"):
            return False

        # Быстрая проверка точного совпадения
        if ip in self._exact:
            return True

        # Проверка по подсетям
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._networks)
        except ValueError:
            return False

    def filter_dataframe(self, df: pd.DataFrame, ip_col: str = "_src_ip") -> tuple[pd.DataFrame, pd.DataFrame]:
        """
        Разделяет DataFrame на (не_в_белом_списке, в_белом_списке).
        
        Возвращает:
            filtered_df  — строки для анализа ИИ
            skipped_df   — строки, пропущенные как доверенные
        """
        if ip_col not in df.columns:
            return df, pd.DataFrame()

        mask = df[ip_col].apply(lambda ip: not self.is_whitelisted(str(ip)))
        return df[mask].reset_index(drop=True), df[~mask].reset_index(drop=True)

    # ------------------------------------------------------------------ #
    #  Информация                                                          #
    # ------------------------------------------------------------------ #

    def __len__(self) -> int:
        return len(self._exact) + len(self._networks)

    def __contains__(self, ip: str) -> bool:
        return self.is_whitelisted(ip)

    def summary(self) -> dict:
        return {
            "total_entries": len(self),
            "exact_ips":     len(self._exact),
            "subnets":       len(self._networks),
            "entries":       list(self._raw_entries),
        }

    def to_text(self) -> str:
        """Экспортирует белый список в текстовый формат (для скачивания)."""
        return "\n".join(self._raw_entries)


# ------------------------------------------------------------------ #
#  Синглтон для использования в Streamlit session_state              #
# ------------------------------------------------------------------ #

def get_whitelist_from_session(session_state) -> "IPWhitelist":
    """
    Возвращает экземпляр IPWhitelist из session_state Streamlit.
    Создаёт новый, если не существует.
    """
    if "_ip_whitelist" not in session_state:
        session_state["_ip_whitelist"] = IPWhitelist()
    return session_state["_ip_whitelist"]
