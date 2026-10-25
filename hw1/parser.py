import re

from bs4 import BeautifulSoup
from datatypes import Task

class TaskParser:

    DEFAULT_HTML_HEADER_PATTERN = re.compile(r"Отправьте\s+([A-Z]+)-запрос\s+по\s+адресу\s+(\S+)", re.IGNORECASE)
    HTML_HEADER_SEND_FILES_PATTERN = re.compile(r"Загрузите файлы по адресу\s+(\S+)")
    STEP_NUMBER_PATTERN = re.compile(r"Шаг\s+#(\d+)")
    IS_SECRETE_TOKEN = re.compile(r"Секретный ключ:\s+(\S+)")

    def parse(self, html: str) -> Task:
        soup = BeautifulSoup(html, "html.parser")
        method, path = self._parse_method_path(soup)            

        task = Task(
            method=method,
            path=path,
        )

        for table in soup.find_all("table"):
            label = self._get_table_label(table)
            values = self._parse_key_value_table(table, False)

            if "cookie" in label:
                task.cookies.update(values)
            elif "заголовки" in label:
                task.headers.update(values)
            elif "данные формы" in label:
                task.data.update(values)
            elif "параметры запроса" in label:
                task.params.update(values)
            else:
                values = self._parse_key_value_table(table, True)
                task.files.update(values)

        return task

    def _parse_method_path(self, soup: BeautifulSoup) -> tuple[str, str]:
        """Парсим метод request и адрес ссылки"""
        text = soup.get_text(" ", strip=True)

        match = self.DEFAULT_HTML_HEADER_PATTERN.search(text)
        if match:
            return match.group(1).upper(), match.group(2)

        match = self.HTML_HEADER_SEND_FILES_PATTERN.search(text)
        if match:
            return "POST", match.group(1)

        link = soup.find("a", href=True)
        if link:
            return "GET", link["href"]

        return None, None

    def _get_table_label(self, table) -> str:
        """Получаем весь текст перед таблицей"""
        for text_node in table.find_all_previous(string=True):
            text = text_node.strip()

            if text:
                return text.lower()

        return ""

    def _parse_key_value_table(self, table, is_files: bool) -> dict:
        """Парсим таблицу ключ-значение в словарь"""
        result = {}

        for row in table.find_all("tr")[1:]:
            cells = row.find_all("td")

            if len(cells) != 2:
                continue

            key = cells[0].get_text(strip=True)
            value = cells[1].get_text(strip=True)

            if is_files:
                value = value.encode("utf-8")

            result[key] = value

        return result        