import requests
import re
from abc import ABC, abstractmethod
from urllib.parse import urljoin
from datatypes import Task
from parser import TaskParser

class BaseSiteClient(ABC):
    URL = "http://hw1.alexbers.com/"
    BASE_COOKIE = {"user": "a6d28cb0ca702e1fef8d88333911bb52"}

    @abstractmethod
    def send_request(self, task: Task):
            pass


class SiteClientSimple(BaseSiteClient):
    
    def __init__(self):
        self.session = requests.session()
        self.session.headers.update({'User-Agent': 'MyGlobalAgent/1.0'})
        self.session.cookies.update(self.BASE_COOKIE)

    def send_request(self, task: Task) -> str:
        try:
            response = self.session.request(
                method=task.method,
                url=urljoin(self.URL, task.path),
                headers=task.headers,
                cookies=task.cookies,
                data=task.data,
                files=task.files,
                params=task.params
            )
            response.raise_for_status()
            return response.text
        
        except requests.RequestException as exc:
            print(f"Запрос упал с ошибкой:\n{exc}")


class Solver():
    HAS_SECRETE_TOKEN = re.compile(r"Секретный ключ:\s+<b><code>(\S+)</code></b>")

    def __init__(self, site_client: SiteClientSimple, parser: TaskParser):
        self.site_client = site_client
        self.parser = parser

    def solve(self):
        task = Task("GET")
        step_number = 0
        while True:
            response_text = self.site_client.send_request(task)

            match = self.HAS_SECRETE_TOKEN.search(response_text)
            if match:
                print(f"Секретный ключ: {match.group(1)}")
                break

            step_number += 1
            print(f"Текущий шаг -> {step_number}")
            task = self.parser.parse(response_text)
            #self._print_task(task, step_number)
            
    def _print_task(self, task: Task, step_number: int) -> None:
        print(f"Номер шага: {step_number}. Метод запроса: {task.method}")
        print("Задание")
        print(f"path={task.path}, headers={len(task.headers)}, cookies={len(task.cookies)}")
        print(f"data={len(task.data)}, files={len(task.files)}, params={len(task.params)}")
        

if __name__ == "__main__":
    site_client = SiteClientSimple()
    parser = TaskParser()
    solver = Solver(site_client, parser)
    solver.solve()