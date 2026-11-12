"""Чтение Tables.get_tables_list/get_table_data по контракту mpsiemlib."""
import json
from urllib.parse import quote

import httpx

from api.hosts import url_host
from api.limits import MAX_API_RESPONSE, ResponseTooLarge, read_limited

ROOT = '/api/events/v2/table_lists'


class TableError(ValueError):
    pass


def make_client(conn):
    return httpx.Client(verify=conn.verify_tls, timeout=30)


class TablesClient:
    def __init__(self, conn, http, siem_id=''):
        self.conn, self.http = conn, http
        host = conn.host.strip().removeprefix('https://').removeprefix('http://').rstrip('/')
        self.base = f'https://{url_host(host)}'
        self.params = {'siem_id': siem_id} if siem_id else {}

    def request(self, method, path, body=None):
        try:
            with self.http.stream(method, self.base + path, params=self.params, json=body,
                                  headers={'Authorization': f'Bearer {self.conn.api_token}'}) as r:
                if r.status_code != 200:
                    raise TableError(f'Табличные списки SIEM: HTTP {r.status_code}. Проверьте права и выбор конвейера.')
                raw = read_limited(r, MAX_API_RESPONSE)
            return json.loads(raw)
        except (httpx.HTTPError, ResponseTooLarge, json.JSONDecodeError) as exc:
            raise TableError('Не удалось прочитать табличный список SIEM; данные не изменены') from exc

    def catalog(self):
        data = self.request('GET', ROOT)
        if not isinstance(data, list) or any(not isinstance(x, dict) or not isinstance(x.get('name'), str)
                                            or not isinstance(x.get('token'), str) for x in data):
            raise TableError('Неожиданный формат каталога табличных списков SIEM')
        return [{'name': x['name'], 'id': x['token']} for x in data]

    def rows(self, name, *, batch_size=1000, max_rows=100000, preview=False):
        matches = [x for x in self.catalog() if x['name'] == name]
        if len(matches) != 1:
            raise TableError('Выбранный табличный список не найден или его имя неоднозначно')
        token = quote(matches[0]['id'], safe='')
        offset = 0
        while True:
            data = self.request('POST', f'{ROOT}/{token}/content/search', {
                'filter': {'where': '', 'orderBy': [{'field': '_last_changed', 'sortOrder': 'descending'}], 'timeZone': 0},
                'offset': offset, 'limit': batch_size,
            })
            if not isinstance(data, dict) or not isinstance(data.get('items'), list):
                raise TableError('Неожиданный формат строк табличного списка SIEM')
            items = data['items']
            if any(not isinstance(r, dict) for r in items) or len(items) > batch_size:
                raise TableError('Неожиданный формат страницы табличного списка SIEM')
            for row in items:
                if offset >= max_rows:
                    if preview:
                        return
                    raise TableError('Список превышает лимит строк импорта. Увеличьте лимит в настройках; данные не изменены.')
                yield row
                offset += 1
            if len(items) < batch_size or (preview and offset >= max_rows):
                return
