"""Статусы находок — механизм платформы (спека 2026-10-02-finding-status-design).

Модули подключаются адаптером (`adapters.register_adapter`) и вызывают
`adapters.safe_reconcile` в конце импорта; ручки — `router`, монтируется в
api/main.py.
"""
