"""Реестр модулей STools.

Модуль — пакет `api/modules/<id>/` с роутером `router`, у которого префикс
`/api/<id>`. Платформа (api/main.py) монтирует каждый роутер отсюда с
зависимостью get_current_user, поэтому защита по умолчанию распространяется
и на модули, которые добавят позже: забыть её нельзя.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.modules.ad import router as ad_router
from api.modules.assets import router as assets_router
from api.modules.attack import router as attack_router
from api.modules.ksc import router as ksc_router
from api.modules.siem import router as siem_router
from api.modules.vm import router as vm_router

MODULE_ROUTERS: list[APIRouter] = [attack_router, siem_router, vm_router, ad_router, ksc_router, assets_router]
