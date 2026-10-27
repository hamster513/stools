import { test } from 'node:test'
import assert from 'node:assert/strict'
import { plainText } from './plain.ts'

test('plainText: заголовки, жирный, курсив и код теряют маркеры', () => {
  assert.equal(plainText('## Что это\n\nЭто **важно**, *очень* и `так`.'), 'Что это Это важно, очень и так.')
})

test('plainText: ссылка остаётся текстом, адрес и help: пропадают', () => {
  assert.equal(plainText('Это [снапшот](help:snapshot) и [страница](/findings).'), 'Это снапшот и страница.')
})

test('plainText: таблица без разделителя и границ, список без маркеров', () => {
  const body = '| Уровень | Что |\n|---|:--|\n| read | Смотреть |\n\n- один\n1. два'
  assert.equal(plainText(body), 'Уровень Что read Смотреть один два')
})

test('plainText: остаток фронтматтера и цитата', () => {
  assert.equal(plainText('---\nslug: a\n---\n> Совет\nТекст'), 'Совет Текст')
})
