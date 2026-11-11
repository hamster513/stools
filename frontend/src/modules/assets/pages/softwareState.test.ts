import assert from 'node:assert/strict'
import test from 'node:test'
import { inventoryEmptyText } from './softwareState.ts'

test('missing inventory is not described as an empty installed software list', () => {
  assert.match(inventoryEmptyText([], false), /ещё не собран/)
  assert.match(inventoryEmptyText(['not_collected'], false), /ещё не собран/)
})

test('only complete inventories can report an empty software list', () => {
  assert.match(inventoryEmptyText(['complete'], false), /не содержит ПО/)
  assert.match(inventoryEmptyText(['error'], false), /не удалось/)
  assert.match(inventoryEmptyText(['complete', 'error'], false), /неполные/)
  assert.match(inventoryEmptyText(['complete', 'not_collected'], false), /неполные/)
})

test('a search with no rows does not imply empty inventory or hide collection failure', () => {
  assert.match(inventoryEmptyText(['complete'], true), /По запросу/)
  assert.match(inventoryEmptyText(['error'], true), /не удалось/)
  assert.match(inventoryEmptyText(['not_collected'], true), /ещё не собран/)
})
