import { test } from 'node:test'
import assert from 'node:assert/strict'
import { describeCron, fieldValues, nextRuns, parseCron, type CronSchedule } from './cron.ts'

function schedule(text: string): CronSchedule {
  const r = parseCron(text)
  if (!r.ok) throw new Error(`${text}: ${r.error}`)
  if (r.cron.kind !== 'schedule') throw new Error(`${text}: не расписание`)
  return r.cron
}
const say = (text: string) => {
  const r = parseCron(text)
  if (!r.ok) throw new Error(`${text}: ${r.error}`)
  return describeCron(r.cron)
}
const fail = (text: string) => {
  const r = parseCron(text)
  assert.equal(r.ok, false, `${text} должна быть ошибкой`)
  return r.ok ? '' : r.error
}

test('описание: время одной точкой и списком точек', () => {
  assert.equal(say('5 4 * * *'), 'В 04:05.')
  assert.equal(say('15 10,22 * * *'), 'В 10:15 и 22:15.')
  assert.equal(say('0,30 9,18 * * *'), 'В 09:00, 09:30, 18:00 и 18:30.')
})

test('описание: каждую минуту, шаги минут и часов', () => {
  assert.equal(say('* * * * *'), 'Каждую минуту.')
  assert.equal(say('*/1 * * * *'), 'Каждую минуту.')
  assert.equal(say('*/15 * * * *'), 'Каждые 15 минут.')
  assert.equal(say('*/2 * * * *'), 'Каждые 2 минуты.')
  assert.equal(say('0 * * * *'), 'Каждый час в 0 минут.')
  assert.equal(say('0,30 * * * *'), 'Каждый час в 0 и 30 минут.')
  assert.equal(say('1 * * * *'), 'Каждый час в 1 минуту.')
  assert.equal(say('0 */2 * * *'), 'Каждые 2 часа в 0 минут.')
  assert.equal(say('0 */5 * * *'), 'Каждые 5 часов в 0 минут.')
  assert.equal(say('*/15 */2 * * *'), 'Каждые 15 минут в каждый 2-й час.')
})

test('описание: часы диапазоном и одним значением', () => {
  assert.equal(say('0 9-18 * * 1-5'), 'Каждый час с 09:00 по 18:00 с понедельника по пятницу.')
  assert.equal(say('*/5 9-17 * * *'), 'Каждые 5 минут с 09:00 по 17:59.')
  assert.equal(say('* 9 * * *'), 'Каждую минуту с 09:00 по 09:59.')
  assert.equal(say('0-30 * * * *'), 'В минуты 0–30 каждого часа.')
})

test('описание: дни месяца, дни недели, месяцы', () => {
  assert.equal(say('0 0 1 * *'), 'В 00:00 1-го числа.')
  assert.equal(say('0 0 * * 0'), 'В 00:00 по воскресеньям.')
  assert.equal(say('0 0 * * 7'), 'В 00:00 по воскресеньям.')
  assert.equal(say('0 0 * * 1,5'), 'В 00:00 по понедельникам и пятницам.')
  assert.equal(say('0 0 * * MON-FRI'), 'В 00:00 с понедельника по пятницу.')
  assert.equal(say('30 8 1,15 1-3 *'), 'В 08:30 1-го и 15-го числа с января по март.')
  assert.equal(say('0 0 1-7 * *'), 'В 00:00 с 1-го по 7-е число.')
  assert.equal(say('0 12 * jan,jul *'), 'В 12:00 в январе и июле.')
  assert.equal(say('0 0 1 */3 *'), 'В 00:00 1-го числа в каждый 3-й месяц.')
})

test('описание: день месяца и день недели вместе — «или», как у cron', () => {
  assert.equal(say('0 0 13 * 5'), 'В 00:00 13-го числа или по пятницам.')
})

test('специальные строки', () => {
  assert.equal(say('@daily'), 'В 00:00.')
  assert.equal(say('@midnight'), 'В 00:00.')
  assert.equal(say('@hourly'), 'Каждый час в 0 минут.')
  assert.equal(say('@weekly'), 'В 00:00 по воскресеньям.')
  assert.equal(say('@monthly'), 'В 00:00 1-го числа.')
  assert.equal(say('@yearly'), 'В 00:00 1-го числа в январе.')
  assert.equal(say('@annually'), 'В 00:00 1-го числа в январе.')
  assert.equal(say('@reboot'), 'При загрузке системы.')
  const r = parseCron('@weekly')
  assert.ok(r.ok && r.cron.kind === 'schedule' && r.cron.expanded === '0 0 * * 0')
})

test('значения полей: шаги, диапазоны, имена, 7 — воскресенье', () => {
  const c = schedule('*/20 1-3,5 * jan-mar 5-7')
  assert.deepEqual(fieldValues(c, 0), [0, 20, 40])
  assert.deepEqual(fieldValues(c, 1), [1, 2, 3, 5])
  assert.deepEqual(fieldValues(c, 3), [1, 2, 3])
  assert.deepEqual(fieldValues(c, 4), [0, 5, 6])
  assert.deepEqual(fieldValues(schedule('5/20 * * * *'), 0), [5, 25, 45])
  assert.deepEqual(fieldValues(schedule('0 0-12/4 * * *'), 1), [0, 4, 8, 12])
})

test('ошибки: число полей, диапазоны, шаг, мусор', () => {
  assert.match(fail(''), /5 полей/)
  assert.match(fail('* * * *'), /5 полей/)
  assert.match(fail('0 * * * * *'), /секунд/)
  assert.match(fail('60 * * * *'), /минута.*60.*0–59/)
  assert.match(fail('0 24 * * *'), /час.*24.*0–23/)
  assert.match(fail('0 0 0 * *'), /день.*0.*1–31/)
  assert.match(fail('0 0 * 13 *'), /месяц.*13/)
  assert.match(fail('0 0 * * 8'), /день недели.*8/)
  assert.match(fail('*/0 * * * *'), /шаг/)
  assert.match(fail('10-5 * * * *'), /начало диапазона/)
  assert.match(fail('0 0 L * *'), /«L»/)
  assert.match(fail('0 0 ? * *'), /«\?»/)
  assert.match(fail('@often'), /@often/)
  assert.match(fail('1,,2 * * * *'), /пуст/)
})

test('ближайшие запуски: по местному времени, строго после момента', () => {
  const from = new Date(2026, 9, 29, 10, 0, 30) // чт 29.10.2026 10:00:30
  const runs = nextRuns(schedule('5 4 * * *'), from, 3)
  assert.deepEqual(runs.map((d) => [d.getDate(), d.getHours(), d.getMinutes()]), [[30, 4, 5], [31, 4, 5], [1, 4, 5]])
  const every = nextRuns(schedule('*/15 * * * *'), from, 2)
  assert.deepEqual(every.map((d) => d.getMinutes()), [15, 30])
  const weekdays = nextRuns(schedule('0 9 * * 1-5'), from, 3) // пт 30.10, пн 2.11, вт 3.11
  assert.deepEqual(weekdays.map((d) => d.getDate()), [30, 2, 3])
})

test('ближайшие запуски: «или» для дня месяца и дня недели, «и» при звёздочке', () => {
  const from = new Date(2026, 9, 29, 12, 0)
  // 13-го числа или по пятницам: пт 30.10, пт 6.11, пт 13.11 (и 13-е), пт 20.11
  assert.deepEqual(nextRuns(schedule('0 0 13 * 5'), from, 3).map((d) => d.getDate()), [30, 6, 13])
  // */2 в дне месяца начинается со звёздочки — условия складываются через «и»: нечётные числа, только пятницы
  assert.deepEqual(nextRuns(schedule('0 0 */2 * 5'), from, 2).map((d) => [d.getMonth() + 1, d.getDate()]), [[11, 13], [11, 27]])
})

test('ближайшие запуски: несуществующая дата и 29 февраля', () => {
  const from = new Date(2026, 9, 29)
  assert.deepEqual(nextRuns(schedule('0 0 30 2 *'), from, 3), [])
  const leap = nextRuns(schedule('0 0 29 2 *'), from, 1)
  assert.equal(leap[0].getFullYear(), 2028)
})
