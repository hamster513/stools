/** Статические справочники для генерации фикстур мока. */

export const AUTHORS: Record<string, number> = { DEMO: 172, acme: 9, SOC: 5, IOC: 1 }

export const CATEGORIES = ['HC', 'AC', 'TA', 'AN', 'DT'] as const

export const FIELDS = [
  'subject.account.name',
  'subject.account.domain',
  'src.ip',
  'dst.ip',
  'src.host',
  'dst.host',
  'event_src.host',
  'object.name',
  'object.process.name',
  'object.fqdn',
  'subject.sid',
  'subject.privileges',
  'action',
  'msgid',
] as const

export type TableState = 'missing' | 'empty' | 'filled'

export interface TableFixture {
  name: string
  state: TableState
  isScoping: boolean
  valueCount: number
}

/**
 * Табличные списки инсталляции. Смешаны все три состояния из ТЗ: список
 * отсутствует в выгрузке, список есть но пуст, список есть и наполнен.
 */
export const TABLES: TableFixture[] = [
  { name: 'DEMO_User_Authentications', state: 'missing', isScoping: false, valueCount: 0 },
  { name: 'DEMO_Critical_Hosts_by_Rule', state: 'filled', isScoping: true, valueCount: 214 },
  { name: 'DEMO_TTX_Servers', state: 'filled', isScoping: true, valueCount: 58 },
  { name: 'DEMO_Hosts', state: 'filled', isScoping: false, valueCount: 3120 },
  { name: 'DEMO_Admin_Accounts', state: 'empty', isScoping: false, valueCount: 0 },
  { name: 'DEMO_Service_Accounts', state: 'filled', isScoping: false, valueCount: 96 },
  { name: 'DEMO_DC_List', state: 'filled', isScoping: true, valueCount: 12 },
  { name: 'DEMO_VIP_Users', state: 'empty', isScoping: false, valueCount: 0 },
  { name: 'DEMO_Excluded_Processes', state: 'filled', isScoping: false, valueCount: 41 },
  { name: 'DEMO_Whitelisted_IPs', state: 'filled', isScoping: false, valueCount: 187 },
  { name: 'DEMO_Critical_Assets', state: 'missing', isScoping: false, valueCount: 0 },
  { name: 'DEMO_Privileged_Groups', state: 'filled', isScoping: false, valueCount: 23 },
  { name: 'DEMO_Monitoring_Hosts', state: 'empty', isScoping: true, valueCount: 0 },
  { name: 'DEMO_Backup_Servers', state: 'filled', isScoping: false, valueCount: 17 },
  { name: 'acme_Yealink_Devices', state: 'filled', isScoping: false, valueCount: 64 },
  { name: 'SOC_Watchlist_Users', state: 'empty', isScoping: false, valueCount: 0 },
]

export const RULE_NAME_PARTS_BY_CATEGORY: Record<string, string[]> = {
  HC: ['Impacket', 'Kerberoasting', 'PassTheHash', 'DCSync', 'Mimikatz', 'GoldenTicket', 'LSASSDump'],
  AC: ['BruteForce', 'PrivEsc', 'AccountLockout', 'SuspiciousLogin', 'MFA_Bypass'],
  TA: ['LateralMovement', 'C2Beacon', 'ExfilDNS', 'PortScan', 'ARPSpoof'],
  AN: ['Anomaly_Login', 'Anomaly_Traffic', 'Anomaly_Volume', 'Anomaly_Process'],
  DT: ['Yealink_Detect', 'SIP_Abuse', 'VOIP_Toll_Fraud'],
}

/**
 * Малый учебный срез справочника ATT&CK (не полный enterprise-attack.json —
 * этого достаточно для правдоподобной разметки в моке). Используется и как
 * источник предложений модели, и как ответ `GET /api/attack/techniques`.
 */
export interface TechniqueFixture {
  technique_id: string
  name_ru: string
  tactics: string[]
  /** Подтехники нужны в макете затем же, зачем в продукте: без них
   *  не увидеть, что разметка родительской техникой закрывает клетку
   *  матрицы, ничего на деле не установив. */
  parent_id?: string
  /** Распространённость 0..4 и её сырые числа. */
  level?: number
  actor_groups?: number
  sightings?: number
}

export const TECHNIQUE_CATALOG: TechniqueFixture[] = [
  // Подтехники двух семейств: этого хватает, чтобы на макете было видно
  // и предупреждение о неуточнённой разметке, и сортировку по частоте.
  { technique_id: 'T1003.001', name_ru: 'Память LSASS', tactics: ['credential-access'], parent_id: 'T1003', level: 3, actor_groups: 87, sightings: 2260 },
  { technique_id: 'T1003.002', name_ru: 'Диспетчер учётных записей безопасности', tactics: ['credential-access'], parent_id: 'T1003', level: 3, actor_groups: 75, sightings: 4 },
  { technique_id: 'T1003.003', name_ru: 'NTDS', tactics: ['credential-access'], parent_id: 'T1003', level: 2, actor_groups: 34, sightings: 265 },
  { technique_id: 'T1003.006', name_ru: 'DCSync', tactics: ['credential-access'], parent_id: 'T1003', level: 3, actor_groups: 52, sightings: 29 },
  { technique_id: 'T1003.008', name_ru: 'Файлы /etc/passwd и /etc/shadow', tactics: ['credential-access'], parent_id: 'T1003', level: 2, actor_groups: 12, sightings: 71 },
  { technique_id: 'T1059.001', name_ru: 'PowerShell', tactics: ['execution'], parent_id: 'T1059', level: 4, actor_groups: 108, sightings: 193873 },
  { technique_id: 'T1059.003', name_ru: 'Командная оболочка Windows', tactics: ['execution'], parent_id: 'T1059', level: 4, actor_groups: 137, sightings: 30827 },
  { technique_id: 'T1059.008', name_ru: 'Команды сетевого устройства', tactics: ['execution'], parent_id: 'T1059', level: 0, actor_groups: 0, sightings: 0 },
  { technique_id: 'T1047', name_ru: 'Windows Management Instrumentation', tactics: ['execution'] },
  { technique_id: 'T1053', name_ru: 'Планировщик задач', tactics: ['execution', 'persistence', 'privilege-escalation'] },
  { technique_id: 'T1059', name_ru: 'Интерпретатор команд и сценариев', tactics: ['execution'] },
  { technique_id: 'T1003', name_ru: 'Дамп учётных данных ОС', tactics: ['credential-access'] },
  { technique_id: 'T1558', name_ru: 'Подделка билетов Kerberos', tactics: ['credential-access'] },
  { technique_id: 'T1550', name_ru: 'Использование альтернативных материалов аутентификации', tactics: ['defense-evasion', 'lateral-movement'] },
  { technique_id: 'T1021', name_ru: 'Удалённые службы', tactics: ['lateral-movement'] },
  { technique_id: 'T1078', name_ru: 'Действительные учётные записи', tactics: ['defense-evasion', 'persistence', 'privilege-escalation', 'initial-access'] },
  { technique_id: 'T1110', name_ru: 'Подбор учётных данных', tactics: ['credential-access'] },
  { technique_id: 'T1136', name_ru: 'Создание учётной записи', tactics: ['persistence'] },
  { technique_id: 'T1098', name_ru: 'Изменение учётной записи', tactics: ['persistence', 'privilege-escalation'] },
  { technique_id: 'T1069', name_ru: 'Обнаружение групп разрешений', tactics: ['discovery'] },
  { technique_id: 'T1018', name_ru: 'Обнаружение удалённых систем', tactics: ['discovery'] },
  { technique_id: 'T1046', name_ru: 'Сканирование сетевых служб', tactics: ['discovery'] },
  { technique_id: 'T1071', name_ru: 'Протокол прикладного уровня', tactics: ['command-and-control'] },
  { technique_id: 'T1041', name_ru: 'Эксфильтрация по каналу C2', tactics: ['exfiltration'] },
  { technique_id: 'T1048', name_ru: 'Эксфильтрация по альтернативному протоколу', tactics: ['exfiltration'] },
  { technique_id: 'T1486', name_ru: 'Шифрование данных для воздействия', tactics: ['impact'] },
  { technique_id: 'T1490', name_ru: 'Подавление восстановления системы', tactics: ['impact'] },
  { technique_id: 'T1562', name_ru: 'Отключение или изменение средств защиты', tactics: ['defense-evasion'] },
  { technique_id: 'T1070', name_ru: 'Удаление индикаторов', tactics: ['defense-evasion'] },
  { technique_id: 'T1055', name_ru: 'Внедрение в процесс', tactics: ['defense-evasion', 'privilege-escalation'] },
  { technique_id: 'T1057', name_ru: 'Обнаружение процессов', tactics: ['discovery'] },
  { technique_id: 'T1082', name_ru: 'Обнаружение сведений о системе', tactics: ['discovery'] },
  { technique_id: 'T1595', name_ru: 'Активное сканирование', tactics: ['reconnaissance'] },
  { technique_id: 'T1583', name_ru: 'Приобретение инфраструктуры', tactics: ['resource-development'] },
  { technique_id: 'T1190', name_ru: 'Эксплуатация публичного приложения', tactics: ['initial-access'] },
  { technique_id: 'T1566', name_ru: 'Фишинг', tactics: ['initial-access'] },
  { technique_id: 'T1560', name_ru: 'Архивирование собранных данных', tactics: ['collection'] },
  { technique_id: 'T1113', name_ru: 'Захват экрана', tactics: ['collection'] },
]
