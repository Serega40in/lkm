<?php
/**
 * ЛКМ CRM — API в одном файле. PHP 7.4+ / 8.x, SQLite (PDO).
 * Все запросы — POST, тело JSON (Content-Type: text/plain, чтобы браузер не делал preflight).
 * {"action":"...", "token":"...", ...}
 */
declare(strict_types=1);

$CFG = require __DIR__ . '/config.php';

// ---------- CORS ----------
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin && (in_array('*', $CFG['origins'], true) || in_array($origin, $CFG['origins'], true))) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Vary: Origin');
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
}
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') { http_response_code(204); exit; }
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function out($data, int $code = 200): void {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}
function fail(string $msg, int $code = 400): void { out(['ok' => false, 'error' => $msg], $code); }

// ---------- DB ----------
$dir = __DIR__ . '/data';
if (!is_dir($dir)) { mkdir($dir, 0700, true); }
if (!file_exists("$dir/.htaccess")) { file_put_contents("$dir/.htaccess", "Require all denied\nDeny from all\n"); }
$db = new PDO('sqlite:' . $dir . '/crm.sqlite');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$db->exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;');
$db->exec('CREATE TABLE IF NOT EXISTS deals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bitrix_id INTEGER UNIQUE,
    stage TEXT NOT NULL DEFAULT "NEW",
    data TEXT NOT NULL DEFAULT "{}",
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT
)');
$db->exec('CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deal_id INTEGER NOT NULL,
    at TEXT NOT NULL,
    user TEXT NOT NULL,
    type TEXT NOT NULL,
    payload TEXT NOT NULL
)');
$db->exec('CREATE INDEX IF NOT EXISTS ix_hist_deal ON history(deal_id)');
$db->exec('CREATE INDEX IF NOT EXISTS ix_deals_upd ON deals(updated_at)');

function now(): string { return gmdate('Y-m-d\TH:i:s\Z'); }

// ---------- Справочники ----------
$STAGES = [
    ['id' => 'NEW',                'name' => 'Новый лид',         'color' => '#64748b'],
    ['id' => 'UC_MISSCALL',        'name' => 'Н/О',               'color' => '#94a3b8'],
    ['id' => 'UC_X040U9',          'name' => 'Общение',           'color' => '#0ea5e9'],
    ['id' => 'PREPARATION',        'name' => 'Квалифицирован',    'color' => '#6366f1'],
    ['id' => 'UC_1T0IS0',          'name' => 'КП без шоурума',    'color' => '#8b5cf6'],
    ['id' => 'PREPAYMENT_INVOICE', 'name' => 'Записан в шоурум',  'color' => '#d97706'],
    ['id' => 'EXECUTING',          'name' => 'Был в шоуруме',     'color' => '#ea580c'],
    ['id' => 'FINAL_INVOICE',      'name' => 'КП и договор',      'color' => '#16a34a'],
    ['id' => '1',                  'name' => 'В производстве',    'color' => '#15803d'],
    ['id' => 'UC_NUPAHN',          'name' => 'Отложенный спрос',  'color' => '#a16207'],
    ['id' => 'WON',                'name' => 'Сдан',              'color' => '#166534', 'closed' => true],
    ['id' => 'LOSE',               'name' => 'Отказ',             'color' => '#dc2626', 'closed' => true],
    ['id' => 'APOLOGY',            'name' => 'Спам / не целевой', 'color' => '#9ca3af', 'closed' => true],
];
$STAGE_IDS = array_column($STAGES, 'id');

// Разрешённые поля карточки (всё остальное отбрасывается)
$FIELDS = ['title','phone','email','source','responsible','model','package','plot','plot_address',
    'budget','amount','payment','term','decider','visit_date','was_in_shop','next_step','next_date',
    'lose_reason','avito_chat','avito_ad','brief','comment'];

// ---------- Авторизация ----------
function sign(string $user, string $secret): string {
    return rtrim(strtr(base64_encode($user), '+/', '-_'), '=') . '.' . substr(hash_hmac('sha256', $user, $secret), 0, 32);
}
function who(?string $token, array $CFG): ?string {
    if (!$token) return null;
    if (!empty($CFG['claude_key']) && hash_equals($CFG['claude_key'], $token)) return 'Claude';
    $p = explode('.', $token, 2);
    if (count($p) !== 2) return null;
    $user = base64_decode(strtr($p[0], '-_', '+/'));
    if (!isset($CFG['users'][$user])) return null;
    return hash_equals(sign($user, $CFG['secret'] . $CFG['users'][$user]), $token) ? $user : null;
}

// ---------- Вход ----------
$raw = file_get_contents('php://input');
$req = json_decode($raw ?: '{}', true);
if (!is_array($req)) fail('Неверный JSON');
$action = (string)($req['action'] ?? '');

if ($action === 'ping') out(['ok' => true, 'time' => now()]);

if ($action === 'users') out(['ok' => true, 'users' => array_keys($CFG['users'])]);

if ($action === 'login') {
    $u = (string)($req['user'] ?? '');
    $pin = (string)($req['pin'] ?? '');
    usleep(300000); // от перебора
    if (!isset($CFG['users'][$u]) || !hash_equals((string)$CFG['users'][$u], $pin)) fail('Неверное имя или PIN', 401);
    out(['ok' => true, 'user' => $u, 'token' => sign($u, $CFG['secret'] . $CFG['users'][$u])]);
}

$me = who($req['token'] ?? null, $CFG);
if (!$me) fail('Нужен вход', 401);

function row2deal(array $r): array {
    $d = json_decode($r['data'], true) ?: [];
    $d['id'] = (int)$r['id'];
    $d['bitrix_id'] = $r['bitrix_id'] !== null ? (int)$r['bitrix_id'] : null;
    $d['stage'] = $r['stage'];
    $d['created_at'] = $r['created_at'];
    $d['updated_at'] = $r['updated_at'];
    $d['updated_by'] = $r['updated_by'];
    return $d;
}
function load(PDO $db, int $id): ?array {
    $s = $db->prepare('SELECT * FROM deals WHERE id=?');
    $s->execute([$id]);
    $r = $s->fetch();
    return $r ?: null;
}
function hist(PDO $db, int $id, string $user, string $type, $payload, ?string $at = null): void {
    $db->prepare('INSERT INTO history(deal_id,at,user,type,payload) VALUES(?,?,?,?,?)')
       ->execute([$id, $at ?? now(), $user, $type, json_encode($payload, JSON_UNESCAPED_UNICODE)]);
}
function clean(array $in, array $FIELDS): array {
    $o = [];
    foreach ($in as $k => $v) {
        if (!in_array($k, $FIELDS, true)) continue;
        if (is_string($v)) $v = trim($v);
        if ($v === '') $v = null;
        if ($v !== null && !is_scalar($v)) continue;
        $o[$k] = $v;
    }
    return $o;
}

/**
 * Сохранить изменения: меняются только переданные поля (патч), поэтому
 * два человека, правящие разные поля одной карточки, не затирают друг друга.
 */
function apply(PDO $db, ?int $id, array $changes, ?string $stage, string $me, array $FIELDS, array $STAGE_IDS, ?int $bitrixId = null, ?string $createdAt = null): array {
    $changes = clean($changes, $FIELDS);
    if ($stage !== null && !in_array($stage, $STAGE_IDS, true)) fail('Неизвестная стадия: ' . $stage);
    $db->beginTransaction();
    if ($id === null) {
        $data = array_filter($changes, fn($v) => $v !== null);
        if (empty($data['title'])) { $db->rollBack(); fail('Нужно имя клиента (title)'); }
        $st = $stage ?? 'NEW';
        $t = now();
        $db->prepare('INSERT INTO deals(bitrix_id,stage,data,created_at,updated_at,updated_by) VALUES(?,?,?,?,?,?)')
           ->execute([$bitrixId, $st, json_encode($data, JSON_UNESCAPED_UNICODE), $createdAt ?? $t, $t, $me]);
        $id = (int)$db->lastInsertId();
        hist($db, $id, $me, 'create', ['stage' => $st, 'data' => $data]);
    } else {
        $r = load($db, $id);
        if (!$r) { $db->rollBack(); fail('Карточка не найдена', 404); }
        $data = json_decode($r['data'], true) ?: [];
        $diff = [];
        foreach ($changes as $k => $v) {
            $old = $data[$k] ?? null;
            if ($old === $v) continue;
            $diff[$k] = [$old, $v];
            if ($v === null) unset($data[$k]); else $data[$k] = $v;
        }
        $st = $r['stage'];
        if ($stage !== null && $stage !== $st) {
            hist($db, $id, $me, 'stage', ['from' => $st, 'to' => $stage]);
            $st = $stage;
        }
        if ($diff) hist($db, $id, $me, 'change', $diff);
        if ($diff || $st !== $r['stage']) {
            $db->prepare('UPDATE deals SET stage=?, data=?, updated_at=?, updated_by=? WHERE id=?')
               ->execute([$st, json_encode($data, JSON_UNESCAPED_UNICODE), now(), $me, $id]);
        }
    }
    $db->commit();
    return row2deal(load($db, $id));
}

switch ($action) {
    case 'meta':
        out(['ok' => true, 'me' => $me, 'stages' => $STAGES, 'users' => array_keys($CFG['users']), 'fields' => $FIELDS]);

    case 'list': {
        // since — вернуть только изменённые после метки (для быстрого автообновления)
        $since = $req['since'] ?? null;
        if ($since) { $s = $db->prepare('SELECT * FROM deals WHERE updated_at > ? ORDER BY updated_at DESC'); $s->execute([$since]); }
        else { $s = $db->query('SELECT * FROM deals ORDER BY updated_at DESC'); }
        $deals = array_map('row2deal', $s->fetchAll());
        if (!empty($req['light'])) {
            foreach ($deals as &$d) { unset($d['brief'], $d['comment']); }
        }
        out(['ok' => true, 'now' => now(), 'deals' => $deals]);
    }

    case 'find': {
        // поиск для Claude: по имени, телефону, ссылке на чат Авито, bitrix_id
        $q = mb_strtolower(trim((string)($req['q'] ?? '')));
        if ($q === '') fail('Пустой запрос');
        $digits = preg_replace('/\D/', '', $q);
        $res = [];
        foreach ($db->query('SELECT * FROM deals') as $r) {
            $d = row2deal($r);
            $hay = mb_strtolower(($d['title'] ?? '') . ' ' . ($d['avito_chat'] ?? '') . ' ' . ($d['avito_ad'] ?? '') . ' ' . ($d['plot_address'] ?? ''));
            $ph = preg_replace('/\D/', '', (string)($d['phone'] ?? ''));
            if (mb_strpos($hay, $q) !== false || (strlen($digits) >= 6 && $ph && strpos($ph, substr($digits, -10)) !== false)
                || (string)$d['id'] === $q || (string)$d['bitrix_id'] === $q) $res[] = $d;
        }
        out(['ok' => true, 'deals' => array_slice($res, 0, 50)]);
    }

    case 'get': {
        $r = load($db, (int)($req['id'] ?? 0));
        if (!$r) fail('Карточка не найдена', 404);
        $s = $db->prepare('SELECT at,user,type,payload FROM history WHERE deal_id=? ORDER BY id DESC LIMIT 300');
        $s->execute([(int)$r['id']]);
        $h = array_map(function ($x) { $x['payload'] = json_decode($x['payload'], true); return $x; }, $s->fetchAll());
        out(['ok' => true, 'deal' => row2deal($r), 'history' => $h]);
    }

    case 'save': {
        $id = isset($req['id']) && $req['id'] !== null ? (int)$req['id'] : null;
        $deal = apply($db, $id, (array)($req['changes'] ?? []), $req['stage'] ?? null, $me, $FIELDS, $STAGE_IDS);
        out(['ok' => true, 'deal' => $deal]);
    }

    case 'move': {
        $deal = apply($db, (int)($req['id'] ?? 0), [], (string)($req['stage'] ?? ''), $me, $FIELDS, $STAGE_IDS);
        out(['ok' => true, 'deal' => $deal]);
    }

    case 'note': {
        $id = (int)($req['id'] ?? 0);
        $text = trim((string)($req['text'] ?? ''));
        if ($text === '') fail('Пустая заметка');
        if (!load($db, $id)) fail('Карточка не найдена', 404);
        hist($db, $id, $me, 'note', ['text' => $text]);
        $db->prepare('UPDATE deals SET updated_at=?, updated_by=? WHERE id=?')->execute([now(), $me, $id]);
        out(['ok' => true]);
    }

    case 'export': {
        $deals = array_map('row2deal', $db->query('SELECT * FROM deals ORDER BY id')->fetchAll());
        $h = $db->query('SELECT * FROM history ORDER BY id')->fetchAll();
        out(['ok' => true, 'exported_at' => now(), 'deals' => $deals, 'history' => $h]);
    }

    case 'import': {
        // Только для Claude: массовая загрузка (миграция из Битрикса). Upsert по bitrix_id.
        if ($me !== 'Claude') fail('Импорт доступен только ключу Claude', 403);
        $n = ['created' => 0, 'updated' => 0];
        foreach ((array)($req['deals'] ?? []) as $d) {
            $bid = isset($d['bitrix_id']) ? (int)$d['bitrix_id'] : null;
            $existing = null;
            if ($bid) { $s = $db->prepare('SELECT id FROM deals WHERE bitrix_id=?'); $s->execute([$bid]); $existing = $s->fetchColumn() ?: null; }
            $st = $d['stage'] ?? null;
            unset($d['stage'], $d['bitrix_id']);
            $created = $d['created_at'] ?? null;
            $notes = $d['notes'] ?? [];
            if ($existing && !empty($req['only_new'])) { $n['skipped'] = ($n['skipped'] ?? 0) + 1; continue; }
            if ($existing) { apply($db, (int)$existing, $d, $st, 'Импорт из Битрикса', $FIELDS, $STAGE_IDS); $n['updated']++; }
            else {
                $deal = apply($db, null, $d, $st, 'Импорт из Битрикса', $FIELDS, $STAGE_IDS, $bid, $created);
                foreach ((array)$notes as $nt) { if (!empty($nt['text'])) hist($db, $deal['id'], $nt['user'] ?? 'Битрикс', 'note', ['text' => $nt['text']], $nt['at'] ?? null); }
                $n['created']++;
            }
        }
        out(['ok' => true] + $n);
    }

    default:
        fail('Неизвестное действие: ' . $action);
}
