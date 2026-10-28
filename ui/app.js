(function () {
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var esc = function (s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var ico = function (n, c) { return '<svg class="ic ' + (c || '') + '" aria-hidden="true"><use href="#i-' + n + '"/></svg>'; };
  var hms = function () { return new Date().toLocaleTimeString('ru-RU', { hour12: false }); };
  var nowShort = function () { return new Date().toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }); };

  var SVC = {
    discord: { name: 'Zapret (Discord)', icon: 'chat', cls: 'b-discord' },
    telegram: { name: 'Zapret (Telegram)', icon: 'plane', cls: 'b-telegram' },
    fptn: { name: 'FPTN', icon: 'tunnel', cls: 'b-fptn' },
    vless: { name: 'VLESS', icon: 'net', cls: 'b-vless' },
    proxy: { name: 'Proxy', icon: 'wifi', cls: 'b-proxy' },
    wg: { name: 'WireGuard / AmneziaWG', icon: 'vpn', cls: 'b-wg' }
  };
  var IDS = Object.keys(SVC);
  /* разделы-заглушки: чтобы вернуть раздел, уберите его из SOON и удалите data-soon у секции */
  var SOON = {};
  /* внутри Tauri доступны настоящие команды, в обычном браузере остаётся макет */
  var T = window.__TAURI__;
  var inTauri = !!(T && T.core && T.core.invoke);
  var appMode = inTauri || /[?&]app\b/.test(location.search);
  if (appMode) document.body.classList.add('app');
  var installed = function (id) { var c = S.comps.filter(function (x) { return x.id === id; })[0]; return !!(c && c.cur); };
  var live = function () { return S.comps.filter(function (c) { return !SOON[c.id]; }); };
  var PAGES = ['home', 'discord', 'telegram', 'vless', 'proxy', 'wg', 'dns', 'fptn', 'security', 'updates', 'settings'];
  var SUFFIX = ['', 'ALT'];
  for (var q = 2; q <= 13; q++) SUFFIX.push('ALT' + q);
  SUFFIX = SUFFIX.concat(['EXP', 'FAKE TLS AUTO', 'FAKE TLS AUTO ALT', 'FAKE TLS AUTO ALT2', 'FAKE TLS AUTO ALT3', 'SIMPLE FAKE', 'SIMPLE FAKE ALT', 'SIMPLE FAKE ALT2']);
  var STRAT_DEFS = SUFFIX.map(function (s) {
    var g = !s ? 'Базовая' : /^ALT/.test(s) ? 'ALT' : s === 'EXP' ? 'Эксперимент' : /^FAKE/.test(s) ? 'Fake TLS' : 'Simple fake';
    return { f: s ? 'general (' + s + ')' : 'general', t: s || 'general', g: g };
  });
  var STRATS = STRAT_DEFS.map(function (s) { return s.f; });
  /* что проверяем (то же, что в zapret.rs): нужен, чтобы показать строки до первой проверки */
  var TARGETS = [
    { id: 'discord', label: 'Discord', host: 'discord.com' },
    { id: 'gateway', label: 'Discord: чат и голос', host: 'gateway.discord.gg' },
    { id: 'cdn', label: 'Discord: картинки', host: 'cdn.discordapp.com' },
    { id: 'youtube', label: 'YouTube', host: 'www.youtube.com' },
    { id: 'ytimg', label: 'YouTube: превью', host: 'i.ytimg.com' },
    { id: 'video', label: 'YouTube: видео', host: 'redirector.googlevideo.com' }
  ];
  var scanning = null, flash = null, testing = false, probing = false, testRan = [], testCancel = false;

  var S = {
    page: 'home',
    on: { discord: false, telegram: false, fptn: false, vless: false, proxy: false, wg: false },
    discord: { mode: 'auto', strategy: 'general (ALT2)', game: 'disabled', tcpPorts: '1024-65535', udpPorts: '1024-65535', custom: [], ipset: 'none', results: {}, free: null, scanHours: '0', scanLast: 0, autoupd: true, ipsetUpdated: 'ещё не обновляли' },
    telegram: { port: '1443', link: '' },
    fc: { token_in: '', bypass_method: 'sni-spoofing-yandex-26-4', strategy: 'rolling-tunnel', sni: 'google.com', mtu: '1420', preferred_server: '', tun_name: 'FPTN', tun_ip: '10.0.0.1', exclude_networks: '10.0.0.0/8,192.168.0.0/16', include_networks: '', split: false, split_mode: 'exclude', split_domains: '', adblock: true, blacklist: '', auto_gateway: true, remove_adapter: true, autostart: false },
    fptn: { tokenSet: false, hint: '', servers: [], ping: {}, pinging: '', pingAt: 0, tokenError: '', adapter: { exists: false, status: '', description: '' }, dirty: false, busy: false, repairMsg: '', logOpen: false, log: '' },
    v: { profiles: [], config: { active: '', mode: 'tun', socks_port: 10808, http_port: 10809, default_action: 'proxy', bypass_lan: true, dns: ['1.1.1.1', '8.8.8.8'], rules: [], subs: [], sub_auto: true, autoconnect: false, keep_on_exit: false }, running: false, tun: false, dirty: false, adapter: false, busy: false, ping: {}, pinging: {}, pingAt: 0, open: {}, noteOpen: {}, refreshing: '', repairMsg: '', logOpen: false, log: '', view: '', viewName: '', rule: { kind: 'app', value: '', action: 'proxy' }, socks: '10808', http: '10809', dns_text: '1.1.1.1, 8.8.8.8', loaded: false },
    dn: { presets: [], adapters: [], active: '', has_snapshot: false, config: { last: '', custom: ['', ''], ipv6: true, doh: false }, vpn: false, doh_supported: false, busy: false, loaded: false, off: [], ping: {}, pinging: false, c1: '', c2: '', msg: '' },
    p: { profiles: [], config: { active: '', mode: 'proxy', socks_port: 10818, http_port: 10819, default_action: 'proxy', bypass_lan: true, dns: ['1.1.1.1', '8.8.8.8'], rules: [], subs: [], sub_auto: false, autoconnect: false, keep_on_exit: false }, running: false, tun: false, dirty: false, adapter: false, busy: false, ping: {}, pinging: {}, pingAt: 0, repairMsg: '', logOpen: false, log: '', socks: '10818', http: '10819', dns_text: '1.1.1.1, 8.8.8.8', loaded: false },
    w: { profiles: [], config: { active: '', autoconnect: false, keep_on_exit: false, split_default: true }, running: false, tunnel: '', dirty: false, adapter: { exists: false, status: '', description: '' }, stats: { handshake_ago: null, rx: 0, tx: 0 }, busy: false, repairMsg: '', logOpen: false, log: '', paste: false, imp_name: 'wg0', imp_text: '', view: '', viewName: '' },
    tgc: { autostart: false, host: '127.0.0.1', port: '1443', secret: '', dc_ip: '2:149.154.167.220\n4:149.154.167.220', verbose: false, buf_kb: '256', pool_size: '4', log_max_mb: '5', log_backups: '1', cfproxy: true, h2: true, cf_domain_on: false, cf_domain: '', cf_worker_on: false, cf_worker: '', force_test_dc: false, no_secure: false, fake_tls_domain: '' },
    lists: {
      general: { file: 'list-general-user.txt', title: 'Свои домены', hint: 'Домены для обхода, по одному на строку. Поддомены учитываются автоматически.', text: '# по одному домену на строку\nexample.org\ncdn.example.org\n' },
      exclude: { file: 'list-exclude-user.txt', title: 'Исключения доменов', hint: 'Домены, которые не нужно обрабатывать, даже если их IP есть в ipset-all.txt.', text: '' },
      ipset: { file: 'ipset-all.txt', title: 'Свои IP и подсети', hint: 'IP-адреса и подсети для обхода, по одному на строку.', text: '# IP и подсети\n203.0.113.0/24\n' },
      ipsetEx: { file: 'ipset-exclude-user.txt', title: 'Исключения IP', hint: 'IP-адреса и подсети, которые не нужно обрабатывать.', text: '' }
    },
    tgp: { fw: { open: false, stale: false, known: false }, qr: { on: false, svg: '', url: '', until: 0 }, stats: null, check: null, checking: false },
    svc: { installed: false, running: false, strategy: '', foreign: false, busy: false },
    hosts: { installed: false, entries: 0, youtube: [], lines: [] },
    prof: {},
    sel: {},
    nextId: 100,
    uptime: 28 * 3600 + 32 * 60,
    logs: [
      { t: '14:32:11', svc: 'Zapret (Discord)', m: 'Запуск службы…' },
      { t: '14:32:12', m: 'Служба запущена. Соединение установлено.', ok: true },
      { t: '14:32:15', svc: 'Zapret (Telegram)', m: 'Запуск службы…' },
      { t: '14:32:16', m: 'Служба запущена. Соединение установлено.', ok: true },
      { t: '14:45:03', m: 'Проверка обновлений — доступно обновление Zapret (Telegram).' }
    ],
    comps: [
      { id: 'app', name: 'Бунт', cur: '0.1.0', next: null, checked: true, rel: { version: '0.1.0', url: 'https://github.com/belka-developer/bunt/releases', body: '## Первая версия\n- Запрет для Discord и YouTube на основе zapret-discord-youtube\n- Обновление Бунта одной кнопкой\n- Значок в трее' }, cls: 'b-app', icon: 'mark', size: '8.4 МБ', src: 'belka-developer/bunt (GitHub)', sha: 'a91c07d2e5b3…4f60', notes: [], busy: null },
      { id: 'discord', name: 'Zapret (Discord)', checked: true, cur: null, latest: '1.2.3', next: null, cls: 'b-discord', icon: 'chat', size: '12.4 МБ', src: 'Flowseal/zapret-discord-youtube (GitHub)', sha: '3f8e2c4d6a1b…9e07', notes: [], busy: null },
      { id: 'telegram', name: 'Zapret (Telegram)', cur: null, latest: '1.2.4', next: null, cls: 'b-telegram', icon: 'plane', size: '3.1 МБ', src: 'Flowseal/tg-ws-proxy (GitHub)', sha: '7be04a19c3d8…12ff', notes: [], busy: null },
      { id: 'fptn', name: 'FPTN', cur: null, latest: '0.4.6', next: null, cls: 'b-fptn', icon: 'tunnel', size: '58.5 МБ', src: 'fptn-project/fptn (GitHub)', sha: '–', notes: [], busy: null },
      { id: 'vless', name: 'VLESS (Xray-core)', cur: null, latest: '26.3.27', next: null, cls: 'b-vless', icon: 'net', size: '30 МБ', src: 'XTLS/Xray-core (GitHub)', sha: '–', notes: [], busy: null },
      { id: 'proxy', name: 'Proxy (Xray-core)', cur: null, latest: '26.3.27', next: null, cls: 'b-proxy', icon: 'wifi', size: '30 МБ', src: 'XTLS/Xray-core (GitHub)', sha: '–', notes: [], busy: null },
      { id: 'wg', name: 'WireGuard / AmneziaWG', cur: null, latest: '3.1.0', next: null, cls: 'b-wg', icon: 'vpn', size: '3.5 МБ', src: 'amnezia-vpn/amneziawg-windows-client (GitHub)', sha: '–', notes: [], busy: null }
    ],
    lastCheck: 'сегодня, 14:45',
    sec: { running: false, last: nowShort(), items: [
      { g: 'Файлы компонентов', t: 'Запрет Discord и YouTube: хеши файлов', st: 'ok', note: 'Проверено файлов: 64. Всё совпадает с установкой.' },
            { g: 'Скрипты', t: 'Запрет Discord и YouTube: скрипты', st: 'ok', note: 'Проверено скриптов: 21. Опасных команд не найдено.' },
      { g: 'Подписи', t: 'Запрет Discord и YouTube: подпись WinDivert64.sys', st: 'ok', note: 'Подписан: Basil00.' },
      { g: 'Службы и драйверы', t: 'Драйвер WinDivert', st: 'ok', note: 'Из папки Бунта, подписан: Basil00.' },
      { g: 'Автозапуск и система', t: 'Файл hosts', st: 'ok', note: 'Нет записей, которые перенаправляют Discord, YouTube, Telegram или GitHub.' },
      { g: 'Автозапуск и система', t: 'Сам Бунт', st: 'info', note: 'Бунт не подписан цифровой подписью, это нормально для программы с открытым кодом.' }
    ] },
    settings: { autostart: true, autostart_admin: false, tray: true, notify: true, autoupdate: true }
  };
  if (!inTauri) {   /* в обычном браузере показываем примерные серверы */
    S.fptn.tokenSet = true; S.fptn.hint = 'fptnb…demo';
    S.v.profiles = [
      ['Sweden', 'se', 's1', 'se1.example.net', 'reality'], ['Germany', 'de', 's1', 'de2.example.net', 'reality'], ['Netherlands', 'nl', 's1', 'nl1.example.net', 'tls'],
      ['Finland', 'fi', 's1', 'fi3.example.net', 'reality'], ['Russia', 'ru', 's2', 'ru1.example.org', 'reality'], ['Kazakhstan', 'kz', 's2', 'kz1.example.org', 'reality'],
      ['Home VPS', '', '', '203.0.113.7', 'reality'], ['USA', 'us', '', '198.51.100.20', 'tls']
    ].map(function (x, i) { return { id: 'p' + i, name: x[0], label: x[0], code: x[1], sub: x[2], address: x[3], port: 443, network: 'tcp', security: x[4], flow: '', ok: true, error: '' }; });
    S.v.config.active = 'p1';
    S.p.profiles = [['Офисный SOCKS5', 'socks5', '10.20.0.5', 1080, true], ['HTTP Германия', 'http', 'de.proxy.example', 8080, true], ['Открытый HTTPS', 'https', 'px.example.org', 443, false]].map(function (x, i) {
      return { id: 'x' + i, name: x[0], label: x[0], code: '', sub: '', address: x[2], port: x[3], network: 'tcp', security: 'none', flow: '', proto: x[1], auth: x[4], ok: true, error: '' };
    });
    S.p.config.active = 'x0';
    var nowS = Math.floor(Date.now() / 1000), GB = 1073741824;
    S.v.config.subs = [
      { id: 's1', name: 'Быстрый VPN', url: 'https://sub.example.net/abc', updated: nowS - 5400, count: 4, upload: 6 * GB, download: 71 * GB, total: 100 * GB, expire: nowS + 24 * 86400, has_usage: true, web: 'https://example.net/cabinet', support: 'https://t.me/example', announce: 'Уважаемые клиенты! Сервера в Германии временно недоступны из-за технических работ у провайдера. Используйте узлы в Нидерландах и Финляндии. Подробности и новости читайте в нашем канале поддержки.', interval: 24 },
      { id: 's2', name: 'Резервная подписка', url: 'https://sub.example.org/xyz', updated: nowS - 86400, count: 2, upload: 2 * GB, download: 19 * GB, total: 0, expire: 0, has_usage: true, seen: '', web: '', support: '', announce: 'Безлимит до конца месяца', interval: 0 }
    ];
    S.fptn.servers = [['Finland', 'fi'], ['Germany', 'de'], ['Netherlands', 'nl'], ['Sweden', 'se'], ['Kazakhstan', 'kz'], ['Server 6', '']].map(function (x, i) { return { name: x[0], label: x[0], code: x[1], host: '203.0.113.' + (10 + i), port: 443 }; });
  }

  var get = function (p) { return p.split('.').reduce(function (o, k) { return o[k]; }, S); };
  var set = function (p, v) { var a = p.split('.'); var k = a.pop(); a.reduce(function (o, x) { return o[x]; }, S)[k] = v; };

  /* уведомления */
  function toast(msg, kind) {
    var el = document.createElement('div');
    el.className = 'toast' + (kind ? ' ' + kind : '');
    el.textContent = msg;
    $('#toasts').appendChild(el);
    setTimeout(function () { el.remove(); }, 3400 + Math.min(String(msg).length, 700) * 20);
  }
  function addLog(e) { e.t = hms(); S.logs.push(e); if (S.logs.length > 80) S.logs.shift(); renderLog(); }

  /* отрисовка */
  function renderLog() {
    var ul = $('#log');
    if (!ul) return;
    ul.innerHTML = S.logs.map(function (l) {
      var body = l.svc ? '<span class="nm">' + esc(l.svc) + '</span> — ' + esc(l.m) : esc(l.m);
      return '<li class="' + (l.ok ? 'ok' : '') + '"><span class="t">[' + l.t + ']</span>' + (l.ok ? ico('check') : '') + '<span>' + body + '</span></li>';
    }).join('');
    ul.scrollTop = ul.scrollHeight;
  }

  function renderCards() {
    var meta = {
      fptn: function () { return [['Метод', S.fc.bypass_method === 'obfuscation' ? 'Обфускация' : 'SNI-маскировка'], ['Адаптер', S.fc.tun_name]]; },
      discord: function () { return [['Метод', 'winws'], ['Режим', S.discord.mode === 'auto' ? 'Авто' : 'Вручную']]; },
      telegram: function () { return [['Метод', 'MTProto-прокси'], ['Порт', String(S.telegram.port)]]; },
      vless: function () { var p = S.v.profiles.filter(function (x) { return x.id === S.v.config.active; })[0]; return [['Сервер', p ? p.name : 'Не выбран'], ['Режим', S.v.config.mode === 'proxy' ? 'Прокси' : 'TUN']]; },
      proxy: function () { var p = S.p.profiles.filter(function (x) { return x.id === S.p.config.active; })[0]; return [['Прокси', p ? p.name : 'Не выбран'], ['Режим', S.p.config.mode === 'proxy' ? 'Системный прокси' : 'TUN']]; },
      wg: function () { var a = S.w.config.active, p = S.w.profiles.filter(function (x) { return x.name === a; })[0]; return [['Профиль', a || 'Не выбран'], ['Тип', p ? (p.awg ? 'AmneziaWG' : 'WireGuard') : '–']]; }
    };
    var host = $('#cards');
    if (!host) return;
    host.innerHTML = IDS.map(function (id) {
      var on = S.on[id], s = SVC[id], ni = !SOON[id] && !installed(id);
      if (ni) return '<article class="card noinst"><div class="card-top"><button class="card-open" data-go="' + id + '"><span class="badge ' + s.cls + '">' + ico(s.icon) + '</span>' +
        '<span class="who"><span class="card-name">' + s.name + '</span><span class="state">Не установлено</span></span></button>' +
        '<button class="btn sm primary" data-act="installComp" data-arg="' + id + '">Установить</button></div>' +
        '<div class="meta"><div>Версия на GitHub: <b>' + esc(comp(id).latest) + '</b></div></div></article>';
      return '<article class="card ' + (on ? 'on' : '') + '">' +
        '<div class="card-top"><button class="card-open" data-go="' + id + '"><span class="badge ' + s.cls + '">' + ico(s.icon) + '</span>' +
        '<span class="who"><span class="card-name">' + s.name + '</span><span class="state ' + (on ? 'on' : '') + '">' + (on ? '<i class="dot"></i>Активен' : 'Отключен') + '</span></span></button>' +
        '<button class="sw" role="switch" data-svc="' + id + '" aria-label="' + s.name + '"></button></div>' +
        '<div class="meta">' + meta[id]().map(function (r) { return '<div>' + r[0] + ': <b>' + esc(r[1]) + '</b></div>'; }).join('') + '</div></article>';
    }).join('');
  }

  function renderHeads() {
    $$('[data-state]').forEach(function (el) {
      var on = S.on[el.dataset.state];
      el.className = 'state ' + (on ? 'on' : '');
      el.innerHTML = on ? '<i class="dot"></i>Активен' : 'Отключен';
    });
  }

  function renderInstall() {
    ['discord', 'telegram', 'fptn', 'wg', 'vless', 'proxy'].forEach(function (id) {
      var c = comp(id), ok = installed(id), box = $('#inst-' + id), body = document.querySelector('[data-body="' + id + '"]');
      if (!box || !body) return;
      box.hidden = ok; body.hidden = !ok;
      var sw = document.querySelector('.head-sw [data-svc="' + id + '"]');
      if (sw) sw.parentNode.hidden = !ok;
      document.querySelector('[data-latest="' + id + '"]').textContent = c.latest || '…';
      $('#instAct-' + id).innerHTML = c.busy != null
        ? '<span class="bar-track"><span class="bar-fill" style="width:' + c.busy + '%"></span></span><div class="note mt-s">' + (id === 'telegram' || id === 'fptn' || id === 'wg' || id === 'vless' || id === 'proxy' ? esc(c.stage || 'Готовим установку') + '… ' + c.busy + '%. Это займёт около минуты.' : 'Скачиваем и проверяем файлы… ' + c.busy + '%') + '</div>'
        : '<button class="btn primary" data-act="installComp" data-arg="' + id + '">' + ico('plus') + 'Установить</button>';
    });
  }

  function renderTray() {
    var rows = [
      ['mark', 'Открыть Бунт', 'home'],
      null,
      ['chat', 'Запрет Discord и YouTube' + (installed('discord') ? (S.on.discord ? ' · включён' : ' · выключен') : ''), 'discord'],
      ['plane', 'Запрет Telegram' + (installed('telegram') ? (S.on.telegram ? ' · включён' : ' · выключен') : ''), 'telegram'],
      ['tunnel', 'FPTN' + (installed('fptn') ? (S.on.fptn ? ' · подключён' : ' · отключён') : ''), 'fptn'],
      ['net', 'VLESS' + (installed('vless') ? (S.on.vless ? ' · подключён' : ' · отключён') : ''), 'vless'],
      ['wifi', 'Proxy' + (installed('proxy') ? (S.on.proxy ? ' · подключён' : ' · отключён') : ''), 'proxy'],
      ['vpn', 'WireGuard / AmneziaWG' + (installed('wg') ? (S.on.wg ? ' · подключён' : ' · отключён') : ''), 'wg'],
      ['globe', 'DNS' + (S.dn.loaded && S.dn.active ? ' · ' + (DN_ACTIVE[S.dn.active] || (S.dn.presets.filter(function (p) { return p.id === S.dn.active; })[0] || {}).name || '') : ''), 'dns'],
      null,
      ['download', 'Обновления', 'updates'],
      ['sliders', 'Настройки', 'settings']
    ];
    var h = rows.map(function (r) {
      if (!r) return '<li class="sep"></li>';
      return '<li><button ' + (r[2] ? 'data-go="' + r[2] + '"' : 'disabled') + '>' + ico(r[0]) + r[1] + '</button></li>';
    }).join('');
    h += '<li class="sep"></li><li><button data-act="exitApp">' + ico('x') + 'Выход</button></li>';
    $('#trayList').innerHTML = h;
    var n = IDS.filter(function (id) { return S.on[id]; }).length;
    $('#trayIcons').textContent = 'Служб активно: ' + n;
  }

  function renderSide() {
    var n = live().filter(function (c) { return c.next; }).length;
    var p = $('#sidePill');
    var dot = $('#navDot');
    if (dot) dot.hidden = !n;
    if (isChecking()) { p.className = 'pill'; p.innerHTML = '<span class="spin"></span>Проверяем обновления…'; }
    else if (n) { p.className = 'pill warn'; p.innerHTML = ico('refresh') + 'Доступно обновлений: ' + n; }
    else { p.className = 'pill'; p.innerHTML = ico('check') + 'Все системы работают'; }
  }

  function validPorts(s) {
    s = String(s).trim();
    if (!s || s.length > 120) return false;
    return s.split(',').every(function (p) {
      var m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(p.trim());
      if (!m) return false;
      var a = +m[1], b = m[2] ? +m[2] : a;
      return a >= 1 && b <= 65535 && a <= b;
    });
  }
  function targetsAll() {
    return TARGETS.concat((S.discord.custom || []).map(function (h) { return { id: 'custom:' + h, label: h, host: h }; }));
  }

  function renderDiscord() {
    var d = S.discord;
    $('#stratNow').textContent = d.strategy;
    var cr = d.results[d.strategy];
    $('#stratWhen').textContent = (d.mode === 'auto' ? 'Подобрана автоматически' : 'Выбрана вручную') + ' · ' +
      (cr && !cr.error ? 'проверена ' + fmtAt(cr.at) + ': открывается ' + okCount(cr) + ' из ' + cr.checks.length : cr ? 'не запустилась при проверке' : 'ещё не проверялась');
    $('#btnTest').disabled = testing;
    $('#btnCheck').disabled = testing;
    $('#btnCancel').hidden = !testing;
    $('#btnProbe').disabled = testing || probing;
    var sh = Number(d.scanHours) || 0;
    $('#scanInfo').textContent = !sh ? 'Раз в выбранное время Бунт проверяет текущую стратегию и, если что-то перестало открываться, подбирает другую'
      : (S.on.discord ? 'Последняя: ' + (d.scanLast ? fmtAt(d.scanLast) : 'ещё не было') + '. Если что-то перестанет открываться, Бунт подберёт другую стратегию'
        : 'Работает, пока включён запрет и открыт Бунт');
    $('#stratLine').hidden = testing;
    $('#stratWhen').hidden = testing;
    $('#testBox').hidden = !testing;
    $('#ipsetWarn').hidden = d.ipset !== 'any';
    $('#ipsetDesc').textContent = { none: 'none: IP-адреса не проверяются', loaded: 'loaded: IP проверяется по списку ipset-all.txt', any: 'any: любой IP попадает под фильтр' }[d.ipset];
    $('#ipsetUpd').textContent = d.ipsetUpdated;
    $('#gameDesc').textContent = { disabled: 'Обход для игр и других сервисов выключен', all: 'Обход для игр на TCP и UDP, порты из полей ниже', tcp: 'Обход только для TCP-соединений', udp: 'Обход только для UDP-соединений' }[d.game] + '. После переключения запрет перезапускается.';
    $('#gamePorts').hidden = d.game === 'disabled';
    $('#gpTcp').hidden = d.game === 'udp';
    $('#gpUdp').hidden = d.game === 'tcp';
    renderDiscordExtras();
    $('#dVer').textContent = comp('discord').cur || '–';
    $('#lists').innerHTML = Object.keys(S.lists).map(function (k) {
      var l = S.lists[k], ed = l.editable !== false;
      var n = l.count != null ? l.count : l.text.split('\n').map(function (x) { return x.trim(); }).filter(function (x) { return x && x.charAt(0) !== '#'; }).length;
      return '<div class="row"><div class="lbl">' + esc(l.title) + '<small class="mono">' + esc(l.file) + '</small></div><div class="inl"><span class="tag">записей: ' + n + '</span><button class="btn sm" data-act="editList" data-arg="' + k + '">' + (ed ? 'Редактировать' : 'Открыть') + '</button></div></div>';
    }).join('');
    $('#strats').innerHTML = STRAT_DEFS.map(function (s) {
      var r = d.results[s.f], cur = d.strategy === s.f;
      var cls = (cur ? 'cur ' : '') + (scanning === s.f || (probing && cur && S.on.discord) ? 'scan ' : '') + (flash === s.f ? 'win' : '');
      return '<button class="strat ' + cls + '" data-strat="' + esc(s.f) + '" aria-pressed="' + cur + '">' +
        '<span class="shd"><span class="sg">' + s.g + '</span>' + stratTag(r) + '</span>' +
        '<span class="sn">' + (cur ? ico('check') : '') + esc(s.t) + '</span>' +
        '<span class="sf">' + esc(s.f) + '.bat</span></button>';
    }).join('');
    var free = !S.on.discord && d.free && (!cr || d.free.at >= cr.at) ? d.free : null;
    var src = free || cr;
    $('#tgtWho').textContent = free ? 'Без запрета · проверено ' + fmtAt(free.at)
      : cr ? 'Стратегия ' + d.strategy + ' · проверено ' + fmtAt(cr.at) + (S.on.discord ? '' : ' · запрет сейчас выключен')
      : 'Для стратегии ' + d.strategy + ' проверок ещё не было. Нажмите «Проверить» или «Проверить стратегии».';
    if (src && src.error) {
      $('#targets').innerHTML = '<p class="note warn">Не удалось запустить стратегию: ' + esc(src.error) + '</p>';
    } else {
      var byId = {};
      (src ? src.checks : []).forEach(function (c) { byId[c.id] = c; });
      $('#targets').innerHTML = targetsAll().map(function (t) {
        var c = byId[t.id];
        return '<div class="tgt"><span class="tl">' + esc(t.label) + '<small class="mono">' + t.host + '</small></span>' +
          '<span class="ms">' + (c && c.ok ? c.ms + ' мс' : '') + '</span>' +
          (c ? '<span class="tag ' + (c.ok ? 'ok' : 'bad') + '">' + (c.ok ? 'Открывается' : 'Недоступен') + '</span>' : '<span class="tag">–</span>') + '</div>';
      }).join('');
    }
  }

  /* результаты проверки стратегий */
  function pad2(n) { return (n < 10 ? '0' : '') + n; }
  function fmtAt(sec) {
    if (!sec) return '';
    var dt = new Date(sec * 1000), n = new Date(), t = pad2(dt.getHours()) + ':' + pad2(dt.getMinutes());
    if (dt.toDateString() === n.toDateString()) return 'сегодня, ' + t;
    return pad2(dt.getDate()) + '.' + pad2(dt.getMonth() + 1) + ', ' + t;
  }
  function okCount(r) { return r.checks.filter(function (c) { return c.ok; }).length; }
  function avgMs(r) {
    var v = r.checks.filter(function (c) { return c.ok; }).map(function (c) { return c.ms; });
    return v.length ? v.reduce(function (a, b) { return a + b; }, 0) / v.length : 1e9;
  }
  function stratTag(r) {
    if (!r) return '<span class="tw"><span class="tag">–</span><span class="tip" role="tooltip"><span class="tn">Эту стратегию ещё не проверяли</span></span></span>';
    if (r.error) return '<span class="tw"><span class="tag bad">ошибка</span><span class="tip" role="tooltip"><span class="tn">' + esc(r.error) + '</span></span></span>';
    var n = okCount(r), total = r.checks.length;
    var rows = r.checks.map(function (c) {
      return '<span class="tr ' + (c.ok ? 'ok' : 'bad') + '"><i>' + (c.ok ? '✓' : '✗') + '</i><span>' + esc(c.label) + '</span><b>' + (c.ok ? c.ms + ' мс' : 'нет ответа') + '</b></span>';
    }).join('');
    return '<span class="tw"><span class="tag ' + (n === total ? 'ok' : n >= total - 2 ? 'warn' : 'bad') + '">' + n + '/' + total + '</span>' +
      '<span class="tip" role="tooltip">' + rows + '<span class="tn">Проверено ' + fmtAt(r.at) + '</span></span></span>';
  }
  function applyResults(res) { S.discord.results = (res && res.results) || {}; }
  function demoChecks(name) {
    var h = 0;
    for (var i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
    var n = h % 7;
    return targetsAll().map(function (t, k) { var ok = k < n; return { id: t.id, label: t.label, host: t.host, ok: ok, ms: ok ? 60 + ((h >> k) % 90) : null }; });
  }
  function onTestEvent(p) {
    if (!testing) return;
    var bar = $('#testBox .bar-fill');
    if (p.phase === 'start') {
      scanning = p.name;
      $('#testState').textContent = 'Проверяем ' + p.name + ' (' + (p.index + 1) + ' из ' + p.total + ')';
      if (bar) bar.style.width = (p.index / p.total * 100) + '%';
    } else {
      testRan.push(p.name);
      if (bar) bar.style.width = ((p.index + 1) / p.total * 100) + '%';
      if (inTauri) T.core.invoke('zapret_results').then(function (r) { applyResults(r); renderDiscord(); }).catch(function () {});
    }
    renderDiscord();
    var el = $('.strat.scan');
    if (el && el.scrollIntoView) el.scrollIntoView({ block: 'nearest' });
  }
  /* автопроверка по расписанию: смотрим текущую стратегию, при сбое подбираем другую */
  function scanSave(patch) {
    if (inTauri) T.core.invoke('zapret_scan_set', patch).catch(function () {});
  }
  function scanDue() {
    var d = S.discord, h = Number(d.scanHours) || 0;
    if (!inTauri || !h || !S.on.discord || !installed('discord') || testing || probing || S.admin === false || vpnRunning()) return false;
    return Math.floor(Date.now() / 1000) - d.scanLast >= h * 3600;
  }
  function autoScan() {
    var d = S.discord, h = Number(d.scanHours) || 0, now = Math.floor(Date.now() / 1000);
    d.scanLast = now; scanSave({ last: now });
    probing = true; renderDiscord();
    T.core.invoke('zapret_probe').then(function (r) {
      probing = false;
      if (r.strategy) d.results[r.strategy] = { at: r.at, checks: r.checks, error: null };
      var n = r.checks.filter(function (c) { return c.ok; }).length;
      if (n === r.checks.length) {
        addLog({ svc: 'Zapret (Discord)', m: 'Автопроверка: на стратегии ' + d.strategy + ' открываются все сервисы.', ok: true });
        renderDiscord();
      } else if (n === 0) {
        /* скорее всего нет интернета: не перебираем стратегии, повторим через 15 минут */
        var back = Math.max(0, h * 3600 - 900);
        d.scanLast = now - back; scanSave({ last: d.scanLast });
        addLog({ svc: 'Zapret (Discord)', m: 'Автопроверка: ни один сервис не ответил. Возможно, нет интернета. Повторим позже.' });
        renderDiscord();
      } else {
        addLog({ svc: 'Zapret (Discord)', m: 'Автопроверка: на стратегии ' + d.strategy + ' открывается ' + n + ' из ' + r.checks.length + '. Подбираем другую…' });
        renderDiscord();
        runTest(false);
      }
    }).catch(function () { probing = false; renderDiscord(); });
  }
  setInterval(function () { if (scanDue()) autoScan(); }, 60000);

  /* дополнительные возможности запрета: службы, hosts, фейки, диагностика */
  function renderDiscordExtras() {
    var v = S.svc, d = S.discord, h = S.hosts;
    var tag = $('#svcTag'), desc = $('#svcDesc'), btns = $('#svcBtns');
    if (!tag) return;
    if (v.foreign) {
      tag.className = 'tag warn'; tag.textContent = 'Чужая служба';
      desc.textContent = 'Служба zapret поставлена не из Бунта (например, через service.bat). Когда будете включать запрет в Бунте, он предложит её убрать.';
      btns.innerHTML = '';
    } else if (v.installed) {
      tag.className = 'tag ' + (v.running ? 'ok' : ''); tag.textContent = v.running ? 'Работает' : 'Остановлена';
      desc.textContent = 'Запрет запускается вместе с Windows, даже когда Бунт закрыт. Стратегия службы: ' + (v.strategy || 'неизвестна') + '. Чтобы применить другую стратегию или фильтры, переустановите службу.';
      btns.innerHTML = '<button class="btn sm" data-act="svcInstall"' + (v.busy ? ' disabled' : '') + '>Переустановить</button><button class="btn sm" data-act="svcRemove"' + (v.busy ? ' disabled' : '') + '>Удалить службу</button>';
    } else {
      tag.className = 'tag'; tag.textContent = 'Не установлена';
      desc.textContent = 'Служба запускает запрет вместе с Windows, без Бунта. Она использует выбранную сейчас стратегию и фильтры. Пока служба установлена, стратегию в Бунте не поменять, её нужно переустановить.';
      btns.innerHTML = '<button class="btn sm primary" data-act="svcInstall"' + (v.busy || !inTauri ? ' disabled' : '') + '>Установить службу</button>';
    }
    $('#hostsDesc').textContent = (h.installed ? 'Записи Бунта добавлены (' + h.entries + '). ' : 'Не добавлены. Нужны для голосового чата Discord и Telegram Web. ') + (h.youtube.length ? 'В hosts есть записи про YouTube, они могут мешать.' : '');
    $('#customDesc').textContent = d.custom.length ? 'Добавлено сайтов: ' + d.custom.length : 'К шести встроенным адресам можно добавить свои';
  }
  function refreshDiscordExtras() {
    if (!inTauri || !installed('discord')) return;
    T.core.invoke('zapret_lists').then(function (r) {
      var o = {};
      r.lists.forEach(function (l) { o[l.key] = { file: l.file, title: l.title, hint: l.hint, text: l.text, count: l.count, editable: l.editable }; });
      S.lists = o;
      S.discord.ipsetUpdated = r.ipset_updated ? fmtAt(r.ipset_updated) : 'ещё не обновляли';
      renderDiscord();
    }).catch(function () {});
    T.core.invoke('zapret_service_status').then(function (r) { S.svc.installed = r.installed; S.svc.running = r.running; S.svc.strategy = r.strategy || ''; S.svc.foreign = r.foreign; renderDiscord(); }).catch(function () {});
    T.core.invoke('zapret_hosts_status').then(function (r) { S.hosts.installed = r.installed; S.hosts.entries = r.entries; S.hosts.youtube = r.youtube || []; renderDiscord(); }).catch(function () {});
    T.core.invoke('zapret_targets_get').then(function (r) { S.discord.custom = r || []; renderDiscord(); }).catch(function () {});
  }
  function onlyInApp() { toast('Это работает только в приложении.', 'warn'); }
  function failToast(e) { toast(String(e).slice(0, 220), 'warn'); }
  function vpnRunning() { return VPNS.filter(function (id) { return S.on[id]; }).length > 0; }

  function renderTelegram() {
    var p = String(S.tgc.port).replace(/\D/g, '') || '1443';
    $('#tgLink').value = S.telegram.link || (inTauri ? '' : 'tg://proxy?server=127.0.0.1&port=' + p + '&secret=dd00000000000000000000000000000000');
    var tv = $('#tVer'); if (tv) tv.textContent = comp('telegram').cur || '–';
    renderTgExtras();
  }

  /* телефон в локальной сети, QR-код, состояние прокси */
  function tgIsLan() { return ['127.0.0.1', 'localhost', '::1', ''].indexOf(String(S.tgc.host).trim()) < 0; }
  function renderTgExtras() {
    var sw = $('#tgLanSw'); if (!sw) return;
    var lan = tgIsLan(), p = S.tgp;
    sw.setAttribute('aria-checked', lan ? 'true' : 'false');
    $('#tgLanDesc').textContent = lan ? 'Прокси слышит все устройства в вашей сети (адрес ' + S.tgc.host + '). Подключайте только доверенные сети.' : 'Сейчас прокси работает только на этом компьютере. Включите, чтобы подключить телефон.';
    $('#tgPhoneHint').textContent = lan ? 'Телефон должен быть в той же сети Wi-Fi. Откройте порты, нажмите «Показать QR-код» и наведите на него камеру.' : 'Чтобы использовать запрет на телефоне, включите «Доступ из локальной сети» выше.';
    var fw = p.fw, tag = $('#tgFwTag'), btn = $('#tgFwBtn');
    tag.className = 'tag ' + (fw.open ? 'ok' : fw.stale ? 'warn' : '');
    tag.textContent = !fw.known ? '…' : fw.open ? 'Открыты' : fw.stale ? 'Устарели' : 'Закрыты';
    $('#tgFwDesc').textContent = fw.stale ? 'Порт прокси изменился, обновите правило' : 'Открываются только для устройств вашей подсети. Нужны права администратора';
    btn.textContent = fw.open ? 'Закрыть порты' : fw.stale ? 'Обновить порты' : 'Открыть порты';
    btn.disabled = !lan || !inTauri;
    $('#tgQrBtn').textContent = p.qr.on ? 'Скрыть QR-код' : 'Показать QR-код';
    $('#tgQrBtn').disabled = !lan || !inTauri;
    $('#tgQrBox').hidden = !p.qr.on;
    if (p.qr.on) {
      $('#tgQrImg').innerHTML = p.qr.svg;
      $('#tgQrUrl').textContent = p.qr.url;
      var left = Math.max(0, Math.round((p.qr.until - Date.now()) / 1000));
      $('#tgQrNote').textContent = 'Наведите камеру телефона на код. Страница отключится через ' + Math.floor(left / 60) + ':' + pad2(left % 60) + ', потому что на ней виден секрет.' + (fw.open ? '' : ' Порты в брандмауэре закрыты, телефон может не подключиться.');
    }
    var st = p.stats;
    $('#tgStats').textContent = st ? 'Подключений: ' + st.total + ', сейчас: ' + st.active + '. Трафик: ↑ ' + st.up + ', ↓ ' + st.down + '. Через Cloudflare: ' + st.cf + ', ошибок: ' + st.err + '. Обновлено ' + (st.at || '').slice(11, 16) + '.' : (S.on.telegram ? 'Статистика появится через минуту после запуска: прокси пишет её в лог раз в минуту.' : 'Прокси выключен.');
    $('#tgCheckBtn').disabled = p.checking;
    var c = p.check;
    $('#tgChecks').innerHTML = !c ? '' :
      '<div class="tgt"><span>Прокси запущен</span><span class="tag ' + (c.running ? 'ok' : 'bad') + '">' + (c.running ? 'Да' : 'Нет') + '</span></div>' +
      '<div class="tgt"><span>Порт отвечает</span><span class="tag ' + (c.listening ? 'ok' : 'bad') + '">' + (c.listening ? 'Да' : 'Нет') + '</span></div>' +
      c.hosts.map(function (x) { return '<div class="tgt"><span class="mono">' + esc(x.host) + '</span><span class="ms">' + (x.ok ? x.ms + ' мс' : '') + '</span><span class="tag ' + (x.ok ? 'ok' : 'bad') + '">' + (x.ok ? 'Доступен' : 'Нет ответа') + '</span></div>'; }).join('');
  }
  function refreshTgExtras() {
    if (!inTauri || !installed('telegram')) return;
    T.core.invoke('telegram_firewall_status').then(function (r) { S.tgp.fw = { open: r.open, stale: r.stale, known: true }; renderTgExtras(); }).catch(function () { S.tgp.fw.known = true; renderTgExtras(); });
    T.core.invoke('telegram_stats').then(function (r) { S.tgp.stats = r; renderTgExtras(); }).catch(function () {});
  }
  function stopQr() {
    if (!S.tgp.qr.on) return;
    S.tgp.qr.on = false;
    if (inTauri) T.core.invoke('telegram_share_stop').catch(function () {});
  }
  setInterval(function () {
    if (S.tgp.qr.on) {
      if (Date.now() >= S.tgp.qr.until) { stopQr(); toast('Страница для телефона отключена'); }
      if (S.page === 'telegram') renderTgExtras();
    }
  }, 1000);
  setInterval(function () {
    if (inTauri && S.page === 'telegram' && S.on.telegram) T.core.invoke('telegram_stats').then(function (r) { S.tgp.stats = r; renderTgExtras(); }).catch(function () {});
  }, 15000);

  /* упрощённый разбор описания релиза: заголовки, списки, жирный текст */
  function md(src) {
    var out = [], list = false;
    function inline(s) { return esc(s).replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/`(.+?)`/g, '<span class="mono">$1</span>').replace(/\[(.+?)\]\(.+?\)/g, '$1'); }
    String(src || '').replace(/\r/g, '').split('\n').forEach(function (line) {
      var m;
      if ((m = /^\s*[-*]\s+(.*)$/.exec(line))) { if (!list) { out.push('<ul>'); list = true; } out.push('<li>' + inline(m[1]) + '</li>'); return; }
      if (list) { out.push('</ul>'); list = false; }
      if ((m = /^#{1,4}\s+(.*)$/.exec(line))) out.push('<h4>' + inline(m[1]) + '</h4>');
      else if (line.trim()) out.push('<p>' + inline(line) + '</p>');
    });
    if (list) out.push('</ul>');
    return out.join('');
  }
  function renderNotes() {
    var host = $('#homeNotes');
    if (!host) return;
    host.innerHTML = live().filter(function (c) { return c.cur && c.rel; }).map(function (c) {
      var r = c.rel, state = c.next ? '<span class="tag warn">есть новая</span>' : (c.cur === r.version ? '<span class="tag ok">установлена</span>' : '');
      return '<div class="panel notes-panel"><div class="panel-head"><h3>Что нового · ' + esc(c.name) + '</h3><span class="inl"><span class="ver">' + esc(r.version) + '</span>' + state + '</span></div>' +
        '<div class="notes">' + (r.body && r.body.trim() ? md(r.body) : '<p>Описание к этой версии не указано.</p>') + '</div>' +
        '<div class="notes-foot"><span class="note">' + (r.published ? 'Опубликовано: ' + esc(String(r.published).slice(0, 10)) : '') + '</span><button class="btn sm" data-url="' + esc(r.url) + '">Все изменения на GitHub</button></div></div>';
    }).join('');
    var n = live().filter(function (c) { return c.next; });
    var b = $('#homeUpd');
    b.hidden = !n.length;
    if (n.length) b.innerHTML = '<span><b>Доступно обновлений: ' + n.length + '</b> · ' + n.map(function (c) { return esc(c.name) + ' ' + esc(c.next); }).join(', ') + '</span><button class="btn sm primary" data-go="updates">Открыть обновления</button>';
  }
  function loadNotes() {
    if (!inTauri) return;
    ['app', 'discord', 'telegram', 'fptn', 'wg', 'vless', 'proxy'].forEach(function (id) {
      var c = comp(id);
      if (!c || (id !== 'app' && !c.cur)) return;
      T.core.invoke('release_notes', { id: id }).then(function (n) {
        c.rel = { version: n.version, body: n.body, url: n.url, published: n.published };
        renderNotes();
      }).catch(function () { /* без сети заметок нет */ });
    });
  }
  function isChecking() { return checking || startPending; }
  var startPending = false;
  function openUrl(u) {
    if (inTauri) T.core.invoke('open_url', { url: u }).catch(function (e) { toast(String(e), 'warn'); });
    else window.open(u, '_blank', 'noopener');
  }
  /* настройки сохраняются сразу при переключении */
  function saveSettings() {
    if (!inTauri) return;
    T.core.invoke('settings_set', { settings: S.settings }).then(function (s) { S.settings = s; sync(); renderAutostart(); }).catch(function (err) {
      toast(String(err).slice(0, 200), 'warn');
      T.core.invoke('settings_get').then(function (s) { S.settings = s; sync(); renderAutostart(); });
    });
  }
  /* автозапуск: запись в «Автозагрузке» диспетчера задач, Бунт стартует без прав администратора */
  function renderAutostart() {
    var el = $('#autoInfo'), ad = $('#autoAdminInfo');
    if (!el) return;
    if (!inTauri) { el.textContent = ''; if (ad) ad.textContent = ''; return; }
    var base = 'Бунт стартует вместе с Windows в трее и без прав администратора, а в окне предложит их дать. ';
    el.textContent = base;
    T.core.invoke('autostart_exists').then(function (ok) {
      el.textContent = base + (ok ? 'Запись в автозагрузке создана.' : 'Запись в автозагрузке не создана.');
    }).catch(function () {});
    if (ad) {
      ad.textContent = '';
      if (S.settings.autostart_admin) T.core.invoke('autostart_task').then(function (ok) {
        ad.textContent = ok === true ? 'Задача в планировщике создана.' : ok === false ? 'Задача в планировщике не найдена: выключите и включите переключатель заново.' : 'Задачу можно проверить только с правами администратора.';
        ad.className = ok === false ? 'warn-text' : '';
      }).catch(function () {});
    }
  }
  /* права администратора: без них запрет и установка компонентов не работают */
  function renderAdmin() {
    var b = $('#adminBanner');
    if (b) b.hidden = !(inTauri && S.admin === false);
  }
  function adminNeeded(quiet) {
    if (!(inTauri && S.admin === false)) return false;
    if (!quiet) {
      toast('Нужны права администратора. Нажмите «Дать права» вверху окна.', 'warn');
      var b = $('#adminBanner');
      if (b) { b.classList.remove('flash'); void b.offsetWidth; b.classList.add('flash'); }
    }
    return true;
  }
  function elevate() {
    T.core.invoke('relaunch_as_admin').then(function () {
      toast('Подтвердите запрос Windows. Бунт перезапустится с правами администратора.');
    }).catch(function (e) { toast(String(e).slice(0, 160), 'warn'); });
  }
  var trayLast = null;
  function syncTray() {
    if (!inTauri || trayLast === !!S.on.discord) return;
    trayLast = !!S.on.discord;
    T.core.invoke('tray_set_discord', { on: trayLast }).catch(function () {});
  }
  function renderVersions() {
    $('#lastCheck').textContent = S.lastCheck;
    var ve = $('#verErr');
    ve.hidden = !S.verErr;
    ve.textContent = S.verErr ? 'Не удалось проверить обновления: ' + S.verErr : '';
    $('#verList').innerHTML = live().map(function (c) {
      var unchecked = !c.checked && (c.id === 'app' || REAL[c.id]);
      var latest = c.next || (unchecked ? '…' : (c.cur || c.latest || '…')), stat;
      if (c.busy != null) stat = '<span class="tag">' + c.busy + '%</span>';
      else if (!c.cur) stat = '<button class="btn sm primary" data-act="installComp" data-arg="' + c.id + '">Установить</button>';
      else if (c.next) stat = '<button class="btn sm primary" data-act="updateOne" data-arg="' + c.id + '">Обновить</button>';
      else if (unchecked) stat = isChecking() ? '<span class="tag"><span class="spin"></span>Проверяем…</span>' : '<span class="tag">Не проверено</span>';
      else stat = '<span class="tag ok">Актуально</span>';
      return '<div class="vrow"><div class="vwho"><span class="badge sm ' + c.cls + '">' + ico(c.icon) + '</span>' +
        '<span class="pn"><b>' + c.name + (appMode && c.demo ? ' <span class="tag">демо</span>' : '') + '</b><small>' + esc(c.src) + '</small></span></div>' +
        '<div class="vcell"><small>Установлено</small><span class="v">' + (c.cur || 'Не установлено') + '</span></div>' +
        '<div class="vcell"><small>На GitHub</small><span class="v ' + (c.next ? 'new' : '') + '">' + latest + '</span></div>' +
        '<div class="vstat">' + stat + '</div>' +
        (c.busy != null ? '<div class="vbar"><span class="bar-track"><span class="bar-fill" style="width:' + Math.max(c.busy, 3) + '%"></span></span><small>' + esc(c.stage ? c.stage + '…' : 'Загрузка…') + '</small></div>' : '') +
        (inTauri && REAL[c.id] && c.cur && c.busy == null ? '<div class="vmore"><button class="btn sm" data-act="reinstallAsk" data-arg="' + c.id + '">Переустановить</button><button class="btn sm danger" data-act="uninstallAsk" data-arg="' + c.id + '">Удалить</button></div>' : '') +
        '</div>';
    }).join('');
  }

  function renderSecurity() {
    var run = S.sec.running, items = S.sec.items;
    var bad = items.some(function (i) { return i.st === 'bad'; });
    var warn = items.some(function (i) { return i.st === 'warn'; });
    var done = items.length && items.every(function (i) { return i.st !== 'idle' && i.st !== 'run'; });
    $('#secIco').className = 'sec-ico' + (run ? ' run' : bad ? ' bad' : warn ? ' warn' : '');
    $('#secTitle').textContent = run ? 'Идёт проверка…' : !done ? 'Проверка ещё не запускалась' : bad ? 'Найдены изменения в файлах' : warn ? 'Есть замечания' : 'Всё в порядке';
    $('#secText').textContent = run ? 'Проверяем файлы, скрипты, подписи, службы и автозапуск.' : !done ? 'Нажмите «Быстрая проверка». Она же запускается сама при старте Бунта.' : bad ? 'Что-то изменено или подложено. Подробности ниже: переустановите затронутый компонент.' : warn ? 'Есть замечания, подробности в списке ниже.' : 'Файлы, скрипты, драйверы и автозапуск в порядке.';
    $('#secLast').textContent = S.sec.last;
    $('#btnSec').disabled = run;
    var bo = $('#btnSecOnline'); if (bo) bo.disabled = run;
    var fix = $('#secFix');
    if (fix) fix.innerHTML = (bad && !run && inTauri) ? ['discord', 'telegram', 'fptn', 'wg', 'vless', 'proxy'].filter(installed).map(function (id) {
      return '<div class="sec-fix"><span>Файлы компонента «' + esc(comp(id).name) + '» отличаются от оригинала. Лучше всего переустановить его.</span><button class="btn sm primary" data-act="reinstallAsk" data-arg="' + id + '">Переустановить</button></div>';
    }).join('') : '';
    var RES = { ok: 'OK', warn: 'Внимание', bad: 'Нарушено', info: 'Заметка', run: 'Проверяю…', idle: 'Ожидает' };
    var ICO = { ok: 'check', warn: 'alert', bad: 'alert', info: 'shield', idle: 'clock' };
    var nav = document.querySelector('.nav[data-go="security"]'); if (nav) nav.classList.toggle('alert', bad && !run);
    var lastG = '';
    $('#secList').innerHTML = items.map(function (i) {
      var lead = i.st === 'run' ? '<span class="spin"></span>' : ico(ICO[i.st] || 'check');
      var head = '';
      if (i.g && i.g !== lastG) { lastG = i.g; head = '<div class="sec-group">' + esc(i.g) + '</div>'; }
      return head + '<div class="sec-item ' + i.st + '">' + lead + '<span>' + esc(i.t) + (i.note ? '<small>' + esc(i.note) + '</small>' : '') + '</span><span class="res">' + (RES[i.st] || '') + '</span></div>';
    }).join('');
  }


  function sync() {
    $$('.sw[data-svc]').forEach(function (b) { b.setAttribute('aria-checked', String(!!S.on[b.dataset.svc])); });
    $$('[data-sw]').forEach(function (b) { b.setAttribute('aria-checked', String(!!get(b.dataset.sw))); });
    $$('[data-seg]').forEach(function (g) {
      var v = get(g.dataset.seg);
      $$('button', g).forEach(function (b) { b.setAttribute('aria-pressed', String(b.dataset.v === v)); });
    });
    $$('[data-bind]').forEach(function (el) { if (document.activeElement !== el) el.value = get(el.dataset.bind); });
  }

  function renderAll() {
    renderSide(); renderCards(); renderTray(); renderHeads(); renderLog();
    renderInstall(); renderDiscord(); renderTelegram(); renderFptn(); renderWg(); renderDn(); renderVless(); renderProxy();
    renderVersions(); renderNotes(); renderSecurity(); renderAdmin(); sync(); syncTray();
  }

  function go(page) {
    if (PAGES.indexOf(page) < 0) page = 'home';
    S.page = page;
    if (page === 'dns') loadDn();
    if (page === 'fptn' && S.fptn.servers.length) fAutoPing();
    if (page === 'vless' && S.v.profiles.length) vAutoPing();
    if (page === 'proxy' && S.p.profiles.length) pAutoPing();
    if (page === 'discord') refreshDiscordExtras();
    if (page === 'telegram') refreshTgExtras(); else stopQr();
    $$('[data-page]').forEach(function (s) { s.hidden = s.dataset.page !== page; });
    $$('.nav').forEach(function (n) { if (n.dataset.go === page) n.setAttribute('aria-current', 'page'); else n.removeAttribute('aria-current'); });
    try { history.replaceState(null, '', '#' + page); } catch (e) { /* без адреса */ }
  }

  /* службы */
  function setSvc(id, on, quiet) {
    if (SOON[id]) { if (!quiet) toast('Этот раздел скоро появится.', 'warn'); return false; }
    if (S.on[id] === on) return false;
    if (on && !installed(id)) {
      if (!quiet) { toast('Сначала установите компонент.', 'warn'); go(id); }
      return false;
    }
    if (on && VPNS.indexOf(id) >= 0 && vpnConflict(id, quiet)) return false;
    if (inTauri && id === 'discord') {
      if (testing) { if (!quiet) toast('Идёт проверка стратегий, дождитесь завершения.', 'warn'); return false; }
      realDiscord(on, quiet); return true;
    }
    if (inTauri && id === 'telegram') { realTelegram(on, quiet); return true; }
    if (inTauri && id === 'fptn') { realFptn(on, quiet); return true; }
    if (inTauri && id === 'wg') { realWg(on, quiet); return true; }
    if (inTauri && id === 'vless') { realVless(on, quiet); return true; }
    if (inTauri && id === 'proxy') { realProxy(on, quiet); return true; }
    S.on[id] = on;
    var n = SVC[id].name;
    if (on) {
      addLog({ svc: n, m: 'Запуск службы…' });
      setTimeout(function () { if (S.on[id]) addLog({ m: 'Служба запущена. Соединение установлено.', ok: true }); }, 700);
    } else {
      addLog({ svc: n, m: 'Служба остановлена.' });
    }
    renderAll();
    return true;
  }
  /* настоящий запуск и остановка winws */
  var zBusy = false;
  /* запрет уже работает не из Бунта (служба Flowseal или другой winws): предлагаем перейти на Бунт */
  function askTakeOver(f) {
    var what = [];
    if (f.service) what.push('служба <b class="mono">zapret</b> (она будет остановлена и удалена из автозапуска Windows)');
    if (f.procs.length) what.push('процесс <b class="mono">winws.exe</b>: <span class="mono">' + esc(f.procs[0]) + '</span>' + (f.procs.length > 1 ? ' и ещё ' + (f.procs.length - 1) : ''));
    openModal('Запрет работает не из Бунта',
      '<p>Найдено: ' + what.join('; ') + '.</p>' +
      '<p class="note">Оба запрета сразу работать не могут, они мешают друг другу. Бунт остановит чужой запрет и запустит свой со стратегией <b class="mono">' + esc(S.discord.strategy) + '</b>. Файлы Flowseal на диске останутся.</p>',
      '<button class="btn" data-act="closeModal">Отмена</button><button class="btn primary" data-act="takeOver">Остановить и запустить из Бунта</button>');
  }
  function checkForeign() {
    return T.core.invoke('zapret_foreign').then(function (f) {
      var found = f.service || f.procs.length;
      if (found) askTakeOver(f);
      return !!found;
    }).catch(function () { return false; });
  }
  function takeOver() {
    closeModal();
    if (zBusy) return;
    zBusy = true;
    addLog({ svc: 'Zapret (Discord)', m: 'Останавливаем запрет, запущенный не из Бунта…' });
    T.core.invoke('zapret_take_over').then(function () {
      zBusy = false;
      realDiscord(true, false, true);
    }).catch(function (err) {
      zBusy = false;
      addLog({ svc: 'Zapret (Discord)', m: 'Ошибка: ' + err });
      toast(String(err).slice(0, 200), 'warn');
      renderAll();
    });
  }
  function realDiscord(on, quiet, skipCheck) {
    if (zBusy) return;
    if (on && adminNeeded(quiet)) return;
    if (on && !skipCheck) {
      zBusy = true;
      T.core.invoke('zapret_foreign').then(function (f) {
        zBusy = false;
        if (f.service || f.procs.length) askTakeOver(f);
        else realDiscord(true, quiet, true);
      }).catch(function () { zBusy = false; realDiscord(true, quiet, true); });
      return;
    }
    zBusy = true;
    var d = S.discord, n = SVC.discord.name;
    var p = on
      ? (addLog({ svc: n, m: 'Запуск winws со стратегией ' + d.strategy + '…' }),
         T.core.invoke('zapret_start', { strategy: d.strategy, game: d.game, ipset: d.ipset, gameTcp: d.tcpPorts, gameUdp: d.udpPorts }))
      : T.core.invoke('zapret_stop');
    p.then(function () {
      S.on.discord = on;
      addLog(on ? { m: 'winws запущен. Запрет работает.', ok: true } : { svc: n, m: 'Остановлено.' });
    }).catch(function (err) {
      S.on.discord = false;
      addLog({ svc: n, m: 'Ошибка: ' + err });
      if (!quiet) toast(String(err).slice(0, 200), 'warn');
    }).then(function () { zBusy = false; renderAll(); });
  }
  /* Telegram: локальный MTProto-прокси, права администратора не нужны */
  var tBusy = false;
  var TGN = ['port', 'buf_kb', 'pool_size', 'log_max_mb', 'log_backups'];
  function applyTg(st) {
    var c = st.config || {};
    Object.keys(S.tgc).forEach(function (k) { if (c[k] !== undefined) S.tgc[k] = TGN.indexOf(k) >= 0 ? String(c[k]) : c[k]; });
    S.telegram.port = S.tgc.port;
    S.telegram.link = st.link || '';
  }
  function tgPayload() {
    var o = {};
    Object.keys(S.tgc).forEach(function (k) { o[k] = TGN.indexOf(k) >= 0 ? parseInt(S.tgc[k], 10) : S.tgc[k]; });
    for (var i = 0; i < TGN.length; i++) if (!(o[TGN[i]] >= 0)) return TGN[i];
    return o;
  }
  function tgPayloadOrNull() {
    var o = tgPayload();
    if (typeof o === 'string') { toast('Проверьте числовые поля: ' + o, 'warn'); return null; }
    return o;
  }
  function tgSave() {
    if (!inTauri || !installed('telegram')) return;
    var o = tgPayload();
    if (typeof o === 'string') { toast('Проверьте числовые поля: ' + o, 'warn'); return; }
    T.core.invoke('telegram_config_set', { config: o }).then(function (st) {
      applyTg(st);
      S.on.telegram = st.running;
      addLog({ svc: SVC.telegram.name, m: 'Настройки применены' + (st.running ? ', прокси перезапущен. Если менялись порт или секрет, добавьте новую ссылку в Telegram.' : '.') });
      toast('Настройки применены');
      refreshTgExtras();
    }).catch(function (err) { toast(String(err).slice(0, 220), 'warn'); S.on.telegram = false; }).then(renderAll);
  }
  function tgAutostart(on) {
    if (!inTauri || !installed('telegram')) { S.tgc.autostart = false; toast('Сначала установите компонент.', 'warn'); renderAll(); return; }
    T.core.invoke('telegram_set_autostart', { on: on }).then(function () {
      if (on && S.settings && !S.settings.autostart && !S.settings.autostart_admin) {
        S.settings.autostart = true;
        saveSettings();
        toast('Автозапуск прокси включён. Бунт тоже будет запускаться вместе с Windows.');
      } else toast(on ? 'Прокси будет запускаться вместе с Бунтом' : 'Автозапуск прокси выключен');
    }).catch(function (err) { S.tgc.autostart = !on; toast(String(err).slice(0, 200), 'warn'); }).then(renderAll);
  }
  function askTgTakeOver(f) {
    var what = [];
    if (f.procs.length) what.push('процесс: <span class="mono">' + esc(f.procs[0]) + '</span>' + (f.procs.length > 1 ? ' и ещё ' + (f.procs.length - 1) : ''));
    if (f.autostart) what.push('запись <b class="mono">TgWsProxy</b> в автозагрузке Windows');
    openModal('Прокси Telegram работает не из Бунта',
      '<p>Найдено: ' + what.join('; ') + '.</p>' +
      '<p class="note">Две копии прокси мешают друг другу: занимают один порт и не дают запуститься второй. Бунт остановит чужую и запустит свою. Файлы на диске останутся.</p>',
      '<button class="btn" data-act="closeModal">Отмена</button>' +
      '<button class="btn' + (f.autostart ? '' : ' primary') + '" data-act="tgTakeOver" data-arg="0">Отключить и запустить из Бунта</button>' +
      (f.autostart ? '<button class="btn primary" data-act="tgTakeOver" data-arg="1">Отключить и убрать из автозагрузки</button>' : ''));
  }
  function tgTakeOver(arg) {
    closeModal();
    if (tBusy) return;
    tBusy = true;
    addLog({ svc: SVC.telegram.name, m: 'Останавливаем прокси, запущенный не из Бунта…' });
    T.core.invoke('telegram_take_over', { removeAutostart: arg === '1' }).then(function () {
      tBusy = false;
      if (arg === '1') addLog({ svc: SVC.telegram.name, m: 'Чужой прокси убран из автозагрузки.' });
      realTelegram(true, false, true);
    }).catch(function (err) {
      tBusy = false;
      addLog({ svc: SVC.telegram.name, m: 'Ошибка: ' + err });
      toast(String(err).slice(0, 200), 'warn');
      renderAll();
    });
  }
  function checkTgForeign() {
    return T.core.invoke('telegram_foreign').then(function (f) { if (f.procs.length) askTgTakeOver(f); }).catch(function () {});
  }
  function tgReset() {
    if (!inTauri || !installed('telegram')) return;
    T.core.invoke('telegram_config_reset').then(function (st) {
      applyTg(st);
      S.on.telegram = st.running;
      toast('Настройки сброшены (секрет прежний)');
    }).catch(function (err) { toast(String(err).slice(0, 220), 'warn'); }).then(renderAll);
  }
  function tgSecret() {
    if (!inTauri || !installed('telegram')) return;
    T.core.invoke('telegram_new_secret').then(function (st) {
      applyTg(st);
      S.on.telegram = st.running;
      toast('Новый секрет создан. Добавьте новую ссылку в Telegram.');
    }).catch(function (err) { toast(String(err).slice(0, 220), 'warn'); }).then(renderAll);
  }
  function realTelegram(on, quiet, skipCheck) {
    if (tBusy) return;
    if (on && !skipCheck) {
      tBusy = true;
      T.core.invoke('telegram_foreign').then(function (f) {
        tBusy = false;
        if (f.procs.length || (f.autostart && !quiet)) askTgTakeOver(f);
        else realTelegram(true, quiet, true);
      }).catch(function () { tBusy = false; realTelegram(true, quiet, true); });
      return;
    }
    tBusy = true;
    var n = SVC.telegram.name;
    if (on) addLog({ svc: n, m: 'Запуск прокси…' });
    /* поля настроек могли быть изменены, но не сохранены: перед запуском сохраняем их, иначе applyTg вернёт старый адрес */
    var pre = Promise.resolve();
    if (on && installed('telegram')) {
      var payload = tgPayload();
      if (typeof payload !== 'string') pre = T.core.invoke('telegram_config_set', { config: payload });
    }
    pre.then(function () { return T.core.invoke(on ? 'telegram_start' : 'telegram_stop'); }).then(function (st) {
      applyTg(st);
      S.on.telegram = on;
      addLog(on ? { m: 'Прокси запущен на порту ' + st.port + '. Добавьте ссылку в Telegram один раз.', ok: true } : { svc: n, m: 'Остановлено.' });
    }).catch(function (err) {
      S.on.telegram = false;
      addLog({ svc: n, m: 'Ошибка: ' + err });
      if (!quiet) toast(String(err).slice(0, 200), 'warn');
    }).then(function () { tBusy = false; renderAll(); });
  }
  /* VPN-подобные службы делят маршруты: одновременно может работать только одна */
  var VPNS = ['fptn', 'wg', 'vless'];
  function vpnBusy(id) { return id === 'fptn' ? S.fptn.busy : id === 'wg' ? S.w.busy : id === 'vless' ? S.v.busy : false; }
  function vpnConflict(id, quiet) {
    var other = VPNS.filter(function (x) { return x !== id && (S.on[x] || vpnBusy(x)); })[0];
    if (!other) return false;
    var on = SVC[other].name, mine = SVC[id].name;
    if (quiet) { addLog({ svc: mine, m: 'Не включён: ' + on + ' уже работает, два VPN сразу не включаются.' }); return true; }
    openModal('Уже включён ' + esc(on),
      '<p>' + esc(on) + ' ' + (S.on[other] ? 'сейчас работает' : 'ещё подключается') + '. Два VPN сразу делят маршруты и ломают интернет, поэтому одновременно может работать только один.</p>' +
      '<p class="note">Бунт отключит ' + esc(on) + ', вернёт сеть в исходное состояние и сразу включит ' + esc(mine) + '.</p>',
      '<button class="btn" data-act="closeModal">Отмена</button><button class="btn primary" data-act="vpnSwitch" data-arg="' + other + ':' + id + '">Отключить ' + esc(on) + ' и включить ' + esc(mine) + '</button>');
    return true;
  }
  /* переключение с одного VPN на другой: сначала ждём полного отключения первого */
  function vpnSwitch(arg) {
    closeModal();
    var p = String(arg).split(':'), other = p[0], id = p[1];
    if (VPNS.indexOf(other) < 0 || VPNS.indexOf(id) < 0) return;
    var tries = 0;
    setSvc(other, false, true);
    (function wait() {
      if (!S.on[other] && !vpnBusy(other)) { setSvc(id, true); return; }
      if (++tries > 200) { toast('Не удалось отключить ' + SVC[other].name + '. ' + SVC[id].name + ' не включён.', 'warn'); return; }
      setTimeout(wait, 300);
    })();
  }
  /* FPTN: консольный клиент с защитой сети, нужны права администратора */
  var FNUM = ['mtu'];
  var FST = { Up: 'Включён', Disabled: 'Отключён', Disconnected: 'Не подключён', NotPresent: 'Отсутствует' };
  function applyF(st) {
    var c = st.config || {};
    Object.keys(S.fc).forEach(function (k) { if (k !== 'token_in' && c[k] !== undefined) S.fc[k] = FNUM.indexOf(k) >= 0 ? String(c[k]) : c[k]; });
    var f = S.fptn;
    f.tokenSet = !!st.token_set; f.hint = st.token_hint || '';
    f.servers = st.servers || []; f.tokenError = st.token_error || '';
    f.adapter = st.adapter || f.adapter;
    f.dirty = !!st.dirty;
    S.on.fptn = !!st.running;
  }
  function fPayload() {
    var o = {};
    Object.keys(S.fc).forEach(function (k) { if (k !== 'token_in') o[k] = FNUM.indexOf(k) >= 0 ? parseInt(S.fc[k], 10) : S.fc[k]; });
    o.token = '';
    if (!(o.mtu >= 0)) return 'MTU';
    return o;
  }
  function fErr(err) { toast(String(err).slice(0, 240), 'warn'); }
  function fSave(extra) {
    if (!inTauri || !installed('fptn')) return Promise.resolve();
    var o = fPayload();
    if (typeof o === 'string') { toast('Проверьте поле: ' + o, 'warn'); return Promise.resolve(); }
    if (extra) o.token = extra;
    return T.core.invoke('fptn_config_set', { config: o }).then(function (st) {
      applyF(st);
      if (!extra) toast('Настройки сохранены. Они применятся при следующем подключении.');
    }).catch(fErr).then(renderAll);
  }
  function fSaveToken() {
    var t = (S.fc.token_in || '').trim();
    if (!t) { toast('Вставьте токен.', 'warn'); return; }
    fSave(t).then(function () { if (S.fptn.tokenSet) { S.fc.token_in = ''; if (S.fptn.tokenError) toast('Токен сохранён, но не разобран: ' + S.fptn.tokenError, 'warn'); else toast('Токен сохранён, серверов: ' + S.fptn.servers.length); S.fptn.ping = {}; S.fptn.pingAt = 0; renderAll(); fAutoPing(); } });
  }
  function fServer(name) {
    var cur = (S.fc.preferred_server || '').split(',').map(function (x) { return x.trim(); }).filter(Boolean);
    if (!name) cur = [];
    else {
      var i = cur.findIndex(function (x) { return x.toLowerCase() === name.toLowerCase(); });
      if (i >= 0) cur.splice(i, 1); else cur.push(name);
    }
    S.fc.preferred_server = cur.join(',');
    renderAll();
    fSave().then(function () { toast(cur.length ? 'Сервер: ' + cur.join(', ') + '. Применится при следующем подключении.' : 'Сервер: автовыбор. Применится при следующем подключении.'); });
  }
  function fClearToken() {
    if (!inTauri || !installed('fptn')) return;
    T.core.invoke('fptn_clear_token').then(function (st) { applyF(st); toast('Токен удалён'); }).catch(fErr).then(renderAll);
  }
  function fReset() {
    if (!inTauri || !installed('fptn')) return;
    T.core.invoke('fptn_config_reset').then(function (st) { applyF(st); toast('Настройки сброшены (токен прежний)'); }).catch(fErr).then(renderAll);
  }
  function fRepair() {
    if (!inTauri || !installed('fptn')) return;
    addLog({ svc: 'FPTN', m: 'Восстанавливаем сеть…' });
    T.core.invoke('fptn_repair').then(function (d) {
      applyF(d.info); S.fptn.repairMsg = d.message;
      addLog({ svc: 'FPTN', m: d.message, ok: true });
      toast(d.message);
    }).catch(function (err) { S.fptn.repairMsg = String(err); fErr(err); }).then(renderAll);
  }
  function fAdapter(action) {
    if (!inTauri || !installed('fptn')) return;
    if (action === 'disable' && S.on.fptn && !window.confirm('FPTN подключён: отключение адаптера оборвёт VPN. Продолжить?')) return;
    T.core.invoke('fptn_adapter', { action: action }).then(function (st) {
      applyF(st);
      toast({ enable: 'Адаптер включён', disable: 'Адаптер отключён', remove: 'Адаптер удалён' }[action]);
    }).catch(fErr).then(renderAll);
  }
  function fLog() {
    var f = S.fptn;
    f.logOpen = !f.logOpen;
    if (f.logOpen && inTauri) T.core.invoke('fptn_log').then(function (t) { f.log = t || 'Лог пуст.'; renderAll(); }).catch(function () {});
    renderAll();
  }
  function askFptnTakeOver(f) {
    var what = [];
    if (f.procs.length) what.push('процесс: <span class="mono">' + esc(f.procs[0]) + '</span>' + (f.procs.length > 1 ? ' и ещё ' + (f.procs.length - 1) : ''));
    if (f.autostart.length) what.push('автозагрузка Windows: <b class="mono">' + esc(f.autostart.join(', ')) + '</b>');
    openModal('FPTN работает не из Бунта',
      '<p>Найдено: ' + what.join('; ') + '.</p>' +
      '<p class="note">Два клиента FPTN одновременно ломают маршрутизацию, из-за этого и пропадает интернет. Бунт закроет чужой клиент и запустит свой под защитой сети. Файлы на диске останутся.</p>',
      '<button class="btn" data-act="closeModal">Отмена</button>' +
      '<button class="btn' + (f.autostart.length ? '' : ' primary') + '" data-act="fTakeOver" data-arg="0">Отключить и подключиться из Бунта</button>' +
      (f.autostart.length ? '<button class="btn primary" data-act="fTakeOver" data-arg="1">Отключить и убрать из автозагрузки</button>' : ''));
  }
  function fTakeOver(arg) {
    closeModal();
    if (S.fptn.busy) return;
    S.fptn.busy = true; renderAll();
    T.core.invoke('fptn_take_over', { removeAutostart: arg === '1' }).then(function () {
      S.fptn.busy = false;
      if (arg === '1') addLog({ svc: 'FPTN', m: 'Чужой FPTN убран из автозагрузки.' });
      realFptn(true, false, true);
    }).catch(function (err) { S.fptn.busy = false; fErr(err); renderAll(); });
  }
  function realFptn(on, quiet, skipCheck) {
    var f = S.fptn;
    if (f.busy) return;
    if (on && vpnConflict('fptn', quiet)) return;
    if (on && !f.tokenSet) { if (!quiet) { toast('Сначала добавьте токен доступа.', 'warn'); go('fptn'); } return; }
    if (on && adminNeeded(quiet)) return;
    if (on && !skipCheck) {
      f.busy = true;
      T.core.invoke('fptn_foreign').then(function (x) {
        f.busy = false;
        if (x.procs.length || (x.autostart.length && !quiet)) askFptnTakeOver(x);
        else realFptn(true, quiet, true);
      }).catch(function () { f.busy = false; realFptn(true, quiet, true); });
      return;
    }
    f.busy = true;
    addLog({ svc: 'FPTN', m: on ? 'Подключаемся…' : 'Отключаемся и убираем маршруты…' });
    renderAll();
    var p = on
      ? T.core.invoke('fptn_connect').then(function (st) { applyF(st); addLog({ m: 'FPTN подключён.', ok: true }); })
      : T.core.invoke('fptn_disconnect').then(function (d) { applyF(d.info); addLog({ m: d.message, ok: true }); });
    p.catch(function (err) {
      S.on.fptn = false;
      addLog({ svc: 'FPTN', m: 'Ошибка: ' + err });
      if (!quiet || on) toast(String(err).slice(0, 240), 'warn');
      T.core.invoke('fptn_status').then(function (st) { applyF(st); renderAll(); }).catch(function () {});
    }).then(function () { f.busy = false; if (f.logOpen) T.core.invoke('fptn_log').then(function (t) { f.log = t; renderAll(); }).catch(function () {}); renderAll(); });
  }
  /* клиент мог завершиться сам: тогда проверяем, не осталось ли следов в сети, и чиним */
  function watchFptn() {
    if (!inTauri || !installed('fptn') || S.fptn.busy) return;
    T.core.invoke('fptn_status').then(function (st) {
      var was = S.on.fptn;
      applyF(st);
      if (was && !st.running) addLog({ svc: 'FPTN', m: 'Клиент FPTN завершился.' });
      if (st.dirty && S.admin !== false) {
        S.fptn.busy = true;
        T.core.invoke('fptn_repair').then(function (d) { applyF(d.info); S.fptn.repairMsg = d.message; addLog({ svc: 'FPTN', m: 'Бунт восстановил сеть после сбоя. ' + d.message, ok: true }); toast('Сеть после FPTN восстановлена'); })
          .catch(function () {}).then(function () { S.fptn.busy = false; renderAll(); });
      } else renderAll();
    }).catch(function () {});
  }
  function flagHtml(code) {
    return code ? '<img class="flag" src="flags/' + esc(code) + '.svg" alt="" width="22" height="16">' : '<span class="flag none">' + ico('globe') + '</span>';
  }
  /* пинг серверов по одному: блок проверяемого сервера пульсирует оранжевым */
  var fPingRun = false;
  function fPingAll(quiet) {
    var f = S.fptn;
    if (fPingRun || !f.servers.length) return;
    if (S.on.fptn || f.busy) { if (!quiet) toast('Пока FPTN включён, пинг шёл бы через туннель. Отключите FPTN и повторите.', 'warn'); return; }
    var list = f.servers.slice(), i = 0;
    fPingRun = true;
    (function step() {
      if (i >= list.length || S.on.fptn || f.busy) {
        fPingRun = false; f.pinging = ''; f.pingAt = Date.now(); renderFptn();
        if (!quiet) {
          var ok = list.filter(function (s) { return typeof f.ping[s.name] === 'number'; }).sort(function (a, b) { return f.ping[a.name] - f.ping[b.name]; });
          toast(ok.length ? 'Быстрее всех: ' + (ok[0].label || ok[0].name) + ', ' + f.ping[ok[0].name] + ' мс. Отвечают: ' + ok.length + ' из ' + list.length : 'Ни один сервер не ответил. Проверьте интернет.', ok.length ? undefined : 'warn');
        }
        return;
      }
      var s = list[i++];
      f.pinging = s.name; renderFptn();
      var run = inTauri ? T.core.invoke('fptn_ping', { name: s.name }) : new Promise(function (resolve) {
        setTimeout(function () { var h = 0; for (var k = 0; k < s.name.length; k++) h = (h * 31 + s.name.charCodeAt(k)) >>> 0; resolve(h % 7 === 5 ? null : 18 + (h % 160)); }, 380);
      });
      run.then(function (ms) { return typeof ms === 'number' ? ms : null; }, function () { return null; }).then(function (ms) { f.ping[s.name] = ms; step(); });
    })();
  }
  function fAutoPing() { if (Date.now() - S.fptn.pingAt > 120000) fPingAll(true); }
  function renderFptn() {
    var f = S.fptn, c = comp('fptn');
    var set = function (id, v) { var e = $(id); if (e) e.textContent = v; };
    set('#fVer', c.cur || '–');
    set('#fToken', f.tokenSet ? 'Токен задан: ' + f.hint : 'Токен не добавлен.');
    var a = f.adapter || {};
    set('#fAdState', !inTauri ? 'Нет данных' : a.exists ? (FST[a.status] || a.status || '–') : 'Нет (создаётся при подключении)');
    set('#fAdDesc', a.exists ? (a.description || '–') : '–');
    var dis = function (id, v) { var e = $(id); if (e) e.disabled = v; };
    dis('#fAdOn', !a.exists || a.status === 'Up' || f.busy);
    dis('#fAdOff', !a.exists || a.status === 'Disabled' || f.busy);
    dis('#fAdDel', !a.exists || S.on.fptn || f.busy);
    dis('#fPingBtn', fPingRun || !f.servers.length || f.busy);
    set('#fPingBtn', fPingRun ? 'Проверяем…' : 'Пинг');
    var sl = $('#fServers');
    if (sl) {
      var picked = (S.fc.preferred_server || '').split(',').map(function (x) { return x.trim().toLowerCase(); }).filter(Boolean);
      if (!f.servers.length) {
        sl.innerHTML = '<span class="note">' + (f.tokenError ? 'Токен не удалось разобрать: ' + esc(f.tokenError) : 'Добавьте токен, и здесь появится список серверов.') + '</span>';
      } else {
        var best = null;
        f.servers.forEach(function (s) { var v = f.ping[s.name]; if (typeof v === 'number' && (best === null || v < best)) best = v; });
        sl.innerHTML = '<button class="strat srv' + (picked.length ? '' : ' cur') + '" data-act="fServer" data-arg="" aria-pressed="' + !picked.length + '">' +
          '<span class="shd"><span class="sn"><span class="flag none">' + ico('globe') + '</span><span class="nm">Автовыбор</span>' + (picked.length ? '' : ico('check')) + '</span></span>' +
          '<span class="sf">клиент берёт самый быстрый сервер</span></button>' +
          f.servers.map(function (s) {
            var on = picked.indexOf(s.name.toLowerCase()) >= 0, pv = f.ping[s.name], busy = f.pinging === s.name;
            var tag = busy ? '<span class="tag warn">…</span>'
              : pv === undefined ? '<span class="tag">–</span>'
              : pv === null ? '<span class="tag bad">нет ответа</span>'
              : '<span class="tag ' + (pv === best ? 'ok' : pv > 250 ? 'warn' : '') + '">' + pv + ' мс</span>';
            var flag = flagHtml(s.code);
            return '<button class="strat srv' + (on ? ' cur' : '') + (busy ? ' scan' : '') + '" data-act="fServer" data-arg="' + esc(s.name) + '" aria-pressed="' + on + '">' +
              '<span class="shd"><span class="sn">' + flag + '<span class="nm">' + esc(s.label || s.name) + '</span>' + (on ? ico('check') : '') + '</span>' + tag + '</span>' +
              '<span class="sf">' + esc(s.host + ':' + s.port) + '</span></button>';
          }).join('');
      }
    }
    var d = $('#fDirty'); if (d) d.hidden = !f.dirty;
    var rm = $('#fRepairMsg'); if (rm) { rm.hidden = !f.repairMsg; rm.textContent = f.repairMsg; }
    var lg = $('#fLog'); if (lg) { lg.hidden = !f.logOpen; lg.textContent = f.log || ''; }
    var sw = document.querySelector('.head-sw [data-svc="fptn"]'); if (sw) sw.disabled = f.busy;
    var st = document.querySelector('[data-state="fptn"]');
    if (st && f.busy) { st.className = 'state'; st.innerHTML = '<span class="spin"></span>Подождите…'; }
  }
  /* WireGuard и AmneziaWG: профили .conf, туннель службой клиента AmneziaWG, нужны права администратора */
  var WST = { Up: 'Включён', Disabled: 'Отключён', Disconnected: 'Не подключён', NotPresent: 'Отсутствует' };
  function applyW(st) {
    var w = S.w;
    w.profiles = st.profiles || [];
    w.config = st.config || w.config;
    w.running = !!st.running; w.tunnel = st.tunnel || '';
    w.dirty = !!st.dirty;
    w.adapter = st.adapter || w.adapter;
    w.stats = st.stats || w.stats;
    S.on.wg = w.running;
    if (w.view && !w.profiles.some(function (p) { return p.name === w.viewName; })) w.view = '';
  }
  function wErr(err) { toast(String(err).slice(0, 240), 'warn'); }
  var fmtBytes = function (n) { return n < 1024 ? n + ' Б' : n < 1048576 ? (n / 1024).toFixed(1) + ' КБ' : n < 1073741824 ? (n / 1048576).toFixed(1) + ' МБ' : (n / 1073741824).toFixed(2) + ' ГБ'; };
  var fmtAgo = function (s) { return s == null ? 'Пока не было' : s < 5 ? 'только что' : s < 120 ? s + ' с назад' : s < 7200 ? Math.round(s / 60) + ' мин назад' : Math.round(s / 3600) + ' ч назад'; };
  function wSaveConfig() {
    if (!inTauri || !installed('wg')) return;
    T.core.invoke('wg_config_set', { config: S.w.config }).then(function (st) { applyW(st); toast('Настройки сохранены'); }).catch(wErr).then(renderAll);
  }
  /* quiet: массовая загрузка, конфликты имён не спрашиваем, а возвращаем статус */
  function wImport(name, text, replace, quiet) {
    if (!inTauri) { toast('Импорт работает только в приложении.', 'warn'); return Promise.resolve('err'); }
    if (!installed('wg')) { toast('Сначала установите компонент.', 'warn'); return Promise.resolve('err'); }
    var status = 'ok';
    return T.core.invoke('wg_import', { name: name, text: text, replace: !!replace }).then(function (st) {
      applyW(st);
      S.w.paste = false; S.w.imp_text = '';
      var n = name.replace(/\.conf$/i, '');
      addLog({ svc: SVC.wg.name, m: 'Профиль добавлен: ' + n + '.', ok: true });
      if (!quiet) toast('Профиль добавлен');
    }).catch(function (err) {
      var m = String(err);
      if (m.indexOf('EXISTS:') === 0) {
        status = 'exists';
        if (!quiet) {
          S.w.pending = { name: name, text: text };
          openModal('Профиль уже есть', '<p>' + esc(m.replace('EXISTS: ', '')) + ' Заменить его новым конфигом?</p>',
            '<button class="btn" data-act="closeModal">Отмена</button><button class="btn primary" data-act="wReplace">Заменить</button>');
        }
      } else { status = 'err'; wErr((quiet ? name + ': ' : '') + m); }
    }).then(function () { renderAll(); return status; });
  }
  /* несколько файлов подряд (выбор или перетаскивание) */
  function wImportFiles(files) {
    var list = Array.prototype.slice.call(files || []);
    if (!list.length) return;
    var ok = list.filter(function (f) { return /\.(conf|txt)$/i.test(f.name); });
    if (ok.length < list.length) toast('Пропущено файлов не .conf: ' + (list.length - ok.length), 'warn');
    if (!ok.length) return;
    var big = ok.filter(function (f) { return f.size > 256 * 1024; });
    if (big.length) { toast('Файл «' + big[0].name + '» слишком большой для конфига WireGuard.', 'warn'); ok = ok.filter(function (f) { return f.size <= 256 * 1024; }); }
    var single = ok.length === 1;
    var added = 0, dup = [];
    ok.reduce(function (chain, f) {
      return chain.then(function () {
        return new Promise(function (res) {
          var r = new FileReader();
          r.onload = function () { res(String(r.result)); };
          r.onerror = function () { toast('Не удалось прочитать файл «' + f.name + '».', 'warn'); res(null); };
          r.readAsText(f);
        }).then(function (text) {
          if (text == null) return;
          return wImport(f.name.replace(/\.(conf|txt)$/i, ''), text, false, !single).then(function (st) {
            if (st === 'ok') added++; else if (st === 'exists') dup.push(f.name);
          });
        });
      });
    }, Promise.resolve()).then(function () {
      if (single) return;
      toast('Добавлено профилей: ' + added + (dup.length ? '. Уже есть, пропущены: ' + dup.join(', ') : ''), dup.length && !added ? 'warn' : undefined);
    });
  }
  function wReplace() {
    closeModal();
    var p = S.w.pending; S.w.pending = null;
    if (p) wImport(p.name, p.text, true);
  }
  function wImportText() {
    var n = (S.w.imp_name || '').trim(), t = S.w.imp_text || '';
    if (!n) { toast('Укажите имя профиля.', 'warn'); return; }
    if (!t.trim()) { toast('Вставьте текст конфига.', 'warn'); return; }
    wImport(n, t, false);
  }
  function wPick(name) {
    if (!inTauri) return;
    if (S.w.running && S.w.tunnel !== name) { toast('Сначала отключите туннель, потом выбирайте другой профиль.', 'warn'); return; }
    T.core.invoke('wg_select', { name: name }).then(applyW).catch(wErr).then(renderAll);
  }
  function wView(name) {
    var w = S.w;
    if (w.view && w.viewName === name) { w.view = ''; renderAll(); return; }
    T.core.invoke('wg_profile_view', { name: name }).then(function (t) { w.view = t; w.viewName = name; renderAll(); }).catch(wErr);
  }
  function wDelAsk(name) {
    openModal('Удалить профиль «' + esc(name) + '»',
      '<p>Конфиг и ключи профиля будут удалены с этого компьютера.</p><p class="note">Если нужен запасной экземпляр, сохраните свой .conf заранее: из Бунта ключи не выгружаются.</p>',
      '<button class="btn" data-act="closeModal">Отмена</button><button class="btn danger" data-act="wDelDo" data-arg="' + esc(name) + '">Удалить</button>');
  }
  function wDelDo(name) {
    closeModal();
    T.core.invoke('wg_delete', { name: name }).then(function (st) { applyW(st); addLog({ svc: SVC.wg.name, m: 'Профиль удалён: ' + name + '.' }); }).catch(wErr).then(renderAll);
  }
  function wRepair() {
    if (!inTauri || !installed('wg') || adminNeeded()) return;
    addLog({ svc: SVC.wg.name, m: 'Восстанавливаем сеть…' });
    T.core.invoke('wg_repair').then(function (d) {
      applyW(d.info); S.w.repairMsg = d.message;
      addLog({ svc: SVC.wg.name, m: d.message, ok: true });
      toast(d.message);
    }).catch(function (err) { S.w.repairMsg = String(err); wErr(err); }).then(renderAll);
  }
  function wAdapter(action) {
    if (!inTauri || !installed('wg') || adminNeeded()) return;
    if (action === 'disable' && S.w.running && !window.confirm('Туннель включён: отключение адаптера оборвёт соединение. Продолжить?')) return;
    T.core.invoke('wg_adapter', { action: action }).then(function (st) {
      applyW(st);
      toast({ enable: 'Адаптер включён', disable: 'Адаптер отключён', remove: 'Адаптер удалён' }[action]);
    }).catch(wErr).then(renderAll);
  }
  function wLog() {
    var w = S.w;
    w.logOpen = !w.logOpen;
    if (w.logOpen && inTauri) T.core.invoke('wg_log').then(function (t) { w.log = t || 'Журнал пуст.'; renderAll(); }).catch(function () {});
    renderAll();
  }
  function realWg(on, quiet) {
    var w = S.w;
    if (w.busy) return;
    if (on && vpnConflict('wg', quiet)) return;
    if (on && adminNeeded(quiet)) return;
    if (on && !w.config.active) { if (!quiet) { toast('Сначала импортируйте профиль и выберите его.', 'warn'); go('wg'); } return; }
    w.busy = true;
    addLog({ svc: SVC.wg.name, m: on ? 'Подключаем «' + w.config.active + '»…' : 'Отключаем туннель и убираем следы в сети…' });
    renderAll();
    var p = on
      ? T.core.invoke('wg_connect', { name: w.config.active }).then(function (st) { applyW(st); addLog({ m: 'Туннель «' + st.tunnel + '» поднят.', ok: true }); })
      : T.core.invoke('wg_disconnect').then(function (d) { applyW(d.info); w.repairMsg = d.message; addLog({ m: d.message, ok: true }); });
    p.catch(function (err) {
      S.on.wg = false;
      addLog({ svc: SVC.wg.name, m: 'Ошибка: ' + err });
      if (!quiet || on) toast(String(err).slice(0, 240), 'warn');
      T.core.invoke('wg_status').then(function (st) { applyW(st); renderAll(); }).catch(function () {});
    }).then(function () { w.busy = false; if (w.logOpen) T.core.invoke('wg_log').then(function (t) { w.log = t; renderAll(); }).catch(function () {}); renderAll(); });
  }
  /* туннель мог упасть сам или Бунт закрылся аварийно: проверяем следы и чиним */
  function watchWg() {
    if (!inTauri || !installed('wg') || S.w.busy) return;
    T.core.invoke('wg_status').then(function (st) {
      var was = S.w.running;
      applyW(st);
      if (was && !st.running) addLog({ svc: SVC.wg.name, m: 'Туннель остановился.' });
      if (st.dirty && S.admin !== false) {
        S.w.busy = true;
        T.core.invoke('wg_repair').then(function (d) { applyW(d.info); S.w.repairMsg = d.message; addLog({ svc: SVC.wg.name, m: 'Бунт восстановил сеть после сбоя. ' + d.message, ok: true }); toast('Сеть после туннеля восстановлена'); })
          .catch(function () {}).then(function () { S.w.busy = false; renderAll(); });
      } else renderAll();
    }).catch(function () {});
  }
  function renderWg() {
    var w = S.w, c = comp('wg');
    var set = function (id, v) { var e = $(id); if (e) e.textContent = v; };
    var dis = function (id, v) { var e = $(id); if (e) e.disabled = v; };
    set('#wVer', c.cur || '–');
    var host = $('#list-wg');
    if (host) {
      if (!w.profiles.length) host.innerHTML = '<div class="empty"><span>Профилей пока нет.</span><button class="btn" data-act="pickWg">' + ico('plus') + 'Импортировать .conf</button></div>';
      else host.innerHTML = w.profiles.map(function (p) {
        var sel = w.config.active === p.name, live = w.running && w.tunnel === p.name;
        var sub = (p.awg ? 'AmneziaWG' : 'WireGuard') + ' · ' + (p.endpoint || 'Endpoint не указан') + (p.full_tunnel ? ' · весь трафик' : '');
        return '<div class="prof ' + (sel ? 'sel' : '') + '"><button class="pick" data-act="wPick" data-arg="' + esc(p.name) + '" aria-pressed="' + sel + '"><span class="radio"></span><span class="pn"><b>' + esc(p.name) + '</b><small>' + esc(sub) + '</small></span></button>' +
          (live ? '<span class="tag ok">включён</span>' : '') +
          '<button class="btn sm ghost" data-act="wView" data-arg="' + esc(p.name) + '">Конфиг</button>' +
          '<button class="btn sm ghost" data-act="wDel" data-arg="' + esc(p.name) + '" aria-label="Удалить ' + esc(p.name) + '"' + (live ? ' disabled' : '') + '>' + ico('x') + '</button></div>';
      }).join('');
    }
    var v = $('#wView'); if (v) { v.hidden = !w.view; v.textContent = w.view ? '# ' + w.viewName + ' (ключи скрыты)\n' + w.view : ''; }
    var a = w.adapter || {};
    set('#wAdState', !inTauri ? 'Нет данных' : a.exists ? (WST[a.status] || a.status || '–') : 'Нет (создаётся при подключении)');
    set('#wAdDesc', a.exists ? (a.description || '–') : '–');
    dis('#wAdOn', !a.exists || a.status === 'Up' || w.busy);
    dis('#wAdOff', !a.exists || a.status === 'Disabled' || w.busy);
    dis('#wAdDel', !a.exists || w.running || w.busy);
    var sb = $('#wStatsBox'); if (sb) sb.hidden = !w.running;
    if (w.running) {
      var st = w.stats || {};
      set('#wTun', w.tunnel); set('#wHs', fmtAgo(st.handshake_ago)); set('#wRx', fmtBytes(st.rx || 0)); set('#wTx', fmtBytes(st.tx || 0));
    }
    var d = $('#wDirty'); if (d) d.hidden = !w.dirty;
    var rm = $('#wRepairMsg'); if (rm) { rm.hidden = !w.repairMsg; rm.textContent = w.repairMsg; }
    var lg = $('#wLog'); if (lg) { lg.hidden = !w.logOpen; lg.textContent = w.log || ''; }
    var pb = $('#wPasteBox'); if (pb) pb.hidden = !w.paste;
    var sw = document.querySelector('.head-sw [data-svc="wg"]'); if (sw) sw.disabled = w.busy;
    var stt = document.querySelector('[data-state="wg"]');
    if (stt && w.busy) { stt.className = 'state'; stt.innerHTML = '<span class="spin"></span>Подождите…'; }
  }

  /* DNS */
  var DN_ACTIVE = { auto: 'Автоматически', custom: 'Свои адреса', mixed: 'По-разному на адаптерах' };
  function applyDn(st) {
    var d = S.dn, first = !d.loaded;
    d.presets = st.presets || d.presets; d.adapters = st.adapters || []; d.active = st.active || '';
    d.has_snapshot = !!st.has_snapshot; d.config = st.config || d.config; d.vpn = !!st.vpn; d.doh_supported = !!st.doh_supported;
    d.off = d.off.filter(function (i) { return d.adapters.some(function (a) { return a.index === i; }); });
    if (first) { d.c1 = (d.config.custom || [])[0] || ''; d.c2 = (d.config.custom || [])[1] || ''; }
    d.loaded = true;
  }
  function loadDn() {
    if (!inTauri || S.dn.busy) return Promise.resolve();
    return T.core.invoke('dns_status').then(function (st) { applyDn(st); renderAll(); }).catch(function () {});
  }
  function dnSel() { return S.dn.adapters.filter(function (a) { return S.dn.off.indexOf(a.index) < 0; }).map(function (a) { return a.index; }); }
  function dAd(i) {
    i = Number(i);
    var o = S.dn.off, k = o.indexOf(i);
    if (k < 0) o.push(i); else o.splice(k, 1);
    renderAll();
  }
  function dnDone(d) {
    applyDn(d.info); S.dn.msg = d.message;
    addLog({ svc: 'DNS', m: d.message, ok: true });
    toast(d.message.length > 120 ? d.message.slice(0, 117) + '…' : d.message);
  }
  function dnRun(call, text) {
    var d = S.dn;
    d.busy = true; d.msg = ''; addLog({ svc: 'DNS', m: text }); renderAll();
    call.then(dnDone).catch(function (err) { d.msg = String(err); addLog({ svc: 'DNS', m: 'Ошибка: ' + err }); toast(String(err).slice(0, 240), 'warn'); })
      .then(function () { d.busy = false; renderAll(); loadDn(); });
  }
  /* тумблер: включить выбранный DNS или вернуть автоматический */
  function dnOn() { var a = S.dn.active; return !!a && a !== 'auto'; }
  function dToggle() {
    var d = S.dn;
    if (!inTauri) { toast('Смена DNS работает в приложении Бунт.', 'warn'); return; }
    if (d.busy) return;
    if (d.vpn) { toast('Сначала отключите VPN: он сам управляет DNS.', 'warn'); return; }
    if (dnOn()) { dReset('auto'); return; }
    var last = (d.config && d.config.last) || '';
    var known = d.presets.some(function (p) { return p.id === last; });
    if (last === 'custom' && (d.c1 || '').trim()) { dApply('custom'); return; }
    dApply(known ? last : (d.presets[0] ? d.presets[0].id : 'cloudflare'));
  }
  function dApply(id) {
    var d = S.dn;
    if (!inTauri) { toast('Смена DNS работает в приложении Бунт.', 'warn'); return; }
    if (d.busy || adminNeeded()) return;
    if (d.vpn) { toast('Сначала отключите VPN: он сам управляет DNS.', 'warn'); return; }
    var sel = dnSel();
    if (!sel.length) { toast('Отметьте хотя бы один адаптер.', 'warn'); return; }
    var custom = [];
    if (id === 'custom') {
      custom = [d.c1.trim(), d.c2.trim()].filter(Boolean);
      if (!custom.length) { toast('Введите адрес DNS-сервера, например 1.1.1.1.', 'warn'); return; }
    }
    var pr = d.presets.filter(function (p) { return p.id === id; })[0];
    dnRun(T.core.invoke('dns_apply', { req: { preset: id, custom: custom, adapters: sel, ipv6: !!d.config.ipv6, doh: !!d.config.doh } }),
      'Меняем DNS на ' + (pr ? pr.name : 'свои адреса') + '…');
  }
  function dReset(mode) {
    var d = S.dn;
    if (!inTauri || d.busy || adminNeeded()) return;
    if (d.vpn) { toast('Сначала отключите VPN: он сам управляет DNS.', 'warn'); return; }
    if (mode === 'restore' && !d.has_snapshot) { toast('Бунт ещё не менял DNS: возвращать нечего.', 'warn'); return; }
    dnRun(T.core.invoke('dns_reset', { mode: mode }), mode === 'restore' ? 'Возвращаем прежние настройки DNS…' : 'Возвращаем автоматический DNS…');
  }
  function dPing() {
    var d = S.dn;
    if (!inTauri || d.pinging) return;
    d.pinging = true; renderAll();
    T.core.invoke('dns_ping').then(function (r) {
      d.ping = {};
      r.forEach(function (x) { d.ping[x.id] = x.ms; });
      var best = r.filter(function (x) { return x.ms != null; }).sort(function (a, b) { return a.ms - b.ms; })[0];
      if (best) { var p = d.presets.filter(function (q) { return q.id === best.id; })[0]; toast('Быстрее всех отвечает ' + (p ? p.name : best.id) + ': ' + best.ms + ' мс.'); }
      else toast('Ни один сервер не ответил. Проверьте подключение к сети.', 'warn');
    }).catch(function (e) { toast(String(e).slice(0, 200), 'warn'); }).then(function () { d.pinging = false; renderAll(); });
  }
  function renderDn() {
    var d = S.dn;
    var set = function (id, v) { var e = $(id); if (e) e.textContent = v; };
    var pn = d.presets.filter(function (p) { return p.id === d.active; })[0];
    set('#dNow', !inTauri || !d.loaded ? 'DNS: нет данных' : 'Сейчас: ' + (pn ? pn.name : DN_ACTIVE[d.active] || '–'));
    var off = d.busy || d.vpn;
    var on = dnOn(), sw = $('#dSw');
    if (sw) { sw.setAttribute('aria-checked', String(on)); sw.disabled = off || !d.loaded; }
    var stt = $('#dState');
    if (stt) {
      if (d.busy) { stt.className = 'state'; stt.innerHTML = '<span class="spin"></span>Подождите…'; }
      else { stt.className = 'state ' + (on ? 'on' : ''); stt.innerHTML = on ? '<i class="dot"></i>Включён' : 'Автоматически'; }
    }
    var g = $('#dGrid');
    if (g) {
      g.innerHTML = !d.presets.length ? '<div class="empty"><span>' + (inTauri ? 'Загружаем список…' : 'Список серверов доступен в приложении Бунт.') + '</span></div>' : d.presets.map(function (p) {
        var ms = d.ping[p.id], pg = !(p.id in d.ping) ? '' : ms == null ? '<span class="tag bad">нет ответа</span>' : '<span class="tag ok">' + ms + ' мс</span>';
        return '<button class="dns-card ' + (d.active === p.id ? 'sel' : '') + '" data-act="dApply" data-arg="' + esc(p.id) + '"' + (off ? ' disabled' : '') + '><span class="dn"><span>' + esc(p.name) + '</span>' + pg + '</span><small>' + esc(p.desc) + '</small><span class="mono">' + esc(p.v4.join('  ·  ')) + '</span></button>';
      }).join('');
    }
    var ad = $('#dAdapters');
    if (ad) {
      ad.innerHTML = !d.adapters.length ? '<div class="empty"><span>' + (d.loaded ? 'Активных сетевых адаптеров не найдено.' : 'Нет данных') + '</span></div>' : d.adapters.map(function (a) {
        var on = d.off.indexOf(a.index) < 0;
        return '<div class="dns-ad" role="checkbox" tabindex="0" aria-checked="' + on + '" data-act="dAd" data-arg="' + a.index + '"><input type="checkbox" tabindex="-1" aria-hidden="true" style="pointer-events:none"' + (on ? ' checked' : '') + '><span><b>' + esc(a.name) + '</b><small>' + esc(a.desc) + '</small><small class="mono">' + esc(a.v4.join(', ') || 'нет адресов') + (a.stat ? ' · вручную' : ' · от роутера') + '</small></span></div>';
      }).join('');
    }
    var v = $('#dVpn'); if (v) v.hidden = !d.vpn;
    var cb = $('#dCustomBtn'); if (cb) cb.disabled = off;
    var pb = $('#dPingBtn'); if (pb) { pb.disabled = d.pinging; pb.textContent = d.pinging ? 'Проверяем…' : 'Проверить скорость'; }
    var dr = $('#dDohRow'); if (dr) dr.style.opacity = d.doh_supported || !d.loaded ? '' : '.5';
    var sn = $('#dSnapNote'); if (sn) sn.textContent = d.has_snapshot ? 'Бунт запомнил DNS, который стоял до первой смены' : 'Появятся после первой смены DNS';
    var rs = $('#dRestore'); if (rs) rs.disabled = !d.has_snapshot || off;
    var m = $('#dMsg'); if (m) { m.hidden = !d.msg; m.textContent = d.msg; }
  }

  /* VLESS на ядре Xray-core */
  var VACT = { proxy: 'Через VLESS', direct: 'Напрямую', block: 'Блокировать' };
  var VKIND = { app: 'Приложение', domain: 'Домен', ip: 'Сеть' };
  var VHINT = { app: 'chrome.exe', domain: 'example.com', ip: '10.0.0.0/8' };
  function applyV(st) {
    var v = S.v;
    v.profiles = st.profiles || []; v.config = st.config || v.config;
    v.running = !!st.running; v.tun = !!st.tun; v.dirty = !!st.dirty; v.adapter = !!st.adapter;
    S.on.vless = v.running;
    v.socks = String(v.config.socks_port); v.http = String(v.config.http_port); v.dns_text = (v.config.dns || []).join(', ');
    v.loaded = true;
  }
  function vErr(err) { toast(String(err).slice(0, 700), 'warn'); }
  function vReload() { return inTauri ? T.core.invoke('vless_status').then(applyV).catch(function () {}) : Promise.resolve(); }
  function vSave() {
    var v = S.v;
    if (!inTauri) { renderAll(); return Promise.resolve(); }
    var c = JSON.parse(JSON.stringify(v.config));
    c.socks_port = Number(v.socks) || 0; c.http_port = Number(v.http) || 0;
    c.dns = String(v.dns_text || '').split(/[\s,;]+/).filter(Boolean);
    return T.core.invoke('vless_config_set', { config: c }).then(applyV).catch(function (err) { vErr(err); return vReload(); }).then(renderAll);
  }
  function vApplyNote() { if (S.v.running) toast('Настройки применятся при следующем подключении.'); }
  function vSetMsg(t) { var m = $('#vlessMsg'); if (m) m.textContent = t; }
  function vDone(d) { applyV(d.info); vSetMsg(d.message); addLog({ svc: SVC.vless.name, m: d.message, ok: true }); toast(d.message.length > 120 ? d.message.slice(0, 117) + '…' : d.message); }
  function vImport() {
    var el = $('#vlessIn'), t = el.value.trim();
    if (!t) { vSetMsg('Вставьте ссылку vless:// или адрес подписки.'); return; }
    if (!inTauri) { vSetMsg('Добавление серверов работает в приложении Бунт.'); return; }
    var one = /^https?:\/\/\S+$/i.test(t);
    var p;
    if (one) {
      p = T.core.invoke('vless_sub_add', { name: '', url: t });
    } else p = T.core.invoke('vless_import', { text: t });
    S.v.busy = true; renderAll();
    p.then(function (d) { el.value = ''; vDone(d); }).catch(function (err) { vSetMsg(String(err)); vErr(err); }).then(function () { S.v.busy = false; renderAll(); });
  }
  function vPick(id) {
    var v = S.v;
    if (v.running && v.config.active !== id) { toast('Сначала отключите VLESS, потом выбирайте другой сервер.', 'warn'); return; }
    T.core.invoke('vless_select', { id: id }).then(applyV).catch(vErr).then(renderAll);
  }
  function vDel(id) {
    var v = S.v;
    if (v.running && v.config.active === id) { toast('Этот сервер сейчас используется: сначала отключите VLESS.', 'warn'); return; }
    T.core.invoke('vless_delete', { ids: [id] }).then(applyV).catch(vErr).then(renderAll);
  }
  /* пинг серверов: по четыре сразу, блоки проверяемых серверов пульсируют оранжевым */
  var vPingRun = false;
  function vPingAll(quiet) {
    var v = S.v;
    if (vPingRun) return;
    var queue = v.profiles.filter(function (p) { return p.ok; }).map(function (p) { return p.id; });
    if (!queue.length) return;
    if (v.running) { if (!quiet) toast('Пока VLESS включён, пинг шёл бы через туннель. Отключите VLESS и повторите.', 'warn'); return; }
    var total = queue.length, active = 0, ended = false;
    vPingRun = true; v.ping = {}; renderVless();
    function finish() {
      if (ended) return; ended = true;
      vPingRun = false; v.pinging = {}; v.pingAt = Date.now(); renderVless();
      if (quiet) return;
      var ok = v.profiles.filter(function (p) { return typeof v.ping[p.id] === 'number'; }).sort(function (a, b) { return v.ping[a.id] - v.ping[b.id]; });
      toast(ok.length ? 'Быстрее всех: ' + (ok[0].label || ok[0].name) + ', ' + v.ping[ok[0].id] + ' мс. Отвечают: ' + ok.length + ' из ' + total : 'Ни один сервер не ответил. Проверьте интернет.', ok.length ? undefined : 'warn');
    }
    function pump() {
      while (active < 4 && queue.length && !v.running) {
        (function (id) {
          active++; v.pinging[id] = true;
          var run = inTauri ? T.core.invoke('vless_ping_one', { id: id }) : new Promise(function (resolve) {
            setTimeout(function () { var h = 0; for (var k = 0; k < id.length; k++) h = (h * 31 + id.charCodeAt(k)) >>> 0; resolve(h % 9 === 4 ? null : 20 + (h % 180)); }, 300 + (id.charCodeAt(0) % 5) * 90);
          });
          run.then(function (ms) { return typeof ms === 'number' ? ms : null; }, function () { return null; }).then(function (ms) {
            v.ping[id] = ms; delete v.pinging[id]; active--;
            renderVless(); pump();
          });
        })(queue.shift());
      }
      if (!active) finish();
    }
    pump();
  }
  function vAutoPing() { if (Date.now() - S.v.pingAt > 120000) vPingAll(true); }
  /* подписки обновляются сами, когда подходит срок */
  function vAutoSubs() {
    var v = S.v;
    if (!inTauri || !installed('vless') || !v.config.sub_auto || v.busy) return;
    var now = Math.floor(Date.now() / 1000);
    var due = v.config.subs.filter(function (s) {
      var live = v.running && v.profiles.some(function (p) { return p.sub === s.id && p.id === v.config.active; });
      return !live && now - s.updated > Math.max(1, s.interval || 24) * 3600;
    })[0];
    if (!due) return;
    v.busy = true; v.refreshing = due.id; renderAll();
    T.core.invoke('vless_sub_refresh', { id: due.id }).then(function (d) {
      applyV(d.info); addLog({ svc: SVC.vless.name, m: 'Подписка «' + due.name + '» обновлена сама. ' + d.message });
    }).catch(function (err) {
      var cur = S.v.config.subs.filter(function (s) { return s.id === due.id; })[0];
      if (cur) cur.updated = now - Math.max(1, cur.interval || 24) * 3600 + 3600;   /* не долбим снова в течение часа */
      addLog({ svc: SVC.vless.name, m: 'Подписку «' + due.name + '» обновить не удалось: ' + err });
    }).then(function () { S.v.busy = false; S.v.refreshing = ''; renderAll(); setTimeout(vAutoSubs, 800); });
  }
  function vToggle(id) { var v = S.v; v.open[id] = !vGroupOpen(id); renderVless(); }
  function vGroupOpen(id) {
    var v = S.v;
    if (id in v.open) return v.open[id];
    return v.config.subs.length < 2 || v.profiles.some(function (p) { return p.sub === id && p.id === v.config.active; });
  }
  function noteHtml(s) {
    if (!s.announce) return '';
    var long = s.announce.length > 110 || s.announce.split('\n').length > 2, on = !!S.v.noteOpen[s.id];
    return '<div class="sg-note' + (long && !on ? ' clamp' : '') + '">' + esc(s.announce) + '</div>' +
      (long ? '<button class="sg-more" data-act="vNote" data-arg="' + esc(s.id) + '" aria-expanded="' + on + '">' + (on ? 'Свернуть' : 'Показать полностью') + '<svg class="ic"><use href="#i-chev"/></svg></button>' : '');
  }
  function vNote(id) { S.v.noteOpen[id] = !S.v.noteOpen[id]; renderVless(); }
  function vSubOpen(arg) {
    var p = String(arg).split(':');
    if (!inTauri) return;
    T.core.invoke('vless_sub_open', { id: p[0], what: p[1] }).catch(vErr);
  }
  function fmtTraffic(n) {
    var u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ', 'ПБ'], i = 0, x = Number(n) || 0;
    while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
    return (i === 0 ? String(Math.round(x)) : (x >= 100 ? x.toFixed(0) : x.toFixed(1)).replace(/\.0$/, '').replace('.', ',')) + '\u00a0' + u[i];
  }
  function daysWord(n) { var m = n % 100, d = n % 10; return (m > 10 && m < 15) ? 'дней' : d === 1 ? 'день' : (d > 1 && d < 5) ? 'дня' : 'дней'; }
  function usageHtml(s) {
    var used = (s.upload || 0) + (s.download || 0);
    var tip = 'Получено: ' + fmtTraffic(s.download) + ', отправлено: ' + fmtTraffic(s.upload);
    if (!s.has_usage) {
      return '<div class="usage" title="' + esc(s.seen ? 'Сервис прислал заголовки: ' + s.seen : 'Сервис не прислал ни одного служебного заголовка') + '">' +
        '<div class="ubar none"><span class="ufill"></span></div>' +
        '<div class="uline"><span>Сервис не сообщает трафик</span><span>нажмите «Обновить», чтобы спросить снова</span></div></div>';
    }
    var out = '<div class="usage" title="' + esc(tip) + '">';
    if (s.total > 0) {
      var pct = Math.min(100, used / s.total * 100), left = Math.max(0, s.total - used);
      out += '<div class="ubar" role="progressbar" aria-label="Израсходованный трафик" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' + Math.round(pct) + '"><span class="ufill ' + (pct >= 90 ? 'bad' : pct >= 70 ? 'warn' : '') + '" style="width:' + Math.max(pct, 1.5).toFixed(1) + '%"></span></div>' +
        '<div class="uline"><span>Использовано <b>' + fmtTraffic(used) + '</b> из <b>' + fmtTraffic(s.total) + '</b></span><span>Осталось <b>' + fmtTraffic(left) + '</b> · ' + (pct < 1 && used > 0 ? '<1' : Math.round(pct)) + '%</span></div>';
    } else {
      out += '<div class="ubar inf" role="progressbar" aria-label="Трафик без лимита"><span class="ufill" style="width:100%"></span></div>' +
        '<div class="uline"><span>Использовано <b>' + fmtTraffic(used) + '</b></span><span>Без лимита трафика</span></div>';
    }
    if (s.expire > 0) {
      var days = Math.ceil((s.expire * 1000 - Date.now()) / 86400000), dt = new Date(s.expire * 1000).toLocaleDateString('ru-RU');
      out += '<div class="uline"><span>' + (days < 0 ? 'Срок истёк ' : 'Действует до ') + '<b>' + esc(dt) + '</b></span>' +
        (days < 0 ? '<span class="tag bad">истекла</span>' : '<span class="' + (days <= 3 ? 'tag warn' : '') + '">осталось ' + days + ' ' + daysWord(days) + '</span>') + '</div>';
    }
    return out + '</div>';
  }
  function vCard(p, sub) {
    var v = S.v, cfg = v.config;
    var sel = cfg.active === p.id, live = v.running && sel, ms = v.ping[p.id], busy = !!v.pinging[p.id], best = vBest();
    var info = p.ok ? p.address + ':' + p.port + ' · ' + p.network + (p.security !== 'none' ? ' · ' + p.security : '') : (p.error || 'Ссылка повреждена');
    var tag = live ? '<span class="tag ok">включён</span>' : busy ? '<span class="tag warn">…</span>'
      : !(p.id in v.ping) ? '' : ms == null ? '<span class="tag bad">нет ответа</span>'
      : '<span class="tag ' + (ms === best ? 'ok' : ms > 250 ? 'warn' : '') + '">' + ms + ' мс</span>';
    var del = sub ? '' : '<span class="vtools"><button class="btn xs" data-act="vDel" data-arg="' + esc(p.id) + '" aria-label="Удалить ' + esc(p.name) + '" title="Удалить"' + (live ? ' disabled' : '') + '>' + ico('x') + '</button></span>';
    return '<div class="strat srv vcard' + (sel ? ' cur' : '') + (busy ? ' scan' : '') + (p.ok ? '' : ' bad-link') + '" role="button" tabindex="0" data-act="vPick" data-arg="' + esc(p.id) + '" aria-pressed="' + sel + '">' +
      '<span class="shd"><span class="sn">' + flagHtml(p.code) + '<span class="nm">' + esc(p.label || p.name) + '</span>' + (sel ? ico('check') : '') + '</span><span class="vright">' + tag + del + '</span></span>' +
      '<span class="sf"><span class="ad">' + esc(info) + '</span></span></div>';
  }
  function vBest() {
    var b = null;
    S.v.profiles.forEach(function (p) { var m = S.v.ping[p.id]; if (typeof m === 'number' && (b === null || m < b)) b = m; });
    return b;
  }
  function vGroups() {
    var v = S.v, cfg = v.config, out = '';
    var fmt = function (t) { return t ? new Date(t * 1000).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '–'; };
    cfg.subs.forEach(function (s) {
      var list = v.profiles.filter(function (p) { return p.sub === s.id; }), open = vGroupOpen(s.id), re = v.refreshing === s.id;
      out += '<section class="sgrp"><div class="sg-head"><button class="sg-toggle" data-act="vToggle" data-arg="' + esc(s.id) + '" aria-expanded="' + open + '">' + ico('chev') + '<span class="nm">' + esc(s.name) + '</span><span class="tag">' + list.length + '</span></button><span class="sg-tools">' +
        (s.web ? '<button class="btn sm" data-act="vSubOpen" data-arg="' + esc(s.id) + ':web">Страница</button>' : '') +
        (s.support ? '<button class="btn sm" data-act="vSubOpen" data-arg="' + esc(s.id) + ':support">Поддержка</button>' : '') +
        '<button class="btn sm" data-act="vSubRefresh" data-arg="' + esc(s.id) + '"' + (v.busy ? ' disabled' : '') + '>' + (re ? 'Обновляем…' : 'Обновить') + '</button>' +
        '<button class="btn sm ghost" data-act="vSubRemove" data-arg="' + esc(s.id) + '" aria-label="Удалить подписку ' + esc(s.name) + '" title="Удалить подписку">' + ico('x') + '</button></span></div>' +
        '<div class="sg-meta">Обновлена ' + esc(fmt(s.updated)) + (s.interval ? ' · сервис просит обновлять раз в ' + s.interval + ' ч' : '') + '</div>' +
        usageHtml(s) + noteHtml(s) +
        (open ? (list.length ? '<div class="strats srvs">' + list.map(function (p) { return vCard(p, true); }).join('') + '</div>' : '<div class="sg-note">В подписке нет серверов.</div>') : '') + '</section>';
    });
    var own = v.profiles.filter(function (p) { return !p.sub; });
    if (own.length || !cfg.subs.length) {
      out += '<section class="sgrp plain"><div class="sg-head"><span class="sg-toggle" style="cursor:default">' + ico('net').replace('class="ic"', 'class="ic" style="transform:none"') + '<span class="nm">Обычные серверы</span><span class="tag">' + own.length + '</span></span></div>' +
        (own.length ? '<div class="strats srvs">' + own.map(function (p) { return vCard(p, false); }).join('') + '</div>' : '<div class="empty"><span>Серверов пока нет. Вставьте ссылку vless:// или адрес подписки выше.</span></div>') + '</section>';
    }
    return out;
  }
  function vSubRefresh(id) {
    if (!inTauri || S.v.busy) return;
    S.v.busy = true; S.v.refreshing = id; renderAll();
    T.core.invoke('vless_sub_refresh', { id: id }).then(vDone).catch(vErr).then(function () { S.v.busy = false; S.v.refreshing = ''; renderAll(); });
  }
  function vSubRemove(id) {
    if (!inTauri || S.v.busy) return;
    if (!window.confirm('Удалить подписку вместе с её серверами?')) return;
    T.core.invoke('vless_sub_remove', { id: id }).then(applyV).catch(vErr).then(renderAll);
  }
  function vSubAdd() { vImport(); }
  function vDefault(a) { S.v.config.default_action = a === 'direct' ? 'direct' : 'proxy'; vApplyNote(); vSave(); }
  function vMode(a) { S.v.config.mode = a === 'proxy' ? 'proxy' : 'tun'; vApplyNote(); vSave(); }
  function vRuleAdd() {
    var v = S.v, r = v.rule, val = String(r.value || '').trim();
    if (!val) { toast('Введите значение правила.', 'warn'); return; }
    var dup = v.config.rules.some(function (x) { return x.kind === r.kind && x.value === val && x.action === r.action; });
    if (!dup) v.config.rules.push({ kind: r.kind, value: val, action: r.action });
    r.value = '';
    vApplyNote(); vSave();
  }
  function vRuleAct(i) {
    var r = S.v.config.rules[Number(i)];
    if (!r) return;
    r.action = r.action === 'proxy' ? 'direct' : r.action === 'direct' ? 'block' : 'proxy';
    vApplyNote(); vSave();
  }
  function vRuleDel(i) { S.v.config.rules.splice(Number(i), 1); vApplyNote(); vSave(); }
  function vQuick() {
    var add = [['domain', 'regexp:\\.ru$'], ['domain', 'regexp:\\.su$'], ['domain', 'regexp:\\.xn--p1ai$'], ['ip', 'geoip:ru']];
    var rules = S.v.config.rules, n = 0;
    add.forEach(function (a) {
      if (!rules.some(function (x) { return x.kind === a[0] && x.value === a[1] && x.action === 'direct'; })) { rules.push({ kind: a[0], value: a[1], action: 'direct' }); n++; }
    });
    toast(n ? 'Добавлено правил: ' + n + '. Российские сайты пойдут напрямую.' : 'Эти правила уже есть.');
    vApplyNote(); vSave();
  }
  function vProcs() {
    if (!inTauri) { toast('Список приложений доступен в приложении Бунт.', 'warn'); return; }
    T.core.invoke('vless_processes').then(function (list) {
      var h = '<input class="field" id="vProcFilter" placeholder="Поиск по имени" aria-label="Поиск приложения" autocomplete="off"><div class="proc-list" id="vProcList">' +
        (list.length ? list.map(function (p) { return '<button data-act="vPickProc" data-arg="' + esc(p.name) + '" data-q="' + esc(p.name.toLowerCase()) + '"><b>' + esc(p.name) + '</b><small>' + esc(p.path) + '</small></button>'; }).join('') : '<div class="empty"><span>Запущенных приложений не нашлось.</span></div>') + '</div>';
      openModal('Запущенные приложения', h, '<button class="btn" data-act="closeModal">Закрыть</button>');
      var f = $('#vProcFilter'); if (f) f.focus();
    }).catch(vErr);
  }
  function vPickProc(name) {
    S.v.rule.kind = 'app'; S.v.rule.value = name;
    closeModal(); renderAll();
    var e = $('#vRuleVal'); if (e) e.focus();
  }
  function vRepair() {
    if (!inTauri || !installed('vless')) return;
    if (S.v.config.mode !== 'proxy' && adminNeeded()) return;
    addLog({ svc: SVC.vless.name, m: 'Восстанавливаем сеть…' });
    T.core.invoke('vless_repair').then(function (d) {
      applyV(d.info); S.v.repairMsg = d.message;
      addLog({ svc: SVC.vless.name, m: d.message, ok: true });
      toast(d.message);
    }).catch(function (err) { S.v.repairMsg = String(err); vErr(err); }).then(renderAll);
  }
  function vLog() {
    var v = S.v;
    v.logOpen = !v.logOpen;
    if (v.logOpen && inTauri) T.core.invoke('vless_log').then(function (t) { v.log = t || 'Журнал пуст.'; renderAll(); }).catch(function () {});
    renderAll();
  }
  function realVless(on, quiet) {
    var v = S.v;
    if (v.busy) return;
    if (on && vpnConflict('vless', quiet)) return;
    if (on && v.config.mode !== 'proxy' && adminNeeded(quiet)) return;
    if (on && !v.config.active) { if (!quiet) { toast('Сначала добавьте сервер и выберите его.', 'warn'); go('vless'); } return; }
    v.busy = true;
    var pr = v.profiles.filter(function (p) { return p.id === v.config.active; })[0];
    addLog({ svc: SVC.vless.name, m: on ? 'Подключаем «' + (pr ? pr.name : '') + '»…' : 'Отключаем и убираем следы в сети…' });
    renderAll();
    var p = on
      ? T.core.invoke('vless_connect', { id: v.config.active }).then(function (st) { applyV(st); addLog({ m: 'VLESS подключён' + (st.tun ? ' (TUN).' : ' (системный прокси).'), ok: true }); })
      : T.core.invoke('vless_disconnect').then(function (d) { applyV(d.info); v.repairMsg = d.message; addLog({ m: d.message, ok: true }); });
    p.catch(function (err) {
      S.on.vless = false;
      addLog({ svc: SVC.vless.name, m: 'Ошибка: ' + err });
      if (!quiet || on) toast(String(err).slice(0, 700), 'warn');
      vReload().then(renderAll);
    }).then(function () { v.busy = false; if (v.logOpen) T.core.invoke('vless_log').then(function (t) { v.log = t; renderAll(); }).catch(function () {}); renderAll(); });
  }
  function watchVless() {
    if (!inTauri || !installed('vless') || S.v.busy) return;
    T.core.invoke('vless_status').then(function (st) {
      var was = S.v.running;
      applyV(st);
      if (was && !st.running) addLog({ svc: SVC.vless.name, m: 'Ядро остановилось.' });
      if (st.dirty && (S.admin !== false || (st.config && st.config.mode === 'proxy'))) {
        S.v.busy = true;
        T.core.invoke('vless_repair').then(function (d) { applyV(d.info); S.v.repairMsg = d.message; addLog({ svc: SVC.vless.name, m: 'Бунт восстановил сеть после сбоя. ' + d.message, ok: true }); toast('Сеть после VLESS восстановлена'); })
          .catch(function () {}).then(function () { S.v.busy = false; renderAll(); });
      } else renderAll();
    }).catch(function () {});
  }
  /* Proxy: отдельный экземпляр ядра Xray со своими профилями и настройками, не связан с VLESS */
  var PXNAME = { http: 'HTTP', https: 'HTTPS', socks5: 'SOCKS5' };
  function applyP(st) {
    var p = S.p;
    p.profiles = st.profiles || []; p.config = st.config || p.config;
    p.running = !!st.running; p.tun = !!st.tun; p.dirty = !!st.dirty; p.adapter = !!st.adapter;
    S.on.proxy = p.running;
    p.socks = String(p.config.socks_port); p.http = String(p.config.http_port); p.dns_text = (p.config.dns || []).join(', ');
    p.loaded = true;
  }
  function pErr(err) { toast(String(err).slice(0, 700), 'warn'); }
  function pReload() { return inTauri ? T.core.invoke('proxy_status').then(applyP).catch(function () {}) : Promise.resolve(); }
  function pSave() {
    var p = S.p;
    if (!inTauri) { renderAll(); return Promise.resolve(); }
    var c = JSON.parse(JSON.stringify(p.config));
    c.socks_port = Number(p.socks) || 0; c.http_port = Number(p.http) || 0;
    c.dns = String(p.dns_text || '').split(/[\s,;]+/).filter(Boolean);
    return T.core.invoke('proxy_config_set', { config: c }).then(applyP).catch(function (err) { pErr(err); return pReload(); }).then(renderAll);
  }
  function pApplyNote() { if (S.p.running) toast('Настройки применятся при следующем подключении.'); }
  function pMsg(t) { var m = $('#pmMsg'); if (m) m.textContent = t; }
  function pAddText(text) {
    if (!text) { pMsg('Вставьте адрес прокси или заполните поля.'); return; }
    if (!inTauri) { pMsg('Добавление прокси работает в приложении Бунт.'); return; }
    S.p.busy = true; renderAll();
    T.core.invoke('proxy_add', { text: text }).then(function (d) {
      closeModal();
      applyP(d.info); addLog({ svc: SVC.proxy.name, m: d.message, ok: true }); toast(d.message);
    }).catch(function (err) { pMsg(String(err)); }).then(function () { S.p.busy = false; renderAll(); });
  }
  function pOpenAdd() {
    var f = function (id, label, ph, extra) { return '<div class="row"><span class="lbl">' + label + '</span><input class="field mono" id="' + id + '" spellcheck="false" autocomplete="off" placeholder="' + ph + '" aria-label="' + label + '"' + (extra || '') + ' style="width:210px"></div>'; };
    openModal('Добавить прокси',
      '<div class="row"><span class="lbl">Адрес целиком<small>Можно сразу несколько, по одному в строке</small></span></div>' +
      '<textarea class="field mono ta" id="pmLink" rows="2" style="min-height:0;height:62px" spellcheck="false" placeholder="socks5://user:pass@host:1080" aria-label="Адрес прокси"></textarea>' +
      '<p class="note mt-s">Или заполните поля. Если адрес выше указан, поля не нужны.</p>' +
      '<div class="row"><span class="lbl">Тип</span><select class="field" id="pmType" aria-label="Тип прокси" style="width:210px"><option value="socks5">SOCKS5</option><option value="http">HTTP</option><option value="https">HTTPS</option></select></div>' +
      f('pmHost', 'Адрес', 'proxy.example.com') + f('pmPort', 'Порт', '1080', ' inputmode="numeric"') +
      f('pmUser', 'Логин<small>Если нужен</small>', '') +
      '<div class="row"><span class="lbl">Пароль<small>Хранится только на этом компьютере</small></span><input class="field mono" type="password" id="pmPass" autocomplete="off" aria-label="Пароль" style="width:210px"></div>' +
      f('pmName', 'Название<small>Необязательно</small>', '') +
      '<p class="note" id="pmMsg">SOCKS4 ядро Xray не поддерживает. Строка вида хост:порт считается HTTP-прокси.</p>',
      '<button class="btn" data-act="closeModal">Отмена</button><button class="btn primary" data-act="pSubmit">Добавить</button>');
    var l = $('#pmLink'); if (l) l.focus();
  }
  function pSubmit() {
    var link = ($('#pmLink').value || '').trim();
    if (link) { pAddText(link); return; }
    var v = function (id) { return ($('#' + id).value || '').trim(); };
    var host = v('pmHost'), port = v('pmPort'), user = $('#pmUser').value.trim(), pass = $('#pmPass').value;
    if (!host || !port) { pMsg('Укажите адрес и порт или вставьте адрес целиком.'); return; }
    var auth = user ? encodeURIComponent(user) + (pass ? ':' + encodeURIComponent(pass) : '') + '@' : '';
    var h = host.indexOf(':') >= 0 && host.charAt(0) !== '[' ? '[' + host + ']' : host;
    pAddText($('#pmType').value + '://' + auth + h + ':' + port + (v('pmName') ? '#' + encodeURIComponent(v('pmName')) : ''));
  }
  function pPick(id) {
    var p = S.p;
    if (p.running && p.config.active !== id) { toast('Сначала отключите Proxy, потом выбирайте другой прокси.', 'warn'); return; }
    T.core.invoke('proxy_select', { id: id }).then(applyP).catch(pErr).then(renderAll);
  }
  function pDel(id) {
    var p = S.p;
    if (p.running && p.config.active === id) { toast('Этот прокси сейчас используется: сначала отключите Proxy.', 'warn'); return; }
    T.core.invoke('proxy_delete', { ids: [id] }).then(applyP).catch(pErr).then(renderAll);
  }
  function pMode(a) { S.p.config.mode = a === 'tun' ? 'tun' : 'proxy'; pApplyNote(); pSave(); }
  function pBest() {
    var b = null;
    S.p.profiles.forEach(function (x) { var m = S.p.ping[x.id]; if (typeof m === 'number' && (b === null || m < b)) b = m; });
    return b;
  }
  function pCard(x) {
    var p = S.p, sel = p.config.active === x.id, on = p.running && sel, ms = p.ping[x.id], busy = !!p.pinging[x.id], best = pBest();
    var info = x.ok ? (PXNAME[x.proto] || x.proto) + ' · ' + x.address + ':' + x.port + (x.auth ? ' · логин и пароль' : '') : (x.error || 'Адрес повреждён');
    var tag = on ? '<span class="tag ok">включён</span>' : busy ? '<span class="tag warn">…</span>'
      : !(x.id in p.ping) ? '' : ms == null ? '<span class="tag bad">нет ответа</span>'
      : '<span class="tag ' + (ms === best ? 'ok' : ms > 250 ? 'warn' : '') + '">' + ms + ' мс</span>';
    return '<div class="strat srv vcard' + (sel ? ' cur' : '') + (busy ? ' scan' : '') + (x.ok ? '' : ' bad-link') + '" role="button" tabindex="0" data-act="pPick" data-arg="' + esc(x.id) + '" aria-pressed="' + sel + '">' +
      '<span class="shd"><span class="sn">' + flagHtml(x.code) + '<span class="nm">' + esc(x.label || x.name) + '</span>' + (sel ? ico('check') : '') + '</span><span class="vright">' + tag +
      '<span class="vtools"><button class="btn xs" data-act="pDel" data-arg="' + esc(x.id) + '" aria-label="Удалить ' + esc(x.name) + '" title="Удалить"' + (on ? ' disabled' : '') + '>' + ico('x') + '</button></span></span></span>' +
      '<span class="sf"><span class="ad">' + esc(info) + '</span></span></div>';
  }
  var pPingRun = false;
  function pPingAll(quiet) {
    var p = S.p;
    if (pPingRun) return;
    var queue = p.profiles.filter(function (x) { return x.ok; }).map(function (x) { return x.id; });
    if (!queue.length) return;
    if (p.running) { if (!quiet) toast('Пока Proxy включён, пинг шёл бы через него. Отключите Proxy и повторите.', 'warn'); return; }
    var total = queue.length, active = 0, ended = false;
    pPingRun = true; p.ping = {}; renderProxy();
    function finish() {
      if (ended) return; ended = true;
      pPingRun = false; p.pinging = {}; p.pingAt = Date.now(); renderProxy();
      if (quiet) return;
      var ok = p.profiles.filter(function (x) { return typeof p.ping[x.id] === 'number'; }).sort(function (a, b) { return p.ping[a.id] - p.ping[b.id]; });
      toast(ok.length ? 'Быстрее всех: ' + (ok[0].label || ok[0].name) + ', ' + p.ping[ok[0].id] + ' мс. Отвечают: ' + ok.length + ' из ' + total : 'Ни один прокси не ответил. Проверьте интернет.', ok.length ? undefined : 'warn');
    }
    function pump() {
      while (active < 4 && queue.length && !p.running) {
        (function (id) {
          active++; p.pinging[id] = true;
          var run = inTauri ? T.core.invoke('proxy_ping_one', { id: id }) : new Promise(function (resolve) {
            setTimeout(function () { var h = 0; for (var k = 0; k < id.length; k++) h = (h * 31 + id.charCodeAt(k)) >>> 0; resolve(h % 9 === 4 ? null : 20 + (h % 180)); }, 300 + (id.charCodeAt(0) % 5) * 90);
          });
          run.then(function (ms) { return typeof ms === 'number' ? ms : null; }, function () { return null; }).then(function (ms) {
            p.ping[id] = ms; delete p.pinging[id]; active--;
            renderProxy(); pump();
          });
        })(queue.shift());
      }
      if (!active) finish();
    }
    pump();
  }
  function pAutoPing() { if (Date.now() - S.p.pingAt > 120000) pPingAll(true); }
  function pRepair() {
    if (!inTauri || !installed('proxy')) return;
    if (S.p.running) { toast('Proxy сейчас включён: сначала отключите его.', 'warn'); return; }
    S.p.busy = true; renderAll();
    addLog({ svc: SVC.proxy.name, m: 'Восстанавливаем сеть…' });
    T.core.invoke('proxy_repair').then(function (d) {
      applyP(d.info); S.p.repairMsg = d.message; toast(d.message);
      addLog({ svc: SVC.proxy.name, m: d.message, ok: true });
    }).catch(pErr).then(function () { S.p.busy = false; renderAll(); });
  }
  function pLog() {
    var p = S.p;
    p.logOpen = !p.logOpen;
    if (p.logOpen && inTauri) T.core.invoke('proxy_log').then(function (t) { p.log = t || 'Журнал пуст.'; renderAll(); }).catch(function () {});
    renderAll();
  }
  function realProxy(on, quiet) {
    var p = S.p;
    if (p.busy) return;
    if (on && p.config.mode !== 'proxy' && adminNeeded(quiet)) return;
    if (on && !p.config.active) { if (!quiet) { toast('Сначала добавьте прокси и выберите его.', 'warn'); go('proxy'); } return; }
    p.busy = true;
    var pr = p.profiles.filter(function (x) { return x.id === p.config.active; })[0];
    addLog({ svc: SVC.proxy.name, m: on ? 'Подключаем «' + (pr ? pr.name : '') + '»…' : 'Отключаем и убираем следы в сети…' });
    renderAll();
    var run = on
      ? T.core.invoke('proxy_connect', { id: p.config.active }).then(function (st) { applyP(st); addLog({ m: 'Proxy подключён' + (st.tun ? ' (TUN).' : ' (системный прокси).'), ok: true }); })
      : T.core.invoke('proxy_disconnect').then(function (d) { applyP(d.info); p.repairMsg = d.message; addLog({ m: d.message, ok: true }); });
    run.catch(function (err) {
      S.on.proxy = false;
      addLog({ svc: SVC.proxy.name, m: 'Ошибка: ' + err });
      if (!quiet || on) toast(String(err).slice(0, 700), 'warn');
      pReload().then(renderAll);
    }).then(function () { p.busy = false; if (p.logOpen) T.core.invoke('proxy_log').then(function (t) { p.log = t; renderAll(); }).catch(function () {}); renderAll(); });
  }
  function watchProxy() {
    if (!inTauri || !installed('proxy') || S.p.busy) return;
    T.core.invoke('proxy_status').then(function (st) {
      var was = S.p.running;
      applyP(st);
      if (was && !st.running) addLog({ svc: SVC.proxy.name, m: 'Ядро остановилось.' });
      if (st.dirty && (S.admin !== false || (st.config && st.config.mode === 'proxy'))) {
        S.p.busy = true;
        T.core.invoke('proxy_repair').then(function (d) { applyP(d.info); S.p.repairMsg = d.message; addLog({ svc: SVC.proxy.name, m: 'Бунт восстановил сеть после сбоя. ' + d.message, ok: true }); toast('Сеть после Proxy восстановлена'); })
          .catch(function () {}).then(function () { S.p.busy = false; renderAll(); });
      } else renderAll();
    }).catch(function () {});
  }
  function renderProxy() {
    var p = S.p, c = comp('proxy'), cfg = p.config;
    var set = function (id, t) { var e = $(id); if (e) e.textContent = t; };
    set('#pVer', c.cur || '–');
    var el = $('#pList');
    if (el) el.innerHTML = '<div class="strats srvs">' + p.profiles.map(pCard).join('') +
      '<button class="strat srv vcard add" data-act="pOpenAdd"' + (p.busy ? ' disabled' : '') + '><span class="shd"><span class="sn">' + ico('plus') + '<span class="nm">Добавить прокси</span></span></span><span class="sf"><span class="ad">SOCKS5, HTTP или HTTPS</span></span></button></div>';
    var pp = function (id, on) { var e = $(id); if (e) e.setAttribute('aria-pressed', String(on)); };
    pp('#pModeTun', cfg.mode === 'tun'); pp('#pModeProxy', cfg.mode !== 'tun');
    var tun = cfg.mode === 'tun';
    var pt = $('#pPorts'); if (pt) pt.hidden = tun;
    var dr = $('#pDnsRow'); if (dr) dr.hidden = !tun;
    set('#pModeNote', tun ? 'Весь трафик компьютера идёт через виртуальный адаптер и выбранный прокси. Нужны права администратора.' : 'Включается системный прокси Windows и локальные SOCKS и HTTP. Работает без администратора, но приложения без поддержки прокси пойдут мимо.');
    var sbx = $('#pStatsBox'); if (sbx) sbx.hidden = !p.running;
    if (p.running) {
      var pr = p.profiles.filter(function (x) { return x.id === cfg.active; })[0];
      set('#pRunMode', p.tun ? 'TUN, весь трафик' : 'Системный прокси'); set('#pRunSrv', pr ? pr.name : '–');
      set('#pRunAd', p.tun ? (p.adapter ? 'Работает' : 'Нет') : 'Не используется');
    }
    var d = $('#pDirty'); if (d) d.hidden = !p.dirty;
    var rm = $('#pRepairMsg'); if (rm) { rm.hidden = !p.repairMsg; rm.textContent = p.repairMsg; }
    var lg = $('#pLog'); if (lg) { lg.hidden = !p.logOpen; lg.textContent = p.log || ''; }
    var pb = $('#pPingBtn'); if (pb) { pb.disabled = pPingRun || !p.profiles.length; pb.lastChild.textContent = pPingRun ? 'Проверяем…' : 'Пинг'; }
    var sw = document.querySelector('.head-sw [data-svc="proxy"]'); if (sw) sw.disabled = p.busy;
    var stt = document.querySelector('[data-state="proxy"]');
    if (stt && p.busy) { stt.className = 'state'; stt.innerHTML = '<span class="spin"></span>Подождите…'; }
  }
  function renderVless() {
    var v = S.v, c = comp('vless'), cfg = v.config;
    var set = function (id, t) { var e = $(id); if (e) e.textContent = t; };
    set('#vVer', c.cur || '–');
    var gr = $('#vGroups'); if (gr) gr.innerHTML = vGroups();
    var rl = $('#vRules');
    if (rl) rl.innerHTML = !cfg.rules.length ? '<div class="empty"><span>Правил нет: весь трафик идёт по варианту «по умолчанию».</span></div>' : cfg.rules.map(function (r, i) {
      var cls = r.action === 'proxy' ? 'ok' : r.action === 'block' ? 'bad' : '';
      return '<div class="rule"><span class="tag">' + esc(VKIND[r.kind] || r.kind) + '</span><span class="rv"><b class="mono">' + esc(r.value) + '</b></span>' +
        '<button class="tag ' + cls + '" data-act="vRuleAct" data-arg="' + i + '" title="Нажмите, чтобы сменить действие">' + esc(VACT[r.action] || r.action) + '</button>' +
        '<button class="btn sm ghost" data-act="vRuleDel" data-arg="' + i + '" aria-label="Удалить правило">' + ico('x') + '</button></div>';
    }).join('');
    var pp = function (id, on) { var e = $(id); if (e) e.setAttribute('aria-pressed', String(on)); };
    pp('#vDefProxy', cfg.default_action !== 'direct'); pp('#vDefDirect', cfg.default_action === 'direct');
    pp('#vModeTun', cfg.mode !== 'proxy'); pp('#vModeProxy', cfg.mode === 'proxy');
    var tun = cfg.mode !== 'proxy';
    var pt = $('#vPorts'); if (pt) pt.hidden = tun;
    var dr = $('#vDnsRow'); if (dr) dr.hidden = !tun;
    set('#vModeNote', tun ? 'Весь трафик компьютера идёт через виртуальный адаптер, подходит для игр и любых программ. Нужны права администратора.' : 'Включается системный прокси Windows и локальные SOCKS и HTTP. Работает без администратора, но приложения без поддержки прокси пойдут мимо.');
    var rv = $('#vRuleVal'); if (rv) rv.placeholder = VHINT[v.rule.kind] || '';
    var sbx = $('#vStatsBox'); if (sbx) sbx.hidden = !v.running;
    if (v.running) {
      var pr = v.profiles.filter(function (p) { return p.id === cfg.active; })[0];
      set('#vRunMode', v.tun ? 'TUN, весь трафик' : 'Системный прокси'); set('#vRunSrv', pr ? pr.name : '–');
      set('#vRunAd', v.tun ? (v.adapter ? 'Работает' : 'Нет') : 'Не используется');
    }
    var d = $('#vDirty'); if (d) d.hidden = !v.dirty;
    var rm = $('#vRepairMsg'); if (rm) { rm.hidden = !v.repairMsg; rm.textContent = v.repairMsg; }
    var lg = $('#vLog'); if (lg) { lg.hidden = !v.logOpen; lg.textContent = v.log || ''; }
    var pb = $('#vPingBtn'); if (pb) { pb.disabled = vPingRun || !v.profiles.length; pb.lastChild.textContent = vPingRun ? 'Проверяем…' : 'Пинг'; }
    var sw = document.querySelector('.head-sw [data-svc="vless"]'); if (sw) sw.disabled = v.busy;
    var stt = document.querySelector('[data-state="vless"]');
    if (stt && v.busy) { stt.className = 'state'; stt.innerHTML = '<span class="spin"></span>Подождите…'; }
  }
  function restartDiscord() {
    if (!inTauri) return;
    if (S.svc.installed) { toast('Служба Windows работает с прежними настройками. Нажмите «Переустановить» в блоке «Служба Windows», чтобы применить новые.', 'warn'); return; }
    if (!S.on.discord) return;
    realDiscord(true, false);
  }
  function stopAll() { IDS.forEach(function (id) { setSvc(id, false, true); }); }
  function toggleAll() {
    var any = IDS.some(function (id) { return S.on[id]; });
    if (any) stopAll(); else IDS.forEach(function (id) { setSvc(id, true, true); });
  }

  /* стратегии */
  function pickStrat(name) {
    if (testing) { toast('Идёт подбор, дождитесь завершения.', 'warn'); return; }
    var d = S.discord;
    if (d.strategy === name) return;
    d.strategy = name;
    d.mode = 'manual';
    addLog({ svc: 'Zapret (Discord)', m: 'Стратегия: ' + name + '.' });
    if (S.on.discord) addLog({ svc: 'Zapret (Discord)', m: 'Перезапуск службы со стратегией ' + name + '…' });
    toast('Выбрана стратегия: ' + name);
    renderAll();
    restartDiscord();
  }
  /* all: проверить все и ничего не менять; иначе: искать, пока не найдётся стратегия, где открывается всё */
  function runTest(all) {
    if (testing || probing) return;
    var d = S.discord;
    if (vpnRunning()) { toast('Выключите VPN на время проверки: через него результат не показывает работу запрета.', 'warn'); return; }
    if (inTauri && S.admin === false) { toast('Нужны права администратора. Нажмите «Дать права» вверху окна.', 'warn'); return; }
    if (inTauri && !installed('discord')) { toast('Сначала установите компонент.', 'warn'); return; }
    var names = STRATS.slice(), i0 = names.indexOf(d.strategy);
    if (i0 > 0) { names.splice(i0, 1); names.unshift(d.strategy); }   /* текущую проверяем первой */
    testing = true; testCancel = false; testRan = []; scanning = null; flash = null;
    $('#testBox .bar-fill').style.width = '0%';
    $('#testState').textContent = 'Запускаем проверку…';
    addLog({ svc: 'Zapret (Discord)', m: all ? 'Проверка всех стратегий…' : 'Подбор стратегии…' });
    renderDiscord();
    var run;
    if (inTauri) {
      run = T.core.invoke('zapret_test', { strategies: names, game: d.game, ipset: d.ipset, stopOnFull: !all, gameTcp: d.tcpPorts, gameUdp: d.udpPorts });
    } else {
      run = new Promise(function (resolve) {
        var k = 0;
        (function step() {
          if (k >= names.length || testCancel) { resolve({ results: d.results }); return; }
          var n = names[k], i = k;
          onTestEvent({ phase: 'start', index: i, total: names.length, name: n });
          setTimeout(function () {
            var checks = demoChecks(n);
            d.results[n] = { at: Math.floor(Date.now() / 1000), checks: checks, error: null };
            onTestEvent({ phase: 'done', index: i, total: names.length, name: n });
            k++;
            if (!all && okCount(d.results[n]) === checks.length) { resolve({ results: d.results }); return; }
            step();
          }, 200);
        })();
      });
    }
    run.then(function (res) {
      applyResults(res);
      d.free = null;
      testing = false; scanning = null;
      var ran = testRan.length ? testRan : names, best = null;
      ran.forEach(function (n) {
        var r = d.results[n];
        if (!r || r.error) return;
        var c = okCount(r), ms = avgMs(r);
        if (!best || c > best.c || (c === best.c && ms < best.ms)) best = { n: n, c: c, ms: ms };
      });
      var total = best ? d.results[best.n].checks.length : targetsAll().length;
      if (!best || best.c === 0) {
        addLog({ m: 'Ни одна из проверенных стратегий не открывает сервисы.' });
        toast('Ни одна стратегия не открыла сервисы. Проверьте интернет и отключите VPN.', 'warn');
      } else if (all) {
        addLog({ m: 'Проверено стратегий: ' + ran.length + '. Лучшая: ' + best.n + ', ' + best.c + ' из ' + total + '.', ok: true });
        toast('Проверено: ' + ran.length + '. Лучшая: ' + best.n + ' (' + best.c + '/' + total + ')');
      } else {
        var changed = d.strategy !== best.n;
        d.strategy = best.n; d.mode = 'auto'; flash = best.n;
        addLog({ m: 'Выбрана стратегия ' + best.n + ': открывается ' + best.c + ' из ' + total + '.', ok: best.c === total });
        toast((best.c === total ? 'Подобрана стратегия: ' : 'Лучшая из найденных: ') + best.n + (best.c === total ? '' : ' (' + best.c + '/' + total + ')'));
        if (changed) restartDiscord();
        setTimeout(function () { flash = null; renderDiscord(); }, 1400);
      }
      renderAll();
      if (!all && best && best.c > 0) { var w = $('.strat.cur'); if (w && w.scrollIntoView) w.scrollIntoView({ block: 'center', behavior: 'smooth' }); }
    }).catch(function (e) {
      testing = false; scanning = null;
      toast(String(e).slice(0, 220), 'warn');
      if (inTauri) T.core.invoke('zapret_results').then(function (r) { applyResults(r); renderAll(); }).catch(function () { renderAll(); });
      else renderAll();
    });
  }
  function autotest() { runTest(false); }
  function testall() { runTest(true); }
  function testcancel() {
    testCancel = true;
    $('#testState').textContent = 'Останавливаем после текущей стратегии…';
    if (inTauri) T.core.invoke('zapret_test_cancel').catch(function () {});
  }
  /* быстрая проверка сервисов на текущей стратегии */
  function probe() {
    if (testing || probing) return;
    if (vpnRunning()) { toast('Выключите VPN на время проверки: через него результат не показывает работу запрета.', 'warn'); return; }
    probing = true;
    renderDiscord();
    var d = S.discord;
    var run = inTauri ? T.core.invoke('zapret_probe') : new Promise(function (resolve) {
      setTimeout(function () { resolve({ strategy: S.on.discord ? d.strategy : null, checks: demoChecks(S.on.discord ? d.strategy : 'без запрета'), at: Math.floor(Date.now() / 1000) }); }, 500);
    });
    run.then(function (r) {
      probing = false;
      if (r.strategy) { d.results[r.strategy] = { at: r.at, checks: r.checks, error: null }; d.free = null; }
      else d.free = { at: r.at, checks: r.checks };
      renderDiscord();
    }).catch(function (e) { probing = false; renderDiscord(); toast(String(e).slice(0, 200), 'warn'); });
  }


  /* обновления */
  var checking = false;
  var comp = function (id) { return S.comps.filter(function (c) { return c.id === id; })[0]; };
  function setAppVersion(v) {
    $$('[data-appver]').forEach(function (el) { el.textContent = v; });
    var c = comp('app');
    if (c) c.cur = v;
  }
  function finishCheck(silent) {
    S.lastCheck = 'только что, ' + hms().slice(0, 5);
    var n = live().filter(function (c) { return c.next; }).length;
    addLog({ m: n ? 'Проверка обновлений — доступно обновлений: ' + n + '.' : 'Проверка обновлений — у вас последняя версия.' });
    if (!silent || n) toast(n ? 'Доступно обновлений: ' + n : 'Все компоненты актуальны');
    renderAll();
  }
  /* silent: проверка при запуске, о результате сообщаем только если есть новая версия */
  function checkUpdates(silent) {
    if (checking) return;
    checking = true;
    if (!silent) toast('Проверяем GitHub…');
    if (!inTauri) {
      setTimeout(function () { checking = false; finishCheck(silent); }, 1100);
      return;
    }
    Object.keys(REAL).forEach(function (id) { if (comp(id).cur) refreshLatest(id).then(renderAll); });
    T.core.invoke('check_update').then(function (info) {
      var c = comp('app');
      c.cur = info.current;
      c.next = info.available ? info.latest : null;
      c.notes = info.notes ? [info.notes] : [];
      c.checked = true;
      S.verErr = null;
      checking = false;
      loadNotes();
      finishCheck(silent);
    }).catch(function (err) {
      checking = false;
      comp('app').checked = true;
      var msg = String(err);
      S.verErr = msg;
      addLog({ m: 'Проверка обновлений — ошибка: ' + msg });
      if (!silent) {
        toast(/pubkey|public key|base64|decode|signature/i.test(msg)
          ? 'Ключ подписи обновлений не настроен. См. README.'
          : 'Не удалось проверить обновления. Проверьте сеть и наличие релиза на GitHub.', 'warn');
      }
      renderAll();
    });
  }
  /* настоящие компоненты внутри Tauri: пока только запрет для Discord и YouTube */
  var REAL = { discord: true, telegram: true, fptn: true, wg: true, vless: true, proxy: true };
  function refreshLatest(id) {
    return T.core.invoke('latest_component', { id: id }).then(function (l) {
      var c = comp(id);
      c.latest = l.version;
      c.next = c.cur && c.cur !== l.version ? l.version : null;
      c.checked = true;
    }).catch(function (err) { S.verErr = String(err); comp(id).checked = true; });
  }
  function installReal(id) {
    var c = comp(id);
    if (adminNeeded()) return;
    c.busy = 0;
    addLog({ svc: c.name, m: 'Загрузка из ' + c.src.replace(/ \(GitHub\)/, '') + '…' });
    renderAll();
    T.core.invoke('install_component', { id: id }).then(function (v) {
      c.cur = v; c.latest = v; c.next = null; c.busy = null; c.stage = null;
      if (id === 'telegram') T.core.invoke('telegram_status').then(function (st) { applyTg(st); renderAll(); }).catch(function () {});
      if (id === 'fptn') T.core.invoke('fptn_status').then(function (st) { applyF(st); renderAll(); }).catch(function () {});
      if (id === 'wg') T.core.invoke('wg_status').then(function (st) { applyW(st); renderAll(); }).catch(function () {});
      if (id === 'vless') T.core.invoke('vless_status').then(function (st) { applyV(st); renderAll(); }).catch(function () {});
      if (id === 'proxy') T.core.invoke('proxy_status').then(function (st) { applyP(st); renderAll(); }).catch(function () {});
      addLog({ svc: c.name, m: 'Установлено: ' + v + '. Хеш проверен.', ok: true });
      toast(c.name + ' установлен');
      renderAll();
    }).catch(function (err) {
      c.busy = null; c.stage = null;
      addLog({ svc: c.name, m: 'Ошибка установки: ' + err });
      toast('Не удалось установить: ' + String(err).slice(0, 160), 'warn');
      renderAll();
    });
  }
  /* переустановка и удаление компонентов */
  function reinstallAsk(id) {
    var c = comp(id);
    openModal('Переустановить: ' + c.name,
      '<p>Файлы будут скачаны с GitHub заново (последняя версия) и заменят установленные. Если запрет был включён, он перезапустится.</p><p class="note">' + (id === 'telegram' ? 'Порт и ссылка для Telegram останутся прежними.' : id === 'fptn' ? 'Токен и настройки FPTN сохранятся. Если VPN был включён, он подключится заново.' : id === 'wg' ? 'Профили и ключи сохранятся. Если туннель был включён, Бунт отключит его на время установки и подключит заново.' : id === 'vless' ? 'Серверы, подписки и правила сохранятся. Если VLESS был включён, Бунт отключит его на время установки и подключит заново.' : id === 'proxy' ? 'Список прокси и настройки сохранятся. Если Proxy был включён, Бунт отключит его на время установки и подключит заново.' : 'Ваши списки доменов и IP сохранятся.') + '</p>',
      '<button class="btn" data-act="closeModal">Отмена</button><button class="btn primary" data-act="reinstallDo" data-arg="' + id + '">Переустановить</button>');
  }
  function reinstallDo(id) {
    closeModal();
    var c = comp(id);
    if (!c || c.busy != null || adminNeeded()) return;
    var was = !!S.on[id];
    c.busy = 0;
    addLog({ svc: c.name, m: 'Переустановка: загрузка из ' + c.src.replace(/ \(GitHub\)/, '') + '…' });
    renderAll();
    T.core.invoke('install_component', { id: id, force: true }).then(function (v) {
      c.cur = v; c.latest = v; c.next = null; c.busy = null; c.stage = null; S.on[id] = false;
      addLog({ svc: c.name, m: 'Переустановлено: ' + v + '. Хеш проверен.', ok: true });
      toast(c.name + ': переустановлено');
      renderAll();
      if (was) { if (id === 'telegram') realTelegram(true, true); else if (id === 'fptn') realFptn(true, true); else if (id === 'wg') realWg(true, true); else if (id === 'vless') realVless(true, true); else if (id === 'proxy') realProxy(true, true); else realDiscord(true, true); }
    }).catch(function (err) {
      c.busy = null; c.stage = null;
      addLog({ svc: c.name, m: 'Ошибка переустановки: ' + err });
      toast('Не удалось переустановить: ' + String(err).slice(0, 160), 'warn');
      renderAll();
    });
  }
  function uninstallAsk(id) {
    var c = comp(id);
    openModal('Удалить: ' + c.name,
      '<p>Запрет будет остановлен, а все файлы компонента удалены из папки <span class="mono">modules</span>' + (id === 'telegram' ? ', в том числе настройки прокси (порт и секрет). Ссылку в Telegram придётся добавить заново.' : id === 'fptn' ? ', в том числе токен и настройки FPTN. Перед удалением Бунт отключит VPN и вернёт сеть в исходное состояние. Токен придётся ввести заново.' : id === 'wg' ? ', в том числе все профили с ключами. Перед удалением Бунт отключит туннель и вернёт сеть в исходное состояние. Сохраните свои .conf: профили придётся импортировать заново.' : id === 'vless' ? ', в том числе все серверы, подписки и правила. Перед удалением Бунт отключит VLESS, вернёт системный прокси и сеть в исходное состояние. Ссылки придётся добавить заново.' : id === 'proxy' ? ', в том числе весь список прокси с паролями. Перед удалением Бунт отключит Proxy, вернёт системный прокси и сеть в исходное состояние. Прокси придётся добавить заново.' : ', в том числе ваши списки доменов и IP.') + '</p><p class="note">Потом его можно установить заново кнопкой «Установить».</p>',
      '<button class="btn" data-act="closeModal">Отмена</button><button class="btn danger" data-act="uninstallDo" data-arg="' + id + '">Удалить</button>');
  }
  function uninstallDo(id) {
    closeModal();
    var c = comp(id);
    if (!c || c.busy != null || adminNeeded()) return;
    T.core.invoke('uninstall_component', { id: id }).then(function () {
      c.cur = null; c.next = null; S.on[id] = false;
      if (id === 'telegram') S.telegram.link = '';
      if (id === 'fptn') { S.fptn.tokenSet = false; S.fptn.hint = ''; S.fptn.adapter = { exists: false, status: '', description: '' }; S.fptn.dirty = false; }
      if (id === 'proxy') { S.p.profiles = []; S.p.config.active = ''; S.p.running = false; S.p.dirty = false; S.p.view = ''; }
      if (id === 'vless') { S.v.profiles = []; S.v.config.active = ''; S.v.config.subs = []; S.v.config.rules = []; S.v.running = false; S.v.dirty = false; S.v.view = ''; }
      if (id === 'wg') { S.w.profiles = []; S.w.config.active = ''; S.w.running = false; S.w.tunnel = ''; S.w.dirty = false; S.w.adapter = { exists: false, status: '', description: '' }; S.w.view = ''; }
      S.sec.items = [];
      addLog({ svc: c.name, m: 'Компонент удалён.' });
      toast(c.name + ' удалён');
      renderAll();
    }).catch(function (err) {
      toast('Не удалось удалить: ' + String(err).slice(0, 180), 'warn');
    });
  }
  function installComp(id) {
    var c = comp(id);
    if (!c || c.cur || c.busy != null) return;
    if (inTauri && REAL[id]) { installReal(id); return; }
    c.busy = 0;
    addLog({ svc: c.name, m: 'Загрузка версии ' + c.latest + ' из ' + c.src.replace(/ \(GitHub\)/, '') + '…' });
    renderAll();
    var iv = setInterval(function () {
      c.busy += 10;
      if (c.busy >= 100) {
        clearInterval(iv);
        c.cur = c.latest; c.busy = null; c.stage = null;
        addLog({ svc: c.name, m: 'Установлено: ' + c.cur + '. Хеш проверен.', ok: true });
        toast(c.name + ' установлен');
      }
      renderAll();
    }, 180);
  }
  function updateOne(id) {
    var c = S.comps.filter(function (x) { return x.id === id; })[0];
    if (!c || !c.next || c.busy != null) return;
    if (inTauri && REAL[id]) { installReal(id); return; }
    if (inTauri && id === 'app') {
      c.busy = 0;
      renderVersions();
      addLog({ svc: 'Бунт', m: 'Загрузка версии ' + c.next + '…' });
      T.core.invoke('install_update').catch(function (err) {
        c.busy = null; c.stage = null;
        toast('Не удалось установить обновление: ' + String(err).slice(0, 140), 'warn');
        renderVersions();
      });
      return;
    }
    var was = !!S.on[id];
    if (was) setSvc(id, false, true);
    c.busy = 0;
    renderVersions();
    var iv = setInterval(function () {
      c.busy += 10;
      if (c.busy >= 100) {
        clearInterval(iv);
        c.cur = c.next; c.next = null; c.busy = null; c.stage = null; c.notes = [];
        addLog({ svc: c.name, m: 'Обновлено до ' + c.cur + '. Хеш проверен.', ok: true });
        toast(c.name + ': версия ' + c.cur);
        if (was) setSvc(id, true, true);
        renderAll();
      } else { renderVersions(); }
    }, 180);
  }

  /* проверка целостности */
  function runSecOnline() {
    if (S.sec.running) return;
    if (!inTauri) { toast('Сверка с GitHub работает только в приложении', 'warn'); return; }
    S.sec.running = true;
    S.sec.items = [{ t: 'Скачиваем оригинальный релиз и сверяем файлы…', st: 'run' }];
    renderSecurity();
    T.core.invoke('integrity_verify_online').then(function (list) {
      S.sec.items = list.map(function (r) { return { t: r.title, st: r.state, note: r.note, g: r.group }; });
      var bad = list.filter(function (r) { return r.state === 'bad'; }).length;
      addLog(bad ? { m: 'Сверка с GitHub: найдены отличия от оригинала (' + bad + ').' } : { m: 'Сверка с GitHub завершена.', ok: true });
    }).catch(function (err) {
      S.sec.items = [{ t: 'Сверка не выполнена', st: 'bad', note: String(err) }];
    }).then(function () {
      S.sec.running = false;
      S.sec.last = nowShort();
      renderSecurity();
    });
  }
  /* тихая проверка при запуске и раз в шесть часов: сообщает, только если что-то нарушено */
  function secAuto() {
    if (!inTauri || S.sec.running) return;
    T.core.invoke('integrity_check').then(function (list) {
      if (S.sec.running) return;
      S.sec.items = list.map(function (r) { return { t: r.title, st: r.state, note: r.note, g: r.group }; });
      S.sec.last = nowShort();
      var bad = list.filter(function (r) { return r.state === 'bad'; });
      if (bad.length) {
        addLog({ m: 'Проверка целостности при запуске: найдены нарушения (' + bad.length + ').' });
        toast('Безопасность: найдены изменённые или подложенные файлы (' + bad.length + '). Откройте раздел «Безопасность».', 'warn');
      }
      renderSecurity();
    }).catch(function () {});
  }
  function runSec() {
    if (S.sec.running) return;
    if (inTauri) {
      S.sec.running = true;
      S.sec.items = [{ t: 'Проверка файлов и подписей', st: 'run' }];
      renderSecurity();
      T.core.invoke('integrity_check').then(function (list) {
        S.sec.items = list.map(function (r) { return { t: r.title, st: r.state, note: r.note, g: r.group }; });
        var bad = list.filter(function (r) { return r.state === 'bad'; }).length;
        addLog(bad ? { m: 'Проверка целостности: найдены нарушения (' + bad + ').' } : { m: 'Проверка целостности завершена. Нарушений нет.', ok: true });
      }).catch(function (err) {
        S.sec.items = [{ t: 'Проверка не выполнена', st: 'bad', note: String(err) }];
      }).then(function () {
        S.sec.running = false;
        S.sec.last = nowShort();
        renderSecurity();
      });
      return;
    }
    S.sec.running = true;
    S.sec.items.forEach(function (i) { i.st = 'idle'; });
    renderSecurity();
    var k = 0;
    (function step() {
      if (k >= S.sec.items.length) {
        S.sec.running = false;
        S.sec.last = nowShort();
        addLog({ m: 'Проверка целостности завершена. Все файлы в порядке.', ok: true });
        renderSecurity();
        return;
      }
      S.sec.items[k].st = 'run';
      renderSecurity();
      setTimeout(function () { S.sec.items[k].st = 'ok'; k++; renderSecurity(); step(); }, 750);
    })();
  }

  function copyText(text, okMsg) {
    var p = (navigator.clipboard && navigator.clipboard.writeText) ? navigator.clipboard.writeText(text) : Promise.reject();
    p.then(function () { toast(okMsg); }).catch(function () { var f = $('#tgLink'); if (f) { f.focus(); f.select(); } toast('Выделили ссылку, скопируйте её вручную.', 'warn'); });
  }

  function openModal(title, body, foot) {
    $('#mTitle').textContent = title;
    $('#mBody').innerHTML = body;
    $('#mFoot').innerHTML = foot;
    $('#modal').hidden = false;
    var f = $('#modal textarea') || $('#modal .btn');
    if (f) f.focus();
  }
  function closeModal() { $('#modal').hidden = true; }

  var ACT = {
    editList: function (k) {
      var l = S.lists[k], ed = l.editable !== false;
      openModal(l.file,
        '<p class="note">' + esc(l.hint) + '</p><textarea class="field mono ta" id="listEdit" spellcheck="false"' + (ed ? '' : ' readonly') + ' aria-label="' + esc(l.file) + '">' + esc(l.text) + '</textarea>',
        (ed ? '<button class="btn primary" data-act="saveList" data-arg="' + k + '">Сохранить</button><button class="btn" data-act="closeModal">Отмена</button>' : '<button class="btn" data-act="closeModal">Закрыть</button>'));
    },
    saveList: function (k) {
      var text = $('#listEdit').value;
      function done(clean) {
        S.lists[k].text = clean;
        S.lists[k].count = undefined;
        closeModal();
        addLog({ svc: 'Zapret (Discord)', m: 'Сохранён ' + S.lists[k].file + '.' });
        toast(S.on.discord && inTauri ? 'Список сохранён, запрет перезапускается' : 'Список сохранён. Он применится при следующем запуске запрета.');
        renderAll();
        if (inTauri) { refreshDiscordExtras(); restartDiscord(); }
      }
      if (!inTauri) { done(text); return; }
      T.core.invoke('zapret_list_save', { key: k, text: text }).then(done).catch(failToast);
    },
    closeModal: closeModal,
    updIpset: function () {
      if (!inTauri) { S.discord.ipsetUpdated = 'только что, ' + hms().slice(0, 5); toast('Список обновлён (демонстрация)'); renderDiscord(); return; }
      toast('Скачиваем список…');
      T.core.invoke('zapret_ipset_update').then(function (r) {
        S.discord.ipsetUpdated = fmtAt(r.at);
        addLog({ svc: 'Zapret (Discord)', m: 'Список IP обновлён из репозитория: ' + r.count + ' записей.', ok: true });
        toast('Список IP обновлён: ' + r.count + ' записей');
        refreshDiscordExtras();
        if (S.discord.ipset === 'loaded') restartDiscord();
        else if (S.discord.ipset !== 'loaded') toast('Список применяется в режиме IPSet loaded.');
      }).catch(failToast);
    },
    fakes: function () {
      if (!inTauri) { onlyInApp(); return; }
      T.core.invoke('zapret_fakes').then(function (r) {
        var opts = function (cur) { return r.fakes.map(function (f) { return '<option value="' + esc(f.name) + '"' + (f.name === cur ? ' selected' : '') + '>' + esc(f.name) + '</option>'; }).join(''); };
        var unk = function (cur) { return cur ? '' : '<option value="" selected>Другой (не из списка)</option>'; };
        openModal('Фейки',
          '<p class="note">Фейк это образец пакета, под который запрет маскирует трафик. Если стратегии не помогают, иногда помогает другой образец. После замены запрет перезапускается.</p>' +
          '<div class="row"><div class="lbl">Голос Discord (UDP)<small class="mono">ACTIVE_DISCORD_UDP.bin</small></div><select class="field" id="fkDiscord" style="width:230px">' + unk(r.discord) + opts(r.discord) + '</select></div>' +
          '<div class="row"><div class="lbl">Игры (UDP)<small class="mono">ACTIVE_GAME_UDP.bin</small></div><select class="field" id="fkGame" style="width:230px">' + unk(r.game) + opts(r.game) + '</select></div>',
          '<button class="btn primary" data-act="fakesApply" data-arg="' + esc((r.discord || '') + '|' + (r.game || '')) + '">Применить</button><button class="btn" data-act="closeModal">Отмена</button>');
      }).catch(failToast);
    },
    fakesApply: function (arg) {
      var was = String(arg).split('|'), calls = [];
      [['discord', $('#fkDiscord').value, was[0]], ['game', $('#fkGame').value, was[1]]].forEach(function (x) {
        if (x[1] && x[1] !== x[2]) calls.push(T.core.invoke('zapret_fake_set', { target: x[0], name: x[1] }));
      });
      if (!calls.length) { closeModal(); return; }
      Promise.all(calls).then(function () {
        closeModal();
        addLog({ svc: 'Zapret (Discord)', m: 'Фейки заменены.', ok: true });
        toast('Фейки заменены');
        restartDiscord();
      }).catch(failToast);
    },
    hosts: function () {
      if (!inTauri) { onlyInApp(); return; }
      openModal('Записи hosts', '<p class="note">Скачиваем записи…</p>', '<button class="btn" data-act="closeModal">Закрыть</button>');
      var removeBtn = S.hosts.installed ? '<button class="btn" data-act="hostsRemove">Удалить записи Бунта</button>' : '';
      T.core.invoke('zapret_hosts_preview').then(function (lines) {
        S.hosts.lines = lines;
        $('#mBody').innerHTML = '<p class="note">Flowseal предлагает прописать в файл hosts адреса, которые помогают голосовому чату Discord и Telegram Web. Ниже всё, что будет добавлено (' + lines.length + ' строк). Записи закрепляют IP-адреса и со временем могут устареть. Бунт добавит их отдельным блоком, который можно удалить, а копию вашего hosts сохранит в папке modules.</p>' +
          '<pre class="hosts-pre mono">' + esc(lines.join('\n')) + '</pre>' +
          (S.hosts.youtube.length ? '<p class="note warn">В вашем hosts уже есть записи про YouTube, они могут мешать: ' + esc(S.hosts.youtube.slice(0, 3).join('; ')) + '</p>' : '');
        $('#mFoot').innerHTML = '<button class="btn primary" data-act="hostsApply">' + (S.hosts.installed ? 'Обновить записи' : 'Добавить в hosts') + '</button>' + removeBtn + '<button class="btn" data-act="closeModal">Отмена</button>';
      }).catch(function (e) {
        $('#mBody').innerHTML = '<p class="note warn">' + esc(String(e)) + '</p>';
        $('#mFoot').innerHTML = removeBtn + '<button class="btn" data-act="closeModal">Закрыть</button>';
      });
    },
    hostsApply: function () {
      T.core.invoke('zapret_hosts_apply', { lines: S.hosts.lines }).then(function (r) {
        S.hosts.installed = r.installed; S.hosts.entries = r.entries; S.hosts.youtube = r.youtube || [];
        closeModal(); addLog({ svc: 'Zapret (Discord)', m: 'Записи добавлены в hosts: ' + r.entries + '.', ok: true });
        toast('Записи добавлены в hosts'); renderDiscord();
      }).catch(failToast);
    },
    hostsRemove: function () {
      T.core.invoke('zapret_hosts_remove').then(function (r) {
        S.hosts.installed = r.installed; S.hosts.entries = r.entries; S.hosts.youtube = r.youtube || [];
        closeModal(); toast('Записи Бунта удалены из hosts'); renderDiscord();
      }).catch(failToast);
    },
    customTargets: function () {
      if (!inTauri) { onlyInApp(); return; }
      openModal('Свои сайты для проверки',
        '<p class="note">Адреса сайтов, по одному на строку, например rutracker.org. Бунт будет открывать их вместе со встроенными, и они войдут в оценку стратегии (например, 7 из 8). Не больше 20.</p><textarea class="field mono ta" id="tgEdit" spellcheck="false" aria-label="Сайты">' + esc((S.discord.custom || []).join('\n')) + '</textarea>',
        '<button class="btn primary" data-act="customSave">Сохранить</button><button class="btn" data-act="closeModal">Отмена</button>');
    },
    customSave: function () {
      var hosts = $('#tgEdit').value.split('\n');
      T.core.invoke('zapret_targets_set', { hosts: hosts }).then(function (r) {
        S.discord.custom = r; closeModal();
        toast('Сохранено. Старые оценки стратегий считались без этих сайтов, запустите проверку заново.');
        renderDiscord();
      }).catch(failToast);
    },
    diag: function () {
      if (!inTauri) { onlyInApp(); return; }
      openModal('Диагностика', '<p class="note">Проверяем систему…</p>', '<button class="btn" data-act="closeModal">Закрыть</button>');
      T.core.invoke('zapret_diagnose').then(function (items) {
        var order = { bad: 0, warn: 1, ok: 2 };
        items.sort(function (a, b) { return order[a.level] - order[b.level]; });
        var bad = items.filter(function (x) { return x.level === 'bad'; }).length, warn = items.filter(function (x) { return x.level === 'warn'; }).length;
        $('#mBody').innerHTML = '<p class="note">' + (bad || warn ? 'Проблем: ' + bad + ', предупреждений: ' + warn + '.' : 'Всё в порядке.') + '</p><div class="diag">' + items.map(function (x) {
          return '<div class="diag-i ' + x.level + '"><span class="dot"></span><div><b>' + esc(x.title) + '</b>' + (x.detail ? '<small>' + esc(x.detail) + '</small>' : '') + '</div>' + (x.fix ? '<button class="btn sm" data-act="diagFix" data-arg="' + x.fix + '">Исправить</button>' : '') + '</div>';
        }).join('') + '</div>';
        $('#mFoot').innerHTML = '<button class="btn" data-act="clearCache" title="Закроет Discord и удалит его кэш">Очистить кэш Discord</button><button class="btn" data-act="closeModal">Закрыть</button>';
      }).catch(function (e) { $('#mBody').innerHTML = '<p class="note warn">' + esc(String(e)) + '</p>'; });
    },
    diagFix: function (id) {
      T.core.invoke('zapret_diag_fix', { id: id }).then(function () { toast('Исправлено'); ACT.diag(); }).catch(failToast);
    },
    clearCache: function () {
      T.core.invoke('zapret_clear_discord_cache').then(function (r) { toast('Кэш очищен: ' + r.join(', ') + '. Discord закрыт, откройте его снова.'); }).catch(failToast);
    },
    svcInstall: function () {
      if (!inTauri) { onlyInApp(); return; }
      var d = S.discord;
      S.svc.busy = true; renderDiscord();
      addLog({ svc: 'Zapret (Discord)', m: 'Устанавливаем службу Windows со стратегией ' + d.strategy + '…' });
      T.core.invoke('zapret_service_install', { strategy: d.strategy, game: d.game, ipset: d.ipset, gameTcp: d.tcpPorts, gameUdp: d.udpPorts }).then(function (r) {
        S.svc.busy = false; S.svc.installed = r.installed; S.svc.running = r.running; S.svc.strategy = r.strategy || ''; S.svc.foreign = r.foreign;
        S.on.discord = r.running;
        addLog({ svc: 'Zapret (Discord)', m: 'Служба установлена и работает.', ok: true });
        toast('Служба установлена. Запрет будет запускаться вместе с Windows.');
        renderAll();
      }).catch(function (e) { S.svc.busy = false; renderDiscord(); failToast(e); refreshDiscordExtras(); });
    },
    svcRemove: function () {
      S.svc.busy = true; renderDiscord();
      T.core.invoke('zapret_service_remove').then(function (r) {
        S.svc.busy = false; S.svc.installed = r.installed; S.svc.running = r.running; S.svc.strategy = ''; S.svc.foreign = r.foreign;
        S.on.discord = false;
        addLog({ svc: 'Zapret (Discord)', m: 'Служба удалена.', ok: true });
        toast('Служба удалена');
        renderAll();
      }).catch(function (e) { S.svc.busy = false; renderDiscord(); failToast(e); });
    },
    stopAll: function () { stopAll(); toast('Все службы остановлены'); },
    restartAll: function () {
      var was = IDS.filter(function (id) { return S.on[id]; });
      if (!was.length) { toast('Нет активных служб', 'warn'); return; }
      stopAll(); toast('Перезапускаем…');
      setTimeout(function () { was.forEach(function (id) { setSvc(id, true, true); }); }, 900);
    },
    toggleAll: toggleAll,
    checkUpdates: checkUpdates,
    autotest: autotest,
    testall: testall,
    testcancel: testcancel,
    probe: probe,
    fSave: function () { fSave(); }, fSaveToken: fSaveToken, fServer: fServer, fPing: function () { fPingAll(false); }, fClearToken: fClearToken, fReset: fReset, fRepair: fRepair, fLog: fLog,
    fAdapter: function (a) { fAdapter(a); }, fTakeOver: function (a) { fTakeOver(a); },
    tgSave: tgSave, tgReset: tgReset, tgSecret: tgSecret,
    tgLan: function () {
      var on = !tgIsLan();
      S.tgc.host = on ? '0.0.0.0' : '127.0.0.1';
      if (!on) stopQr();
      renderAll();
      if (inTauri && installed('telegram')) {
        var payload = tgPayloadOrNull();
        if (!payload) { S.tgc.host = on ? '127.0.0.1' : '0.0.0.0'; renderAll(); return; }
        T.core.invoke('telegram_config_set', { config: payload }).then(function (st) {
          applyTg(st); S.on.telegram = st.running;
          addLog({ svc: SVC.telegram.name, m: on ? 'Доступ из локальной сети включён.' : 'Доступ из локальной сети выключен.' });
          toast(on ? 'Доступ из локальной сети включён' : 'Прокси снова доступен только на этом компьютере');
          refreshTgExtras();
        }).catch(function (err) { S.tgc.host = on ? '127.0.0.1' : '0.0.0.0'; toast(String(err).slice(0, 220), 'warn'); }).then(renderAll);
      }
    },
    tgFw: function () {
      if (S.admin === false) { toast('Нужны права администратора. Нажмите «Дать права» вверху окна.', 'warn'); return; }
      var open = !S.tgp.fw.open;
      $('#tgFwBtn').disabled = true;
      T.core.invoke('telegram_firewall_set', { open: open || S.tgp.fw.stale }).then(function (r) {
        S.tgp.fw = { open: r.open, stale: r.stale, known: true };
        toast(r.open ? 'Порты открыты для вашей сети' : 'Порты закрыты');
      }).catch(function (e) { toast(String(e).slice(0, 220), 'warn'); }).then(renderTgExtras);
    },
    tgQr: function () {
      if (S.tgp.qr.on) { stopQr(); renderTgExtras(); return; }
      if (!S.on.telegram) toast('Прокси сейчас выключен. Включите запрет Telegram, иначе телефону не к чему подключаться.', 'warn');
      T.core.invoke('telegram_share_start').then(function (r) {
        S.tgp.qr = { on: true, svg: r.svg, url: r.url, until: Date.now() + r.expires_secs * 1000 };
        renderTgExtras();
      }).catch(function (e) { toast(String(e).slice(0, 240), 'warn'); });
    },
    tgOpen: function () {
      if (!inTauri) { onlyInApp(); return; }
      if (!S.on.telegram) { toast('Сначала включите запрет Telegram.', 'warn'); return; }
      T.core.invoke('telegram_open_link').catch(function (e) { toast(String(e).slice(0, 200), 'warn'); });
    },
    tgCheck: function () {
      if (!inTauri) { onlyInApp(); return; }
      S.tgp.checking = true; renderTgExtras();
      T.core.invoke('telegram_check').then(function (r) { S.tgp.check = r; }).catch(function (e) { toast(String(e).slice(0, 200), 'warn'); }).then(function () { S.tgp.checking = false; renderTgExtras(); });
    },
    tgRestart: function () {
      if (!inTauri || !installed('telegram')) { onlyInApp(); return; }
      T.core.invoke('telegram_restart').then(function (st) {
        applyTg(st); S.on.telegram = st.running; toast('Прокси перезапущен'); addLog({ svc: SVC.telegram.name, m: 'Прокси перезапущен.', ok: true });
      }).catch(function (e) { toast(String(e).slice(0, 220), 'warn'); }).then(renderAll);
    },
    tgLog: function () {
      if (!inTauri) { onlyInApp(); return; }
      T.core.invoke('telegram_log', { lines: 200 }).then(function (text) {
        openModal('Лог прокси', '<pre class="hosts-pre mono" id="tgLogText" style="max-height:380px">' + esc(text) + '</pre>', '<button class="btn" data-act="tgLog">Обновить</button><button class="btn" data-act="closeModal">Закрыть</button>');
        var pre = $('#tgLogText'); if (pre) pre.scrollTop = pre.scrollHeight;
      }).catch(function (e) { toast(String(e).slice(0, 200), 'warn'); });
    },
    copyTg: function () { copyText($('#tgLink').value, 'Ссылка скопирована'); },
    vImport: vImport, vPing: function () { vPingAll(false); }, vToggle: vToggle, vSubOpen: vSubOpen, vNote: vNote, pOpenAdd: pOpenAdd, pSubmit: pSubmit, pPing: function () { pPingAll(false); }, pPick: pPick, pDel: pDel, pMode: pMode, pRepair: pRepair, pLog: pLog, vRepair: vRepair, vLog: vLog, vQuick: vQuick, vProcs: vProcs, vRuleAdd: vRuleAdd,
    vPick: function (a) { vPick(a); }, vDel: function (a) { vDel(a); }, vDefault: function (a) { vDefault(a); }, vMode: function (a) { vMode(a); },
    vRuleAct: function (a) { vRuleAct(a); }, vRuleDel: function (a) { vRuleDel(a); }, vPickProc: function (a) { vPickProc(a); },
    vSubAdd: vSubAdd, vSubRefresh: function (a) { vSubRefresh(a); }, vSubRemove: function (a) { vSubRemove(a); },
    pickWg: function () { $('#wgFile').click(); },
    dToggle: function () { dToggle(); }, dApply: function (a) { dApply(a); }, dApplyCustom: function () { dApply('custom'); }, dReset: function (a) { dReset(a); }, dPing: dPing, dAd: function (a) { dAd(a); },
    vpnSwitch: function (a) { vpnSwitch(a); },
    wPaste: function () { S.w.paste = !S.w.paste; renderAll(); },
    wImportText: wImportText, wRepair: wRepair, wLog: wLog,
    wPick: function (a) { wPick(a); }, wDel: function (a) { wDelAsk(a); }, wDelDo: function (a) { wDelDo(a); }, wView: function (a) { wView(a); },
    wAdapter: function (a) { wAdapter(a); }, wReplace: function (a) { wReplace(a); },
    updateOne: updateOne,
    installComp: installComp,
    elevate: elevate,
    takeOver: takeOver,
    tgTakeOver: function (a) { tgTakeOver(a); },
    runSec: runSec,
    runSecOnline: runSecOnline,
    reinstallAsk: reinstallAsk,
    reinstallDo: reinstallDo,
    uninstallAsk: uninstallAsk,
    uninstallDo: uninstallDo,
    exitApp: function () { toast('В настоящем приложении здесь закроется Бунт.'); },
    stub: function (a) { toast(a || 'Скоро'); },
    toggleTray: function () {
      var tray = $('#tray'), desk = $('#desk');
      var show = tray.hidden;
      tray.hidden = !show;
      desk.classList.toggle('with-tray', show);
      $('#trayBtn').setAttribute('aria-pressed', String(show));
    }
  };

  document.addEventListener('click', function (e) {
    var el = e.target.closest('[data-go],[data-svc],[data-strat],[data-sw],[data-seg] button,[data-act],[data-url]');
    if (!el) return;
    var d = el.dataset;
    if (d.url) { openUrl(d.url); return; }
    if (d.go) { go(d.go); return; }
    if (d.strat) { pickStrat(d.strat); return; }
    if (d.svc) { setSvc(d.svc, !S.on[d.svc]); return; }
    if (d.sw) {
      set(d.sw, !get(d.sw));
      if (d.sw === 'settings.autostart_admin') {
        if (inTauri && S.admin === false) { S.settings.autostart_admin = !S.settings.autostart_admin; adminNeeded(); sync(); return; }
        if (S.settings.autostart_admin) S.settings.autostart = false;
      }
      if (d.sw === 'settings.autostart' && S.settings.autostart && S.settings.autostart_admin) {
        S.settings.autostart = false; sync();
        toast('Сейчас включён автозапуск с правами администратора, он заменяет обычный. Выключите его, если нужен обычный.', 'warn');
        return;
      }
      if (d.sw === 'tgc.autostart') { tgAutostart(S.tgc.autostart); renderAll(); return; }
      if (d.sw.indexOf('w.config.') === 0) { wSaveConfig(); renderAll(); return; }
      if (d.sw.indexOf('dn.') === 0) { renderAll(); return; }
      if (d.sw === 'v.config.sub_auto') { vSave(); if (S.v.config.sub_auto) vAutoSubs(); return; }
      if (d.sw.indexOf('v.config.') === 0) { vApplyNote(); vSave(); return; }
      if (d.sw.indexOf('p.config.') === 0) { pApplyNote(); pSave(); return; }
      if (d.sw === 'discord.autoupd') toast(S.discord.autoupd ? 'Автопроверка включена' : 'Автопроверка выключена');
      renderDiscord();
      sync();
      if (d.sw.indexOf('settings.') === 0) saveSettings();
      return;
    }
    var seg = el.closest('[data-seg]');
    if (seg && d.v) {
      set(seg.dataset.seg, d.v);
      if (seg.dataset.seg === 'discord.ipset') addLog({ svc: 'Zapret (Discord)', m: 'IPSet Filter: ' + d.v + '.' });
      renderAll();
      if (seg.dataset.seg === 'discord.game') addLog({ svc: 'Zapret (Discord)', m: 'Game Filter: ' + d.v + '.' });
      if (seg.dataset.seg === 'discord.ipset' || seg.dataset.seg === 'discord.game') restartDiscord();
      return;
    }
    if (d.act && ACT[d.act]) ACT[d.act](d.arg);
  });

  document.addEventListener('keydown', function (e) {
    if ((e.key === 'Enter' || e.key === ' ') && e.target.matches && e.target.matches('.srv[role="button"]')) { e.preventDefault(); e.target.click(); }
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && !e.shiftKey && e.target && e.target.id && /^pm(Host|Port|User|Pass|Name)$/.test(e.target.id)) { e.preventDefault(); pSubmit(); }
  });
  document.addEventListener('change', function (e) {
    var el = e.target;
    if (el.dataset && el.dataset.bind) {
      set(el.dataset.bind, el.value); renderAll();
      var bn = el.dataset.bind;
      if (bn === 'discord.tcpPorts' || bn === 'discord.udpPorts') {
        var pv = String(get(bn)).trim();
        if (!validPorts(pv)) { toast('Порты указаны неверно. Пример: 1024-65535 или 3478,50000-50100', 'warn'); set(bn, '1024-65535'); renderAll(); return; }
        set(bn, pv); renderAll();
        restartDiscord();
        return;
      }
      if (bn === 'discord.scanHours') {
        var hh = Number(S.discord.scanHours) || 0;
        S.discord.scanLast = Math.floor(Date.now() / 1000);
        scanSave({ hours: hh, last: S.discord.scanLast });
        toast(hh ? 'Автопроверка стратегий включена' : 'Автопроверка стратегий выключена');
        renderDiscord();
      }
      if (bn.indexOf('v.') === 0 && bn.indexOf('v.rule.') !== 0) { vApplyNote(); vSave(); }
      if (bn.indexOf('p.') === 0 && bn.indexOf('p.form.') !== 0) { pApplyNote(); pSave(); }
    }
  });
  document.addEventListener('input', function (e) {
    var el = e.target;
    if (el && el.id === 'vProcFilter') {
      var q = el.value.trim().toLowerCase();
      $$('#vProcList button').forEach(function (b) { b.hidden = !!q && b.dataset.q.indexOf(q) < 0; });
    }
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeModal();
    var ck = (e.key === 'Enter' || e.key === ' ') && e.target.closest && e.target.closest('.dns-ad');
    if (ck) { e.preventDefault(); dAd(ck.dataset.arg); }
  });
  $('#modal').addEventListener('click', function (e) { if (e.target === this) closeModal(); });
  $('#vlessIn').addEventListener('keydown', function (e) { if (e.key === 'Enter') vImport(); });
  $('#vRuleVal').addEventListener('keydown', function (e) { if (e.key === 'Enter') { S.v.rule.value = e.target.value; vRuleAdd(); } });
  $('#wgFile').addEventListener('change', function (e) {
    wImportFiles(e.target.files);
    e.target.value = '';
  });
  /* перетаскивание .conf на область импорта; файл, брошенный мимо, не должен открываться в окне */
  (function () {
    var zone = $('#wDrop'), depth = 0;
    var hasFiles = function (e) { var t = e.dataTransfer && e.dataTransfer.types; return !!t && Array.prototype.indexOf.call(t, 'Files') >= 0; };
    document.addEventListener('dragover', function (e) { if (hasFiles(e)) e.preventDefault(); });
    document.addEventListener('drop', function (e) { if (hasFiles(e)) e.preventDefault(); });
    if (!zone) return;
    zone.addEventListener('dragenter', function (e) { if (!hasFiles(e)) return; e.preventDefault(); depth++; zone.classList.add('over'); });
    zone.addEventListener('dragover', function (e) { if (!hasFiles(e)) return; e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
    zone.addEventListener('dragleave', function () { depth = Math.max(0, depth - 1); if (!depth) zone.classList.remove('over'); });
    zone.addEventListener('drop', function (e) {
      if (!hasFiles(e)) return;
      e.preventDefault(); depth = 0; zone.classList.remove('over');
      wImportFiles(e.dataTransfer.files);
    });
    zone.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('#wgFile').click(); } });
  })();

  /* старт */
  S.comps.forEach(function (c) { if (c.id !== 'app') c.demo = true; });
  /* в настоящем приложении до первой проверки не пишем «Актуально» */
  if (inTauri) { S.sec.items = []; S.sec.last = 'ещё не запускалась'; startPending = true; S.comps.forEach(function (c) { c.checked = false; }); }
  if (appMode) { S.uptime = 0; S.lastCheck = 'ещё не проверяли'; }
  renderAll();
  var h = (location.hash || '').replace(/^#/, '');
  go(PAGES.indexOf(h) >= 0 ? h : 'home');

  if (inTauri) {
    T.core.invoke('app_info').then(function (i) { setAppVersion(i.version); renderAll(); });
    Object.keys(REAL).forEach(function (id) { comp(id).latest = null; comp(id).demo = false; comp(id).sha = '–'; });
    var adminReady = T.core.invoke('is_admin').then(function (ok) { S.admin = ok; renderAll(); }).catch(function () {});
    T.core.invoke('modules_dir').then(function (p) {
      $$('[data-modpath]').forEach(function (el) { el.hidden = false; el.textContent = 'Папка установки: ' + p; });
    });
    T.core.invoke('installed_components').then(function (m) {
      Object.keys(m).forEach(function (id) { if (comp(id)) comp(id).cur = m[id]; });
      renderAll();
      Object.keys(REAL).forEach(function (id) { refreshLatest(id).then(renderAll); });
      loadNotes();
      if (comp('fptn').cur) {
        T.core.invoke('fptn_status').then(function (st) {
          applyF(st);
          renderAll();
          if (!st.running && !st.dirty && st.servers && st.servers.length) fAutoPing();
          if (st.dirty) adminReady.then(function () { if (S.admin !== false) watchFptn(); });
          else if (st.running) addLog({ svc: 'FPTN', m: 'FPTN уже работал. Бунт подхватил его.', ok: true });
          else if ((st.enabled || (st.config && st.config.autostart)) && st.token_set) adminReady.then(function () { realFptn(true, true); });
          else adminReady.then(function () { if (S.admin !== false) T.core.invoke('fptn_foreign').then(function (x) { if (x.procs.length) askFptnTakeOver(x); }).catch(function () {}); });
        }).catch(function () {});
        setInterval(watchFptn, 15000);
      }
      loadDn();
      setTimeout(secAuto, 12000);
      setInterval(secAuto, 6 * 3600 * 1000);
      setInterval(function () { if (S.page === 'dns' && !S.dn.busy) loadDn(); }, 10000);
      if (comp('vless').cur) {
        T.core.invoke('vless_status').then(function (st) {
          applyV(st);
          renderAll();
          if (st.dirty) adminReady.then(function () { watchVless(); });
          else if (st.running) addLog({ svc: SVC.vless.name, m: 'VLESS уже работал. Бунт подхватил его.', ok: true });
          else if (st.config && st.config.autoconnect && st.config.active) adminReady.then(function () { realVless(true, true); });
          if (!st.running && !st.dirty && st.profiles && st.profiles.length) vAutoPing();
          setTimeout(vAutoSubs, 4000);
        }).catch(function () {});
        setInterval(vAutoSubs, 30 * 60 * 1000);
        var vTick = 0;
        setInterval(function () { vTick++; if (S.page === 'vless' || S.on.vless || vTick % 3 === 0) watchVless(); }, 5000);
      }
      if (comp('proxy').cur) {
        T.core.invoke('proxy_status').then(function (st) {
          applyP(st);
          renderAll();
          if (st.dirty) adminReady.then(function () { watchProxy(); });
          else if (st.running) addLog({ svc: SVC.proxy.name, m: 'Proxy уже работал. Бунт подхватил его.', ok: true });
          else if (st.config && st.config.autoconnect && st.config.active) adminReady.then(function () { realProxy(true, true); });
          if (!st.running && !st.dirty && st.profiles && st.profiles.length) pAutoPing();
        }).catch(function () {});
        var pTick = 0;
        setInterval(function () { pTick++; if (S.page === 'proxy' || S.on.proxy || pTick % 3 === 0) watchProxy(); }, 5000);
      }
      if (comp('wg').cur) {
        T.core.invoke('wg_status').then(function (st) {
          applyW(st);
          renderAll();
          if (st.dirty) adminReady.then(function () { if (S.admin !== false) watchWg(); });
          else if (st.running) addLog({ svc: SVC.wg.name, m: 'Туннель уже работал. Бунт подхватил его.', ok: true });
          else if (st.config && st.config.autoconnect && st.config.active) adminReady.then(function () { realWg(true, true); });
        }).catch(function () {});
        var wTick = 0;
        setInterval(function () { wTick++; if (S.page === 'wg' || S.on.wg || wTick % 3 === 0) watchWg(); }, 5000);
      }
      if (comp('telegram').cur) {
        T.core.invoke('telegram_status').then(function (st) {
          applyTg(st);
          refreshTgExtras();
          if (st.running) { S.on.telegram = true; renderAll(); }
          else if (st.enabled || (st.config && st.config.autostart)) realTelegram(true, true);
          else { renderAll(); checkTgForeign(); }
        }).catch(function () {});
      }
      if (!comp('discord').cur) return;
      /* запрет мог остаться включённым (обновление Бунта) или быть включён пользователем до выхода */
      refreshDiscordExtras();
      T.core.invoke('zapret_status').then(function (st) {
        var d = S.discord;
        if (st.strategy && STRATS.indexOf(st.strategy) >= 0) { d.strategy = st.strategy; d.mode = 'manual'; }
        if (st.game) d.game = st.game;
        if (st.game_tcp) d.tcpPorts = st.game_tcp;
        if (st.game_udp) d.udpPorts = st.game_udp;
        if (st.ipset) d.ipset = st.ipset;
        if (st.running) {
          S.on.discord = true;
          addLog({ svc: 'Zapret (Discord)', m: 'Запрет уже работал. Бунт подхватил его.', ok: true });
          renderAll();
        } else if (st.enabled) {
          adminReady.then(function () { realDiscord(true, true); });   /* поднимаем запрет, который был включён */
        } else {
          adminReady.then(function () { if (S.admin !== false) checkForeign(); });   /* работает не из Бунта: предложить перейти */
        }
      }).catch(function () {});
    }).catch(function () { renderAll(); });
    T.event.listen('zapret-test', function (e) { onTestEvent(e.payload || {}); });
    T.core.invoke('zapret_results').then(function (r) { applyResults(r); renderDiscord(); }).catch(function () {});
    T.core.invoke('zapret_scan_get').then(function (c) { if (c) { S.discord.scanHours = String(c.hours || 0); S.discord.scanLast = c.last || 0; renderDiscord(); sync(); } }).catch(function () {});
    T.event.listen('module-progress', function (e) {
      var p = e.payload || {}, c = comp(p.id);
      if (c && c.busy != null && p.total) { c.busy = Math.min(99, Math.round(p.downloaded / p.total * 100)); if (p.stage) c.stage = p.stage; renderAll(); }
    });
    T.event.listen('update-progress', function (e) {
      var c = comp('app'), p = e.payload || {};
      if (c && c.busy != null && p.total) {
        c.busy = Math.min(99, Math.round(p.downloaded / p.total * 100));
        renderVersions();
      }
    });
    T.event.listen('update-installing', function () { toast('Устанавливаем обновление. Бунт перезапустится.'); });
    T.event.listen('navigate', function (e) { go(String(e.payload)); });
    T.core.invoke('settings_get').then(function (s) { S.settings = s; }).catch(function () {}).then(function () {
      startPending = false;
      sync();
      renderAutostart();
      if (S.settings.autoupdate) checkUpdates(true); else renderAll();
    });
  }

  function fmtUp(s) { return Math.floor(s / 86400) + ' д. ' + Math.floor(s % 86400 / 3600) + ' ч. ' + Math.floor(s % 3600 / 60) + ' мин.'; }
  function tick() {
    S.uptime++;
    $('#uptime').textContent = fmtUp(S.uptime);
    var d = new Date();
    $('#trayClock').textContent = d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }) + ' ' + d.toLocaleDateString('ru-RU');
  }
  tick();
  setInterval(tick, 1000);
})();
