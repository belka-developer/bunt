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
  var PAGES = ['home', 'discord', 'telegram', 'vless', 'wg', 'dns', 'fptn', 'security', 'updates', 'settings'];
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
    on: { discord: false, telegram: false, fptn: false, vless: false, wg: false },
    discord: { mode: 'auto', strategy: 'general (ALT2)', game: false, ipset: 'none', results: {}, free: null, scanHours: '0', scanLast: 0, autoupd: true, ipsetUpdated: 'сегодня, 09:12' },
    telegram: { port: '1443', link: '' },
    fc: { token_in: '', bypass_method: 'sni-spoofing-yandex-26-4', strategy: 'rolling-tunnel', sni: 'google.com', mtu: '1420', preferred_server: '', tun_name: 'FPTN', tun_ip: '10.0.0.1', exclude_networks: '10.0.0.0/8,192.168.0.0/16', include_networks: '', split: false, split_mode: 'exclude', split_domains: '', adblock: true, blacklist: '', auto_gateway: true, remove_adapter: true, autostart: false },
    fptn: { tokenSet: false, hint: '', servers: [], tokenError: '', adapter: { exists: false, status: '', description: '' }, dirty: false, busy: false, repairMsg: '', logOpen: false, log: '' },
    v: { profiles: [], config: { active: '', mode: 'tun', socks_port: 10808, http_port: 10809, default_action: 'proxy', bypass_lan: true, dns: ['1.1.1.1', '8.8.8.8'], rules: [], subs: [], autoconnect: false, keep_on_exit: false }, running: false, tun: false, dirty: false, adapter: false, busy: false, ping: {}, pinging: false, repairMsg: '', logOpen: false, log: '', view: '', viewName: '', rule: { kind: 'app', value: '', action: 'proxy' }, socks: '10808', http: '10809', dns_text: '1.1.1.1, 8.8.8.8', loaded: false },
    dn: { presets: [], adapters: [], active: '', has_snapshot: false, config: { last: '', custom: ['', ''], ipv6: true, doh: false }, vpn: false, doh_supported: false, busy: false, loaded: false, off: [], ping: {}, pinging: false, c1: '', c2: '', msg: '' },
    w: { profiles: [], config: { active: '', autoconnect: false, keep_on_exit: false, split_default: true }, running: false, tunnel: '', dirty: false, adapter: { exists: false, status: '', description: '' }, stats: { handshake_ago: null, rx: 0, tx: 0 }, busy: false, repairMsg: '', logOpen: false, log: '', paste: false, imp_name: 'wg0', imp_text: '', view: '', viewName: '' },
    tgc: { autostart: false, host: '127.0.0.1', port: '1443', secret: '', dc_ip: '2:149.154.167.220\n4:149.154.167.220', verbose: false, buf_kb: '256', pool_size: '4', log_max_mb: '5', cfproxy: true, h2: true, cf_domain_on: false, cf_domain: '', cf_worker_on: false, cf_worker: '', force_test_dc: false, no_secure: false, fake_tls_domain: '' },
    lists: {
      general: { file: 'list-general-user.txt', title: 'Свои домены', hint: 'Домены для обхода, по одному на строку. Поддомены учитываются автоматически.', text: '# по одному домену на строку\nexample.org\ncdn.example.org\n' },
      exclude: { file: 'list-exclude-user.txt', title: 'Исключения доменов', hint: 'Домены, которые не нужно обрабатывать, даже если их IP есть в ipset-all.txt.', text: '' },
      ipset: { file: 'ipset-all.txt', title: 'Свои IP и подсети', hint: 'IP-адреса и подсети для обхода, по одному на строку.', text: '# IP и подсети\n203.0.113.0/24\n' },
      ipsetEx: { file: 'ipset-exclude-user.txt', title: 'Исключения IP', hint: 'IP-адреса и подсети, которые не нужно обрабатывать.', text: '' }
    },
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
      { id: 'wg', name: 'WireGuard / AmneziaWG', cur: null, latest: '3.1.0', next: null, cls: 'b-wg', icon: 'vpn', size: '3.5 МБ', src: 'amnezia-vpn/amneziawg-windows-client (GitHub)', sha: '–', notes: [], busy: null }
    ],
    lastCheck: 'сегодня, 14:45',
    sec: { running: false, last: nowShort(), items: [
      { t: 'Проверка хешей файлов', st: 'ok' },
      { t: 'Проверка цифровой подписи', st: 'ok' },
      { t: 'Проверка целостности архива', st: 'ok' },
      { t: 'Сравнение с эталонной версией', st: 'ok' }
    ] },
    settings: { autostart: true, tray: true, notify: true, autoupdate: true }
  };

  var get = function (p) { return p.split('.').reduce(function (o, k) { return o[k]; }, S); };
  var set = function (p, v) { var a = p.split('.'); var k = a.pop(); a.reduce(function (o, x) { return o[x]; }, S)[k] = v; };

  /* уведомления */
  function toast(msg, kind) {
    var el = document.createElement('div');
    el.className = 'toast' + (kind ? ' ' + kind : '');
    el.textContent = msg;
    $('#toasts').appendChild(el);
    setTimeout(function () { el.remove(); }, 3400);
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
    ['discord', 'telegram', 'fptn', 'wg', 'vless'].forEach(function (id) {
      var c = comp(id), ok = installed(id), box = $('#inst-' + id), body = document.querySelector('[data-body="' + id + '"]');
      if (!box || !body) return;
      box.hidden = ok; body.hidden = !ok;
      var sw = document.querySelector('.head-sw [data-svc="' + id + '"]');
      if (sw) sw.parentNode.hidden = !ok;
      document.querySelector('[data-latest="' + id + '"]').textContent = c.latest || '…';
      $('#instAct-' + id).innerHTML = c.busy != null
        ? '<span class="bar-track"><span class="bar-fill" style="width:' + c.busy + '%"></span></span><div class="note mt-s">' + (id === 'telegram' || id === 'fptn' || id === 'wg' || id === 'vless' ? esc(c.stage || 'Готовим установку') + '… ' + c.busy + '%. Это займёт около минуты.' : 'Скачиваем и проверяем файлы… ' + c.busy + '%') + '</div>'
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

  function renderDiscord() {
    var d = S.discord;
    $('#stratNow').textContent = d.strategy;
    var cr = d.results[d.strategy];
    $('#stratWhen').textContent = (d.mode === 'auto' ? 'Подобрана автоматически' : 'Выбрана вручную') + ' · ' +
      (cr && !cr.error ? 'проверена ' + fmtAt(cr.at) + ': открывается ' + okCount(cr) + ' из ' + TARGETS.length : cr ? 'не запустилась при проверке' : 'ещё не проверялась');
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
    $('#dVer').textContent = comp('discord').cur || '–';
    $('#lists').innerHTML = Object.keys(S.lists).map(function (k) {
      var l = S.lists[k];
      var n = l.text.split('\n').map(function (x) { return x.trim(); }).filter(function (x) { return x && x.charAt(0) !== '#'; }).length;
      return '<div class="row"><div class="lbl">' + l.title + '<small class="mono">' + l.file + '</small></div><div class="inl"><span class="tag">записей: ' + n + '</span><button class="btn sm" data-act="editList" data-arg="' + k + '">Редактировать</button></div></div>';
    }).join('');
    $('#strats').innerHTML = STRAT_DEFS.map(function (s) {
      var r = d.results[s.f], cur = d.strategy === s.f;
      var cls = (cur ? 'cur ' : '') + (scanning === s.f ? 'scan ' : '') + (flash === s.f ? 'win' : '');
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
      $('#targets').innerHTML = TARGETS.map(function (t) {
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
    return TARGETS.map(function (t, k) { var ok = k < n; return { id: t.id, label: t.label, host: t.host, ok: ok, ms: ok ? 60 + ((h >> k) % 90) : null }; });
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
  function vpnRunning() { return VPNS.filter(function (id) { return S.on[id]; }).length > 0; }

  function renderTelegram() {
    var p = String(S.tgc.port).replace(/\D/g, '') || '1443';
    $('#tgLink').value = S.telegram.link || (inTauri ? '' : 'tg://proxy?server=127.0.0.1&port=' + p + '&secret=dd00000000000000000000000000000000');
    var tv = $('#tVer'); if (tv) tv.textContent = comp('telegram').cur || '–';
  }

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
    ['app', 'discord', 'telegram', 'fptn', 'wg', 'vless'].forEach(function (id) {
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
    var el = $('#autoInfo');
    if (!el) return;
    if (!inTauri) { el.textContent = ''; return; }
    var base = 'Бунт стартует вместе с Windows в трее и без прав администратора, а в окне предложит их дать. ';
    el.textContent = base;
    T.core.invoke('autostart_exists').then(function (ok) {
      el.textContent = base + (ok ? 'Запись в автозагрузке создана.' : 'Запись в автозагрузке не создана.');
    }).catch(function () {});
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
    $('#secText').textContent = run ? 'Сверяем хеши и подписи компонентов.' : !done ? 'Нажмите «Запустить проверку».' : bad ? 'Файлы отличаются от тех, что были при установке. Переустановите компонент.' : warn ? 'Подробности в списке ниже.' : 'Файлы совпадают с записанными при установке.';
    $('#secLast').textContent = S.sec.last;
    $('#btnSec').disabled = run;
    var bo = $('#btnSecOnline'); if (bo) bo.disabled = run;
    var fix = $('#secFix');
    if (fix) fix.innerHTML = (bad && !run && inTauri) ? ['discord', 'telegram', 'fptn', 'wg', 'vless'].filter(installed).map(function (id) {
      return '<div class="sec-fix"><span>Файлы компонента «' + esc(comp(id).name) + '» отличаются от оригинала. Лучше всего переустановить его.</span><button class="btn sm primary" data-act="reinstallAsk" data-arg="' + id + '">Переустановить</button></div>';
    }).join('') : '';
    var RES = { ok: 'OK', warn: 'Внимание', bad: 'Нарушено', info: 'Заметка', run: 'Проверяю…', idle: 'Ожидает' };
    var ICO = { ok: 'check', warn: 'alert', bad: 'alert', info: 'shield', idle: 'clock' };
    $('#secList').innerHTML = items.map(function (i) {
      var lead = i.st === 'run' ? '<span class="spin"></span>' : ico(ICO[i.st] || 'check');
      return '<div class="sec-item ' + i.st + '">' + lead + '<span>' + esc(i.t) + (i.note ? '<small>' + esc(i.note) + '</small>' : '') + '</span><span class="res">' + (RES[i.st] || '') + '</span></div>';
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
    renderInstall(); renderDiscord(); renderTelegram(); renderFptn(); renderWg(); renderDn(); renderVless();
    renderVersions(); renderNotes(); renderSecurity(); renderAdmin(); sync(); syncTray();
  }

  function go(page) {
    if (PAGES.indexOf(page) < 0) page = 'home';
    S.page = page;
    if (page === 'dns') loadDn();
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
         T.core.invoke('zapret_start', { strategy: d.strategy, game: d.game ? 'all' : 'disabled', ipset: d.ipset }))
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
  var TGN = ['port', 'buf_kb', 'pool_size', 'log_max_mb'];
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
  function tgSave() {
    if (!inTauri || !installed('telegram')) return;
    var o = tgPayload();
    if (typeof o === 'string') { toast('Проверьте числовые поля: ' + o, 'warn'); return; }
    T.core.invoke('telegram_config_set', { config: o }).then(function (st) {
      applyTg(st);
      S.on.telegram = st.running;
      addLog({ svc: SVC.telegram.name, m: 'Настройки применены' + (st.running ? ', прокси перезапущен. Если менялись порт или секрет, добавьте новую ссылку в Telegram.' : '.') });
      toast('Настройки применены');
    }).catch(function (err) { toast(String(err).slice(0, 220), 'warn'); S.on.telegram = false; }).then(renderAll);
  }
  function tgAutostart(on) {
    if (!inTauri || !installed('telegram')) { S.tgc.autostart = false; toast('Сначала установите компонент.', 'warn'); renderAll(); return; }
    T.core.invoke('telegram_set_autostart', { on: on }).then(function () {
      if (on && S.settings && !S.settings.autostart) {
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
    T.core.invoke(on ? 'telegram_start' : 'telegram_stop').then(function (st) {
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
    fSave(t).then(function () { if (S.fptn.tokenSet) { S.fc.token_in = ''; if (S.fptn.tokenError) toast('Токен сохранён, но не разобран: ' + S.fptn.tokenError, 'warn'); else toast('Токен сохранён, серверов: ' + S.fptn.servers.length); renderAll(); } });
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
    var sl = $('#fServers');
    if (sl) {
      var picked = (S.fc.preferred_server || '').split(',').map(function (x) { return x.trim().toLowerCase(); }).filter(Boolean);
      if (!f.servers.length) {
        sl.innerHTML = '<span class="note">' + (f.tokenError ? 'Токен не удалось разобрать: ' + esc(f.tokenError) : 'Добавьте токен, и здесь появится список серверов.') + '</span>';
      } else {
        sl.innerHTML = '<button class="btn sm' + (picked.length ? '' : ' primary') + '" data-act="fServer" data-arg="">Автовыбор</button>' + f.servers.map(function (s) {
          var on = picked.indexOf(s.name.toLowerCase()) >= 0;
          return '<button class="btn sm' + (on ? ' primary' : '') + '" data-act="fServer" data-arg="' + esc(s.name) + '" title="' + esc(s.host + ':' + s.port) + '">' + esc(s.name) + '</button>';
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
    if (v.view && !v.profiles.some(function (p) { return p.id === v.viewName; })) v.view = '';
    v.loaded = true;
  }
  function vErr(err) { toast(String(err).slice(0, 240), 'warn'); }
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
      var host = ''; try { host = new URL(t).hostname; } catch (e) { host = ''; }
      p = T.core.invoke('vless_sub_add', { name: host || 'Подписка', url: t });
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
  function vView(id) {
    var v = S.v;
    if (v.view && v.viewName === id) { v.view = ''; renderAll(); return; }
    T.core.invoke('vless_profile_view', { id: id }).then(function (t) { v.view = t; v.viewName = id; renderAll(); }).catch(vErr);
  }
  function vPing() {
    var v = S.v;
    if (!inTauri || v.pinging) return;
    v.pinging = true; renderAll();
    T.core.invoke('vless_ping').then(function (r) { v.ping = {}; r.forEach(function (x) { v.ping[x.id] = x.ms; }); }).catch(vErr).then(function () { v.pinging = false; renderAll(); });
  }
  function vSubRefresh(id) {
    if (!inTauri || S.v.busy) return;
    S.v.busy = true; renderAll();
    T.core.invoke('vless_sub_refresh', { id: id }).then(vDone).catch(vErr).then(function () { S.v.busy = false; renderAll(); });
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
      if (!quiet || on) toast(String(err).slice(0, 240), 'warn');
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
  function renderVless() {
    var v = S.v, c = comp('vless'), cfg = v.config;
    var set = function (id, t) { var e = $(id); if (e) e.textContent = t; };
    set('#vVer', c.cur || '–');
    var host = $('#list-vless');
    if (host) {
      if (!v.profiles.length) host.innerHTML = '<div class="empty"><span>Серверов пока нет. Вставьте ссылку vless:// или адрес подписки ниже.</span></div>';
      else host.innerHTML = v.profiles.map(function (p) {
        var sel = cfg.active === p.id, live = v.running && sel, ms = v.ping[p.id];
        var sub = p.ok ? p.address + ':' + p.port + ' · ' + p.network + (p.security !== 'none' ? ' · ' + p.security : '') : (p.error || 'Ссылка повреждена');
        var pg = !(p.id in v.ping) ? '' : ms == null ? '<span class="tag bad">нет ответа</span>' : '<span class="tag ' + (ms < 150 ? 'ok' : 'warn') + '">' + ms + ' мс</span>';
        return '<div class="prof ' + (sel ? 'sel' : '') + '"><button class="pick" data-act="vPick" data-arg="' + esc(p.id) + '" aria-pressed="' + sel + '"><span class="radio"></span><span class="pn"><b>' + esc(p.name) + '</b><small>' + esc(sub) + '</small></span></button>' +
          (live ? '<span class="tag ok">включён</span>' : pg) +
          '<button class="btn sm ghost" data-act="vView" data-arg="' + esc(p.id) + '"' + (p.ok ? '' : ' disabled') + '>Описание</button>' +
          '<button class="btn sm ghost" data-act="vDel" data-arg="' + esc(p.id) + '" aria-label="Удалить ' + esc(p.name) + '"' + (live ? ' disabled' : '') + '>' + ico('x') + '</button></div>';
      }).join('');
    }
    var vw = $('#vView'); if (vw) { vw.hidden = !v.view; vw.textContent = v.view || ''; }
    var sb = $('#vSubs');
    if (sb) sb.innerHTML = !cfg.subs.length ? '<div class="empty"><span>Подписок нет. Вставьте адрес подписки в поле выше.</span></div>' : cfg.subs.map(function (s) {
      var d = s.updated ? new Date(s.updated * 1000).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '–';
      return '<div class="prof"><span class="pn" style="flex:1;min-width:0"><b>' + esc(s.name) + '</b><small>Серверов: ' + s.count + ' · обновлена ' + esc(d) + '</small></span>' +
        '<button class="btn sm" data-act="vSubRefresh" data-arg="' + esc(s.id) + '"' + (v.busy ? ' disabled' : '') + '>Обновить</button>' +
        '<button class="btn sm ghost" data-act="vSubRemove" data-arg="' + esc(s.id) + '" aria-label="Удалить подписку ' + esc(s.name) + '">' + ico('x') + '</button></div>';
    }).join('');
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
    var pb = $('#vPingBtn'); if (pb) pb.disabled = v.pinging || !v.profiles.length;
    var sw = document.querySelector('.head-sw [data-svc="vless"]'); if (sw) sw.disabled = v.busy;
    var stt = document.querySelector('[data-state="vless"]');
    if (stt && v.busy) { stt.className = 'state'; stt.innerHTML = '<span class="spin"></span>Подождите…'; }
  }
  function restartDiscord() {
    if (!inTauri || !S.on.discord) return;
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
      run = T.core.invoke('zapret_test', { strategies: names, game: d.game ? 'all' : 'disabled', ipset: d.ipset, stopOnFull: !all });
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
      var total = TARGETS.length;
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
  var REAL = { discord: true, telegram: true, fptn: true, wg: true, vless: true };
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
      '<p>Файлы будут скачаны с GitHub заново (последняя версия) и заменят установленные. Если запрет был включён, он перезапустится.</p><p class="note">' + (id === 'telegram' ? 'Порт и ссылка для Telegram останутся прежними.' : id === 'fptn' ? 'Токен и настройки FPTN сохранятся. Если VPN был включён, он подключится заново.' : id === 'wg' ? 'Профили и ключи сохранятся. Если туннель был включён, Бунт отключит его на время установки и подключит заново.' : id === 'vless' ? 'Серверы, подписки и правила сохранятся. Если VLESS был включён, Бунт отключит его на время установки и подключит заново.' : 'Ваши списки доменов и IP сохранятся.') + '</p>',
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
      if (was) { if (id === 'telegram') realTelegram(true, true); else if (id === 'fptn') realFptn(true, true); else if (id === 'wg') realWg(true, true); else if (id === 'vless') realVless(true, true); else realDiscord(true, true); }
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
      '<p>Запрет будет остановлен, а все файлы компонента удалены из папки <span class="mono">modules</span>' + (id === 'telegram' ? ', в том числе настройки прокси (порт и секрет). Ссылку в Telegram придётся добавить заново.' : id === 'fptn' ? ', в том числе токен и настройки FPTN. Перед удалением Бунт отключит VPN и вернёт сеть в исходное состояние. Токен придётся ввести заново.' : id === 'wg' ? ', в том числе все профили с ключами. Перед удалением Бунт отключит туннель и вернёт сеть в исходное состояние. Сохраните свои .conf: профили придётся импортировать заново.' : id === 'vless' ? ', в том числе все серверы, подписки и правила. Перед удалением Бунт отключит VLESS, вернёт системный прокси и сеть в исходное состояние. Ссылки придётся добавить заново.' : ', в том числе ваши списки доменов и IP.') + '</p><p class="note">Потом его можно установить заново кнопкой «Установить».</p>',
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
      S.sec.items = list.map(function (r) { return { t: r.title, st: r.state, note: r.note }; });
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
  function runSec() {
    if (S.sec.running) return;
    if (inTauri) {
      S.sec.running = true;
      S.sec.items = [{ t: 'Проверка файлов и подписей', st: 'run' }];
      renderSecurity();
      T.core.invoke('integrity_check').then(function (list) {
        S.sec.items = list.map(function (r) { return { t: r.title, st: r.state, note: r.note }; });
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
      var l = S.lists[k];
      openModal(l.file,
        '<p class="note">' + esc(l.hint) + '</p><textarea class="field mono ta" id="listEdit" spellcheck="false" aria-label="' + esc(l.file) + '">' + esc(l.text) + '</textarea>',
        '<button class="btn primary" data-act="saveList" data-arg="' + k + '">Сохранить</button><button class="btn" data-act="closeModal">Отмена</button>');
    },
    saveList: function (k) {
      S.lists[k].text = $('#listEdit').value;
      closeModal();
      addLog({ svc: 'Zapret (Discord)', m: 'Сохранён ' + S.lists[k].file + '.' });
      toast('Список сохранён. Перезапустите стратегию, чтобы он применился.');
      renderAll();
    },
    closeModal: closeModal,
    updIpset: function () {
      S.discord.ipsetUpdated = 'только что, ' + hms().slice(0, 5);
      addLog({ svc: 'Zapret (Discord)', m: 'Список ipset-all.txt обновлён из репозитория.', ok: true });
      toast('Список ipset-all.txt обновлён');
      renderDiscord();
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
    fSave: function () { fSave(); }, fSaveToken: fSaveToken, fServer: fServer, fClearToken: fClearToken, fReset: fReset, fRepair: fRepair, fLog: fLog,
    fAdapter: function (a) { fAdapter(a); }, fTakeOver: function (a) { fTakeOver(a); },
    tgSave: tgSave, tgReset: tgReset, tgSecret: tgSecret,
    copyTg: function () { copyText($('#tgLink').value, 'Ссылка скопирована'); },
    vImport: vImport, vPing: vPing, vRepair: vRepair, vLog: vLog, vQuick: vQuick, vProcs: vProcs, vRuleAdd: vRuleAdd,
    vPick: function (a) { vPick(a); }, vView: function (a) { vView(a); }, vDel: function (a) { vDel(a); }, vDefault: function (a) { vDefault(a); }, vMode: function (a) { vMode(a); },
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
      if (d.sw === 'discord.game') addLog({ svc: 'Zapret (Discord)', m: 'Game Filter: ' + (S.discord.game ? 'включён' : 'выключен') + '. Нужен перезапуск стратегии.' });
      if (d.sw === 'tgc.autostart') { tgAutostart(S.tgc.autostart); renderAll(); return; }
      if (d.sw.indexOf('w.config.') === 0) { wSaveConfig(); renderAll(); return; }
      if (d.sw.indexOf('dn.') === 0) { renderAll(); return; }
      if (d.sw.indexOf('v.config.') === 0) { vApplyNote(); vSave(); return; }
      if (d.sw === 'discord.autoupd') toast(S.discord.autoupd ? 'Автопроверка включена' : 'Автопроверка выключена');
      renderDiscord();
      sync();
      if (d.sw.indexOf('settings.') === 0) saveSettings();
      if (d.sw === 'discord.game') restartDiscord();
      return;
    }
    var seg = el.closest('[data-seg]');
    if (seg && d.v) {
      set(seg.dataset.seg, d.v);
      if (seg.dataset.seg === 'discord.ipset') addLog({ svc: 'Zapret (Discord)', m: 'IPSet Filter: ' + d.v + '.' });
      renderAll();
      if (seg.dataset.seg === 'discord.ipset') restartDiscord();
      return;
    }
    if (d.act && ACT[d.act]) ACT[d.act](d.arg);
  });

  document.addEventListener('change', function (e) {
    var el = e.target;
    if (el.dataset && el.dataset.bind) {
      set(el.dataset.bind, el.value); renderAll();
      var bn = el.dataset.bind;
      if (bn === 'discord.scanHours') {
        var hh = Number(S.discord.scanHours) || 0;
        S.discord.scanLast = Math.floor(Date.now() / 1000);
        scanSave({ hours: hh, last: S.discord.scanLast });
        toast(hh ? 'Автопроверка стратегий включена' : 'Автопроверка стратегий выключена');
        renderDiscord();
      }
      if (bn.indexOf('v.') === 0 && bn.indexOf('v.rule.') !== 0) { vApplyNote(); vSave(); }
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
          if (st.dirty) adminReady.then(function () { if (S.admin !== false) watchFptn(); });
          else if (st.running) addLog({ svc: 'FPTN', m: 'FPTN уже работал. Бунт подхватил его.', ok: true });
          else if ((st.enabled || (st.config && st.config.autostart)) && st.token_set) adminReady.then(function () { realFptn(true, true); });
          else adminReady.then(function () { if (S.admin !== false) T.core.invoke('fptn_foreign').then(function (x) { if (x.procs.length) askFptnTakeOver(x); }).catch(function () {}); });
        }).catch(function () {});
        setInterval(watchFptn, 15000);
      }
      loadDn();
      setInterval(function () { if (S.page === 'dns' && !S.dn.busy) loadDn(); }, 10000);
      if (comp('vless').cur) {
        T.core.invoke('vless_status').then(function (st) {
          applyV(st);
          renderAll();
          if (st.dirty) adminReady.then(function () { watchVless(); });
          else if (st.running) addLog({ svc: SVC.vless.name, m: 'VLESS уже работал. Бунт подхватил его.', ok: true });
          else if (st.config && st.config.autoconnect && st.config.active) adminReady.then(function () { realVless(true, true); });
        }).catch(function () {});
        var vTick = 0;
        setInterval(function () { vTick++; if (S.page === 'vless' || S.on.vless || vTick % 3 === 0) watchVless(); }, 5000);
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
          if (st.running) { S.on.telegram = true; renderAll(); }
          else if (st.enabled || (st.config && st.config.autostart)) realTelegram(true, true);
          else { renderAll(); checkTgForeign(); }
        }).catch(function () {});
      }
      if (!comp('discord').cur) return;
      /* запрет мог остаться включённым (обновление Бунта) или быть включён пользователем до выхода */
      T.core.invoke('zapret_status').then(function (st) {
        var d = S.discord;
        if (st.strategy && STRATS.indexOf(st.strategy) >= 0) { d.strategy = st.strategy; d.mode = 'manual'; }
        if (st.game) d.game = st.game !== 'disabled';
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
