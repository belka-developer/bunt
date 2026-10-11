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
    vless: { name: 'VLESS', icon: 'net', cls: 'b-vless' },
    wg: { name: 'WireGuard', icon: 'vpn', cls: 'b-wg' }
  };
  var IDS = Object.keys(SVC);
  /* разделы-заглушки: чтобы вернуть раздел, уберите его из SOON и удалите data-soon у секции */
  var SOON = { telegram: true, vless: true, wg: true };
  /* внутри Tauri доступны настоящие команды, в обычном браузере остаётся макет */
  var T = window.__TAURI__;
  var inTauri = !!(T && T.core && T.core.invoke);
  var appMode = inTauri || /[?&]app\b/.test(location.search);
  if (appMode) document.body.classList.add('app');
  var installed = function (id) { var c = S.comps.filter(function (x) { return x.id === id; })[0]; return !!(c && c.cur); };
  var live = function () { return S.comps.filter(function (c) { return !SOON[c.id]; }); };
  var PAGES = ['home', 'discord', 'telegram', 'vless', 'wg', 'security', 'updates', 'settings'];
  var SUFFIX = ['', 'ALT'];
  for (var q = 2; q <= 13; q++) SUFFIX.push('ALT' + q);
  SUFFIX = SUFFIX.concat(['EXP', 'FAKE TLS AUTO', 'FAKE TLS AUTO ALT', 'FAKE TLS AUTO ALT2', 'FAKE TLS AUTO ALT3', 'SIMPLE FAKE', 'SIMPLE FAKE ALT', 'SIMPLE FAKE ALT2']);
  var STRAT_DEFS = SUFFIX.map(function (s) {
    var g = !s ? 'Базовая' : /^ALT/.test(s) ? 'ALT' : s === 'EXP' ? 'Эксперимент' : /^FAKE/.test(s) ? 'Fake TLS' : 'Simple fake';
    return { f: s ? 'general (' + s + ')' : 'general', t: s || 'general', g: g };
  });
  var STRATS = STRAT_DEFS.map(function (s) { return s.f; });
  var INIT_SCORES = [2, 4, 6, 3, 2, 5, 4, 3, 1, 5, 4, 3, 5, 2, 3, 4, 5, 4, 3, 1, 2, 5];
  var scanning = null, flash = null, testing = false;

  var S = {
    page: 'home',
    on: { discord: false, telegram: false, vless: false, wg: false },
    discord: { mode: 'auto', strategy: 'general (ALT2)', game: false, ipset: 'none', lastTest: 'сегодня, 14:32', autoupd: true, ipsetUpdated: 'сегодня, 09:12' },
    telegram: { port: '1080' },
    lists: {
      general: { file: 'list-general-user.txt', title: 'Свои домены', hint: 'Домены для обхода, по одному на строку. Поддомены учитываются автоматически.', text: '# по одному домену на строку\nexample.org\ncdn.example.org\n' },
      exclude: { file: 'list-exclude-user.txt', title: 'Исключения доменов', hint: 'Домены, которые не нужно обрабатывать, даже если их IP есть в ipset-all.txt.', text: '' },
      ipset: { file: 'ipset-all.txt', title: 'Свои IP и подсети', hint: 'IP-адреса и подсети для обхода, по одному на строку.', text: '# IP и подсети\n203.0.113.0/24\n' },
      ipsetEx: { file: 'ipset-exclude-user.txt', title: 'Исключения IP', hint: 'IP-адреса и подсети, которые не нужно обрабатывать.', text: '' }
    },
    prof: {
      vless: [
        { id: 1, name: 'Франкфурт · Reality', host: 'fra1.example.net', ping: 48 },
        { id: 2, name: 'Хельсинки · TLS', host: 'hel2.example.net', ping: 61 },
        { id: 3, name: 'Стамбул · WebSocket', host: 'ist1.example.net', ping: 92 }
      ],
      wg: [{ id: 11, name: 'wg-home', host: '203.0.113.10:51820', ping: null }]
    },
    sel: { vless: null, wg: null },
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
      { id: 'vless', name: 'VLESS', cur: '2.0.1', next: null, cls: 'b-vless', icon: 'net', size: '21.7 МБ', src: 'GitHub Releases', sha: 'c20d5e71b8a4…03aa', notes: [], busy: null },
      { id: 'wg', name: 'WireGuard', cur: '0.5.3', next: null, cls: 'b-wg', icon: 'vpn', size: '4.6 МБ', src: 'GitHub Releases', sha: '5d1f9a3e07c2…8b11', notes: [], busy: null }
    ],
    lastCheck: 'сегодня, 14:45',
    targets: [
      { host: 'discord.com', ms: 84, ok: true },
      { host: 'gateway.discord.gg', ms: 112, ok: true },
      { host: 'cdn.discordapp.com', ms: 97, ok: true },
      { host: 'youtube.com', ms: 76, ok: true },
      { host: 'googlevideo.com', ms: 131, ok: true },
      { host: 'i.ytimg.com', ms: 88, ok: true }
    ],
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
  var selName = function (t) { var id = S.sel[t]; var p = S.prof[t].filter(function (x) { return x.id === id; })[0]; return p ? p.name : null; };

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
      discord: function () { return [['Метод', 'winws'], ['Режим', S.discord.mode === 'auto' ? 'Авто' : 'Вручную']]; },
      telegram: function () { return [['Метод', 'tg-ws-proxy'], ['Режим', 'Авто']]; },
      vless: function () { return [['Сервер', selName('vless') || 'Не выбран'], ['Профиль', S.sel.vless ? 'Основной' : 'Нет']]; },
      wg: function () { return [['Профиль', selName('wg') || 'Не выбран'], ['Интерфейс', S.sel.wg ? 'wg0' : '–']]; }
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
    ['discord', 'telegram'].forEach(function (id) {
      var c = comp(id), ok = installed(id), box = $('#inst-' + id), body = document.querySelector('[data-body="' + id + '"]');
      if (!box || !body) return;
      box.hidden = ok; body.hidden = !ok;
      var sw = document.querySelector('.head-sw [data-svc="' + id + '"]');
      if (sw) sw.parentNode.hidden = !ok;
      document.querySelector('[data-latest="' + id + '"]').textContent = c.latest || '…';
      $('#instAct-' + id).innerHTML = c.busy != null
        ? '<span class="bar-track"><span class="bar-fill" style="width:' + c.busy + '%"></span></span><div class="note mt-s">Скачиваем и проверяем файлы… ' + c.busy + '%</div>'
        : '<button class="btn primary" data-act="installComp" data-arg="' + id + '">' + ico('plus') + 'Установить</button>';
    });
  }

  function renderTray() {
    var rows = [
      ['mark', 'Открыть Бунт', 'home'],
      null,
      ['chat', 'Запрет Discord и YouTube' + (installed('discord') ? (S.on.discord ? ' · включён' : ' · выключен') : ''), 'discord'],
      ['plane', 'Запрет Telegram · скоро', null],
      ['net', 'VLESS · скоро', null],
      ['vpn', 'WireGuard · скоро', null],
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
    $('#stratWhen').textContent = (d.mode === 'auto' ? 'Подобрана автоматически · ' : 'Выбрана вручную · последняя проверка: ') + d.lastTest;
    $('#stratLine').hidden = testing;
    $('#stratWhen').hidden = testing;
    $('#testBox').hidden = !testing;
    $('#lastTest').textContent = d.lastTest;
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
      var sc = d.scores[s.f], cur = d.strategy === s.f;
      var cls = (cur ? 'cur ' : '') + (scanning === s.f ? 'scan ' : '') + (flash === s.f ? 'win' : '');
      var tag = sc == null ? '<span class="tag">–</span>' : '<span class="tag ' + (sc === 6 ? 'ok' : sc >= 4 ? 'warn' : 'bad') + '">' + sc + '/6</span>';
      return '<button class="strat ' + cls + '" data-strat="' + esc(s.f) + '" aria-pressed="' + cur + '">' +
        '<span class="shd"><span class="sg">' + s.g + '</span>' + tag + '</span>' +
        '<span class="sn">' + (cur ? ico('check') : '') + esc(s.t) + '</span>' +
        '<span class="sf">' + esc(s.f) + '.bat</span></button>';
    }).join('');
    $('#targets').innerHTML = S.targets.map(function (t) {
      return '<div class="tgt"><span class="mono">' + t.host + '</span><span class="ms">' + (t.ok ? t.ms + ' мс' : '') + '</span><span class="tag ' + (t.ok ? 'ok' : 'bad') + '">' + (t.ok ? 'Открывается' : 'Недоступен') + '</span></div>';
    }).join('');
  }

  function renderTelegram() {
    var p = String(S.telegram.port).replace(/\D/g, '') || '1080';
    $('#tgLink').value = 'tg://socks?server=127.0.0.1&port=' + p;
  }

  function renderProfiles(t) {
    var host = $('#list-' + t), arr = S.prof[t];
    if (!arr.length) {
      host.innerHTML = '<div class="empty"><span>Профилей пока нет.</span>' + (t === 'wg' ? '<button class="btn" data-act="pickWg">' + ico('plus') + 'Импортировать .conf</button>' : '') + '</div>';
      return;
    }
    host.innerHTML = arr.map(function (p) {
      var sel = S.sel[t] === p.id;
      return '<div class="prof ' + (sel ? 'sel' : '') + '"><button class="pick" data-pick="' + t + ':' + p.id + '" aria-pressed="' + sel + '"><span class="radio"></span><span class="pn"><b>' + esc(p.name) + '</b><small>' + esc(p.host) + '</small></span></button>' +
        (p.ping != null ? '<span class="tag ' + (p.ping < 80 ? 'ok' : 'warn') + '">' + p.ping + ' мс</span>' : '') +
        '<button class="btn sm ghost" data-del="' + t + ':' + p.id + '" aria-label="Удалить ' + esc(p.name) + '">' + ico('x') + '</button></div>';
    }).join('');
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
    ['app', 'discord'].forEach(function (id) {
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
  /* автозапуск живёт в планировщике заданий, а не в «Автозагрузке» диспетчера задач */
  function renderAutostart() {
    var el = $('#autoInfo');
    if (!el) return;
    if (!inTauri) { el.textContent = ''; return; }
    el.textContent = 'Работает через планировщик заданий Windows (задача «Bunt»), в «Автозагрузке» диспетчера задач её нет. Проверяем…';
    T.core.invoke('autostart_exists').then(function (ok) {
      el.textContent = 'Работает через планировщик заданий Windows (задача «Bunt»), в «Автозагрузке» диспетчера задач её нет. Сейчас задача: ' + (ok ? 'создана' : 'не создана') + '.';
    }).catch(function () { el.textContent = ''; });
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
      if (c.busy != null) stat = '<span class="bar-track" style="width:110px"><span class="bar-fill" style="width:' + c.busy + '%"></span></span>';
      else if (!c.cur) stat = '<button class="btn sm primary" data-act="installComp" data-arg="' + c.id + '">Установить</button>';
      else if (c.next) stat = '<button class="btn sm primary" data-act="updateOne" data-arg="' + c.id + '">Обновить</button>';
      else if (unchecked) stat = isChecking() ? '<span class="tag"><span class="spin"></span>Проверяем…</span>' : '<span class="tag">Не проверено</span>';
      else stat = '<span class="tag ok">Актуально</span>';
      return '<div class="vrow"><div class="vwho"><span class="badge sm ' + c.cls + '">' + ico(c.icon) + '</span>' +
        '<span class="pn"><b>' + c.name + (appMode && c.demo ? ' <span class="tag">демо</span>' : '') + '</b><small>' + esc(c.src) + '</small></span></div>' +
        '<div class="vcell"><small>Установлено</small><span class="v">' + (c.cur || 'Не установлено') + '</span></div>' +
        '<div class="vcell"><small>На GitHub</small><span class="v ' + (c.next ? 'new' : '') + '">' + latest + '</span></div>' +
        '<div class="vstat">' + stat + '</div></div>';
    }).join('');
  }

  function renderSecurity() {
    var run = S.sec.running;
    var allOk = S.sec.items.every(function (i) { return i.st === 'ok'; });
    $('#secIco').className = 'sec-ico' + (run ? ' run' : '');
    $('#secTitle').textContent = run ? 'Идёт проверка…' : (allOk ? 'Все файлы в порядке' : 'Проверка не завершена');
    $('#secText').textContent = run ? 'Сверяем хеши и подписи компонентов.' : (allOk ? 'Проверка завершена. Подозрительных изменений не найдено.' : 'Запустите проверку ещё раз.');
    $('#secLast').textContent = S.sec.last;
    $('#btnSec').disabled = run;
    $('#secList').innerHTML = S.sec.items.map(function (i) {
      var lead = i.st === 'run' ? '<span class="spin"></span>' : ico(i.st === 'ok' ? 'check' : 'clock');
      return '<div class="sec-item ' + (i.st === 'idle' ? 'idle' : '') + '">' + lead + '<span>' + i.t + '</span><span class="res">' + (i.st === 'ok' ? 'OK' : i.st === 'run' ? 'Проверяю…' : 'Ожидает') + '</span></div>';
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
    renderInstall(); renderDiscord(); renderTelegram(); renderProfiles('vless'); renderProfiles('wg');
    renderVersions(); renderNotes(); renderSecurity(); sync(); syncTray();
  }

  function go(page) {
    if (PAGES.indexOf(page) < 0) page = 'home';
    S.page = page;
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
    if (on && (id === 'vless' || id === 'wg') && !S.sel[id]) {
      if (!quiet) { toast(id === 'vless' ? 'Сначала выберите сервер VLESS.' : 'Сначала импортируйте или выберите профиль WireGuard.', 'warn'); go(id); }
      return false;
    }
    if (inTauri && id === 'discord') { realDiscord(on, quiet); return true; }
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
  function autotest() {
    if (testing) return;
    var d = S.discord, names = STRATS.slice();
    var winner = Math.floor(Math.random() * names.length);
    testing = true;
    flash = null;
    names.forEach(function (n) { d.scores[n] = null; });
    $('#btnTest').disabled = true;
    $('#testBox .bar-fill').style.width = '0%';
    addLog({ svc: 'Zapret (Discord)', m: 'Подбор стратегии…' });
    var i = 0;
    function step() {
      if (i >= names.length) { finish(); return; }
      var k = i, n = names[k];
      scanning = n;
      $('#testState').textContent = 'Проверяем ' + n + ' (' + (k + 1) + ' из ' + names.length + ')';
      renderDiscord();
      $('#testBox .bar-fill').style.width = (k / names.length * 100) + '%';
      var el = $('.strat.scan');
      if (el && el.scrollIntoView) el.scrollIntoView({ block: 'nearest' });
      setTimeout(function () {
        d.scores[n] = k === winner ? 6 : Math.floor(Math.random() * 6);
        i++;
        step();
      }, 260);
    }
    function finish() {
      scanning = null;
      testing = false;
      d.strategy = names[winner];
      d.mode = 'auto';
      d.lastTest = 'только что, ' + hms().slice(0, 5);
      flash = names[winner];
      S.targets.forEach(function (t) { t.ok = true; t.ms = 70 + Math.floor(Math.random() * 70); });
      $('#btnTest').disabled = false;
      addLog({ m: 'Выбрана стратегия ' + names[winner] + '. Все сервисы открываются.', ok: true });
      toast('Подобрана стратегия: ' + names[winner]);
      renderAll();
      var w = $('.strat.cur');
      if (w && w.scrollIntoView) w.scrollIntoView({ block: 'center', behavior: 'smooth' });
      setTimeout(function () { flash = null; renderDiscord(); }, 1400);
    }
    step();
  }

  /* профили */
  function addProfile(t, name, host, ping) {
    var id = ++S.nextId;
    S.prof[t].push({ id: id, name: name, host: host, ping: ping == null ? null : ping });
    renderProfiles(t);
  }
  function addVless() {
    var v = $('#vlessIn').value.trim(), msg = $('#vlessMsg');
    if (!v) { msg.textContent = 'Вставьте ссылку vless:// или адрес подписки.'; return; }
    try {
      var u = new URL(v);
      if (/^vless:$/i.test(u.protocol)) {
        var nm = '';
        try { nm = decodeURIComponent(u.hash.replace(/^#/, '')); } catch (e) { nm = ''; }
        addProfile('vless', nm || u.hostname, u.hostname, null);
        msg.textContent = 'Сервер добавлен: ' + (nm || u.hostname) + '.';
      } else if (/^https?:$/i.test(u.protocol)) {
        addProfile('vless', 'Подписка · ' + u.hostname, 'Серверы подписки загрузятся при выборе', null);
        msg.textContent = 'Подписка добавлена.';
      } else { throw new Error('proto'); }
      $('#vlessIn').value = '';
    } catch (e) {
      msg.textContent = 'Не удалось разобрать ссылку. Проверьте, что она скопирована целиком.';
    }
  }
  function pingAll(t) {
    S.prof[t].forEach(function (p) { p.ping = 35 + Math.floor(Math.random() * 100); });
    renderProfiles(t);
    toast('Пинг обновлён');
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
  var REAL = { discord: true };
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
    c.busy = 0;
    addLog({ svc: c.name, m: 'Загрузка из ' + c.src.replace(/ \(GitHub\)/, '') + '…' });
    renderAll();
    T.core.invoke('install_component', { id: id }).then(function (v) {
      c.cur = v; c.latest = v; c.next = null; c.busy = null;
      addLog({ svc: c.name, m: 'Установлено: ' + v + '. Хеш проверен.', ok: true });
      toast(c.name + ' установлен');
      renderAll();
    }).catch(function (err) {
      c.busy = null;
      addLog({ svc: c.name, m: 'Ошибка установки: ' + err });
      toast('Не удалось установить: ' + String(err).slice(0, 160), 'warn');
      renderAll();
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
        c.cur = c.latest; c.busy = null;
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
        c.busy = null;
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
        c.cur = c.next; c.next = null; c.busy = null; c.notes = [];
        addLog({ svc: c.name, m: 'Обновлено до ' + c.cur + '. Хеш проверен.', ok: true });
        toast(c.name + ': версия ' + c.cur);
        if (was) setSvc(id, true, true);
        renderAll();
      } else { renderVersions(); }
    }, 180);
  }

  /* проверка целостности */
  function runSec() {
    if (S.sec.running) return;
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
    copyTg: function () { copyText($('#tgLink').value, 'Ссылка скопирована'); },
    addVless: addVless,
    pingAll: function (a) { pingAll(a); },
    pickWg: function () { $('#wgFile').click(); },
    updateOne: updateOne,
    installComp: installComp,
    takeOver: takeOver,
    runSec: runSec,
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
    var el = e.target.closest('[data-go],[data-svc],[data-strat],[data-sw],[data-seg] button,[data-act],[data-pick],[data-del],[data-url]');
    if (!el) return;
    var d = el.dataset;
    if (d.url) { openUrl(d.url); return; }
    if (d.go) { go(d.go); return; }
    if (d.strat) { pickStrat(d.strat); return; }
    if (d.svc) { setSvc(d.svc, !S.on[d.svc]); return; }
    if (d.sw) {
      set(d.sw, !get(d.sw));
      if (d.sw === 'discord.game') addLog({ svc: 'Zapret (Discord)', m: 'Game Filter: ' + (S.discord.game ? 'включён' : 'выключен') + '. Нужен перезапуск стратегии.' });
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
    if (d.pick) {
      var a = d.pick.split(':'), t = a[0], id = Number(a[1]);
      S.sel[t] = id;
      if (S.on[t]) addLog({ svc: SVC[t].name, m: 'Переключение на ' + selName(t) + '…' });
      renderAll();
      return;
    }
    if (d.del) {
      var b = d.del.split(':'), tt = b[0], pid = Number(b[1]);
      S.prof[tt] = S.prof[tt].filter(function (p) { return p.id !== pid; });
      if (S.sel[tt] === pid) { S.sel[tt] = null; if (S.on[tt]) setSvc(tt, false, true); }
      renderAll();
      return;
    }
    if (d.act && ACT[d.act]) ACT[d.act](d.arg);
  });

  document.addEventListener('change', function (e) {
    var el = e.target;
    if (el.dataset && el.dataset.bind) { set(el.dataset.bind, el.value); renderAll(); }
  });
  document.addEventListener('input', function (e) {
    var el = e.target;
    if (el.id === 'tgPort') { S.telegram.port = el.value.replace(/\D/g, '').slice(0, 5); renderTelegram(); }
  });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeModal(); });
  $('#modal').addEventListener('click', function (e) { if (e.target === this) closeModal(); });
  $('#vlessIn').addEventListener('keydown', function (e) { if (e.key === 'Enter') addVless(); });
  $('#wgFile').addEventListener('change', function (e) {
    var f = e.target.files && e.target.files[0];
    if (!f) return;
    var r = new FileReader();
    r.onload = function () {
      var m = /Endpoint\s*=\s*(.+)/i.exec(String(r.result));
      addProfile('wg', f.name.replace(/\.conf$/i, ''), m ? m[1].trim() : 'Endpoint не указан', null);
      toast('Профиль добавлен: ' + f.name);
    };
    r.onerror = function () { toast('Не удалось прочитать файл.', 'warn'); };
    r.readAsText(f);
    e.target.value = '';
  });

  /* старт */
  S.comps.forEach(function (c) { if (c.id !== 'app') c.demo = true; });
  /* в настоящем приложении до первой проверки не пишем «Актуально» */
  if (inTauri) { startPending = true; S.comps.forEach(function (c) { c.checked = false; }); }
  if (appMode) { S.uptime = 0; S.lastCheck = 'ещё не проверяли'; }
  S.discord.scores = {};
  STRATS.forEach(function (n, i) { S.discord.scores[n] = INIT_SCORES[i]; });
  renderAll();
  var h = (location.hash || '').replace(/^#/, '');
  go(PAGES.indexOf(h) >= 0 ? h : 'home');

  if (inTauri) {
    T.core.invoke('app_info').then(function (i) { setAppVersion(i.version); renderAll(); });
    Object.keys(REAL).forEach(function (id) { comp(id).latest = null; comp(id).demo = false; comp(id).sha = '–'; });
    T.core.invoke('modules_dir').then(function (p) {
      $$('[data-modpath]').forEach(function (el) { el.hidden = false; el.textContent = 'Папка установки: ' + p; });
    });
    T.core.invoke('installed_components').then(function (m) {
      Object.keys(m).forEach(function (id) { if (comp(id)) comp(id).cur = m[id]; });
      renderAll();
      Object.keys(REAL).forEach(function (id) { refreshLatest(id).then(renderAll); });
      loadNotes();
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
          realDiscord(true, true);          /* поднимаем запрет, который был включён */
        } else {
          checkForeign();                   /* работает не из Бунта: предложить перейти */
        }
      }).catch(function () {});
    }).catch(function () { renderAll(); });
    T.event.listen('module-progress', function (e) {
      var p = e.payload || {}, c = comp(p.id);
      if (c && c.busy != null && p.total) { c.busy = Math.min(99, Math.round(p.downloaded / p.total * 100)); renderAll(); }
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
