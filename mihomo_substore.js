// Sub-Store 的 Mihomo 覆写脚本
// 目标：尽量复刻 mihomo.yaml 的核心行为，并兼容 proxy-providers / proxies 两种输入。

const HEALTHCHECK_URL = 'https://dns.google/generate_204';
const GITHUB_RAW = 'https://raw.githubusercontent.com/kongbaitt/proxy/main';

// 直连伪节点：保留 YAML 中的 IP 优先级直连策略。
const DIRECT_PROXIES = [
  { name: 'IPV4优先', type: 'direct', udp: true, 'ip-version': 'ipv4-prefer' },
  { name: 'IPV6优先', type: 'direct', udp: true, 'ip-version': 'ipv6-prefer' },
  { name: '仅IPV4', type: 'direct', udp: true, 'ip-version': 'ipv4' },
  { name: '仅IPV6', type: 'direct', udp: true, 'ip-version': 'ipv6' },
];

// YAML 里的基础 DNS。
const DIRECT_DNS = [
  'https://dns.alidns.com/dns-query#直接连接',
  'https://doh.pub/dns-query#直接连接&h3=false',
];
const PROXY_DNS = [
  'https://dns.google/dns-query#代理DNS',
  'https://dns.quad9.net/dns-query#代理DNS',
];

// YAML 中的 rule-providers，保留原始行为与路径。
const RULE_PROVIDERS = {
  private_ip: mkProvider('ipcidr', 'private_ip.mrs', './rules/private_ip.mrs'),
  // 与 mihomo.yaml 对齐：广告规则走 anti-ad 的官方 mihomo.mrs。
  'AWAvenue-Ads': mkProvider('domain', 'AWAvenue-Ads_domain.mrs', './rules/AWAvenue-Ads.mrs', 'https://anti-ad.net/mihomo.mrs'),
  private: mkProvider('domain', 'private.mrs', './rules/private.mrs'),
  fcm: mkProvider('domain', 'fcm_domain.mrs', './rules/fcm.mrs'),
  captcha: mkProvider('domain', 'captcha_domain.mrs', './rules/captcha.mrs'),
  ai: mkProvider('domain', 'ai.mrs', './rules/ai.mrs'),
  telegram: mkProvider('domain', 'telegram.mrs', './rules/telegram.mrs'),
  github: mkProvider('domain', 'github.mrs', './rules/github.mrs'),
  media: mkProvider('domain', 'media.mrs', './rules/media.mrs'),
  google: mkProvider('domain', 'google.mrs', './rules/google.mrs'),
  trackerslist: mkProvider('domain', 'trackerslist.mrs', './rules/trackerslist.mrs'),
  'apple-cn': mkProvider('domain', 'apple-cn.mrs', './rules/apple-cn.mrs'),
  'microsoft-cn': mkProvider('domain', 'microsoft-cn.mrs', './rules/microsoft-cn.mrs'),
  'games-cn': mkProvider('domain', 'games-cn.mrs', './rules/games-cn.mrs'),
  proxy_domain: mkProvider('domain', 'proxy_domain.mrs', './rules/proxy_domain.mrs'),
  direct_domain: mkProvider('domain', 'direct_domain.mrs', './rules/direct_domain.mrs'),
  proxy: mkProvider('domain', 'proxy.mrs', './rules/proxy.mrs'),
  cn: mkProvider('domain', 'cn_domain.mrs', './rules/cn.mrs'),
  'dnsmasq-china-add': mkProvider('domain', 'dnsmasq-china-add_domain.mrs', './rules/dnsmasq-china-add.mrs'),
  telegram_ip: mkProvider('ipcidr', 'telegram_ip.mrs', './rules/telegram_ip.mrs'),
  media_ip: mkProvider('ipcidr', 'media_ip.mrs', './rules/media_ip.mrs'),
  google_ip: mkProvider('ipcidr', 'google_ip.mrs', './rules/google_ip.mrs'),
  'enhanced-FaaS-in-China_ip': mkProvider('ipcidr', 'enhanced-FaaS-in-China_ip.mrs', './rules/enhanced-FaaS-in-China_ip.mrs'),
  proxy_ip: mkProvider('ipcidr', 'proxy_ip.mrs', './rules/proxy_ip.mrs'),
  direct_ip: mkProvider('ipcidr', 'direct_ip.mrs', './rules/direct_ip.mrs'),
  cn_ip: mkProvider('ipcidr', 'cn_ip.mrs', './rules/cn_ip.mrs'),
};

// YAML 中的规则，保留 UDP AND、FCM、代理UDP、TRACKER 兜底等行为。
const RULES = [
  'DST-PORT,5228-5230,FCM服务',
  'AND,((NETWORK,UDP),(DST-PORT,1337/2710/6881-6999/7777)),代理UDP',
  'DST-PORT,1337/2710/6881-6999/7777,TRACKER',
  'RULE-SET,private_ip,直接连接,no-resolve',
  'RULE-SET,AWAvenue-Ads,REJECT',
  'RULE-SET,private,直接连接',
  'RULE-SET,fcm,FCM服务',
  'AND,((NETWORK,UDP),(RULE-SET,captcha)),代理UDP',
  'RULE-SET,captcha,人机验证',
  'AND,((NETWORK,UDP),(RULE-SET,ai)),代理UDP',
  'RULE-SET,ai,国外AI',
  'AND,((NETWORK,UDP),(RULE-SET,telegram)),代理UDP',
  'RULE-SET,telegram,TELEGRAM',
  'AND,((NETWORK,UDP),(RULE-SET,github)),代理UDP',
  'RULE-SET,github,GITHUB',
  'AND,((NETWORK,UDP),(RULE-SET,media)),代理UDP',
  'RULE-SET,media,国外媒体',
  'AND,((NETWORK,UDP),(RULE-SET,google)),代理UDP',
  'RULE-SET,google,GOOGLE',
  'AND,((NETWORK,UDP),(RULE-SET,trackerslist)),代理UDP',
  'RULE-SET,trackerslist,TRACKER',
  'RULE-SET,apple-cn,直接连接',
  'RULE-SET,microsoft-cn,直接连接',
  'RULE-SET,games-cn,直接连接',
  'AND,((NETWORK,UDP),(RULE-SET,proxy_domain)),代理UDP',
  'RULE-SET,proxy_domain,代理连接',
  'RULE-SET,direct_domain,直接连接',
  'AND,((NETWORK,UDP),(RULE-SET,proxy)),代理UDP',
  'RULE-SET,proxy,代理连接',
  'RULE-SET,cn,直接连接',
  'AND,((NETWORK,UDP),(RULE-SET,telegram_ip)),代理UDP',
  'RULE-SET,telegram_ip,TELEGRAM',
  'AND,((NETWORK,UDP),(RULE-SET,media_ip)),代理UDP',
  'RULE-SET,media_ip,国外媒体',
  'AND,((NETWORK,UDP),(RULE-SET,google_ip)),代理UDP',
  'RULE-SET,google_ip,GOOGLE',
  'RULE-SET,enhanced-FaaS-in-China_ip,直接连接',
  'AND,((NETWORK,UDP),(RULE-SET,proxy_ip)),代理UDP',
  'RULE-SET,proxy_ip,代理连接',
  'RULE-SET,direct_ip,直接连接',
  'RULE-SET,cn_ip,直接连接',
  'NETWORK,UDP,代理UDP',
  'DST-PORT,10000-65535,TRACKER',
  'MATCH,代理连接',
];

// lite 模式下只保留基础组，因此把原本指向各服务组的规则收敛到基础组。
const LITE_RULES = [
  'DST-PORT,5228-5230,代理连接',
  'AND,((NETWORK,UDP),(DST-PORT,1337/2710/6881-6999/7777)),代理UDP',
  'DST-PORT,1337/2710/6881-6999/7777,代理连接',
  'RULE-SET,private_ip,直接连接,no-resolve',
  'RULE-SET,AWAvenue-Ads,REJECT',
  'RULE-SET,private,直接连接',
  'RULE-SET,fcm,代理连接',
  'AND,((NETWORK,UDP),(RULE-SET,captcha)),代理UDP',
  'RULE-SET,captcha,代理连接',
  'AND,((NETWORK,UDP),(RULE-SET,ai)),代理UDP',
  'RULE-SET,ai,代理连接',
  'AND,((NETWORK,UDP),(RULE-SET,telegram)),代理UDP',
  'RULE-SET,telegram,代理连接',
  'AND,((NETWORK,UDP),(RULE-SET,github)),代理UDP',
  'RULE-SET,github,代理连接',
  'AND,((NETWORK,UDP),(RULE-SET,media)),代理UDP',
  'RULE-SET,media,代理连接',
  'AND,((NETWORK,UDP),(RULE-SET,google)),代理UDP',
  'RULE-SET,google,代理连接',
  'AND,((NETWORK,UDP),(RULE-SET,trackerslist)),代理UDP',
  'RULE-SET,trackerslist,代理连接',
  'RULE-SET,apple-cn,直接连接',
  'RULE-SET,microsoft-cn,直接连接',
  'RULE-SET,games-cn,直接连接',
  'AND,((NETWORK,UDP),(RULE-SET,proxy_domain)),代理UDP',
  'RULE-SET,proxy_domain,代理连接',
  'RULE-SET,direct_domain,直接连接',
  'AND,((NETWORK,UDP),(RULE-SET,proxy)),代理UDP',
  'RULE-SET,proxy,代理连接',
  'RULE-SET,cn,直接连接',
  'AND,((NETWORK,UDP),(RULE-SET,telegram_ip)),代理UDP',
  'RULE-SET,telegram_ip,代理连接',
  'AND,((NETWORK,UDP),(RULE-SET,media_ip)),代理UDP',
  'RULE-SET,media_ip,代理连接',
  'AND,((NETWORK,UDP),(RULE-SET,google_ip)),代理UDP',
  'RULE-SET,google_ip,代理连接',
  'RULE-SET,enhanced-FaaS-in-China_ip,直接连接',
  'AND,((NETWORK,UDP),(RULE-SET,proxy_ip)),代理UDP',
  'RULE-SET,proxy_ip,代理连接',
  'RULE-SET,direct_ip,直接连接',
  'RULE-SET,cn_ip,直接连接',
  'NETWORK,UDP,代理UDP',
  'DST-PORT,10000-65535,代理连接',
  'MATCH,代理连接',
];

const COMMON_GROUP = { url: HEALTHCHECK_URL, interval: 900, timeout: 3000, lazy: false, 'max-failed-times': 2 };
const REGION_FILTERS = [
  ['香港|故障转移', '(?i)🇭🇰|香港|\\bHK\\b|\\bhongkong\\b|\\bhong\\s?kong\\b'],
  ['台湾|故障转移', '(?i)🇹🇼|台湾|\\bTW\\b|\\btaiwan\\b'],
  ['新加坡|故障转移', '(?i)🇸🇬|新加坡|狮城|\\bSG\\b|\\bsingapore\\b'],
  ['日本|故障转移', '(?i)🇯🇵|日本|\\bJP\\b|\\bjapan\\b'],
  ['韩国|故障转移', '(?i)🇰🇷|韩国|\\bKR\\b'],
  ['美国|故障转移', '(?i)🇺🇸|美国|\\bUS\\b|\\bunitedstates\\b|\\bunited\\s?states\\b'],
  ['加拿大|故障转移', '(?i)🇨🇦|加拿大|\\bCA\\b|\\bcanada\\b'],
  ['德国|故障转移', '(?i)🇩🇪|德国|\\bDE\\b|\\bgermany\\b'],
  ['英国|故障转移', '(?i)🇬🇧|英国|\\bUK\\b|\\bGB\\b|\\bunitedkingdom\\b|\\bunited\\s?kingdom\\b'],
  ['法国|故障转移', '(?i)🇫🇷|法国|\\bFR\\b'],
  ['荷兰|故障转移', '(?i)🇳🇱|荷兰|\\bNL\\b|\\bnetherlands?\\b'],
];

// 外部可通过 `$arguments.failover=false` 或直接写 `failover=false` 关闭故障转移。
// 兼容布尔、数字、字符串：false/0/off/no 都会视为关闭。
const SCRIPT_ARGS = typeof $arguments !== 'undefined' ? $arguments : {};
const FAILOVER_ENABLED = resolveFailover(SCRIPT_ARGS);
const REGION_ENABLED = resolveRegionEnabled(SCRIPT_ARGS);
const GROUP_MODE = resolveGroupMode(SCRIPT_ARGS);

function mkProvider(behavior, remoteName, path, url = `${GITHUB_RAW}/rules/mrs/${remoteName}`) {
  return {
    type: 'http',
    interval: 86400,
    // Sub-Store 兼容优先走“代理连接”，避免依赖原生静态组名 GITHUB。
    proxy: '代理连接',
    behavior,
    format: 'mrs',
    url,
    path,
  };
}

function parseBooleanLike(value, defaultValue) {
  if (value === undefined || value === null || value === '') {
    return defaultValue;
  }
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    return value !== 0;
  }
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['false', '0', 'off', 'no'].includes(normalized)) {
      return false;
    }
    if (['true', '1', 'on', 'yes'].includes(normalized)) {
      return true;
    }
  }
  return defaultValue;
}

function resolveFailover(args = {}) {
  let value;

  if (Object.prototype.hasOwnProperty.call(args, 'failover')) {
    value = args.failover;
  } else if (typeof failover !== 'undefined') {
    value = failover;
  } else if (
    typeof globalThis !== 'undefined' &&
    Object.prototype.hasOwnProperty.call(globalThis, 'failover')
  ) {
    value = globalThis.failover;
  }

  return parseBooleanLike(value, true);
}

function resolveRegionEnabled(args = {}) {
  let value;

  if (Object.prototype.hasOwnProperty.call(args, 'region')) {
    value = args.region;
  } else if (typeof region !== 'undefined') {
    value = region;
  } else if (typeof globalThis !== 'undefined' && Object.prototype.hasOwnProperty.call(globalThis, 'region')) {
    value = globalThis.region;
  }

  return parseBooleanLike(value, true);
}

function resolveGroupMode(args = {}) {
  let value;

  if (Object.prototype.hasOwnProperty.call(args, 'groupMode')) {
    value = args.groupMode;
  } else if (typeof groupMode !== 'undefined') {
    value = groupMode;
  } else if (typeof globalThis !== 'undefined' && Object.prototype.hasOwnProperty.call(globalThis, 'groupMode')) {
    value = globalThis.groupMode;
  }

  return typeof value === 'string' && value.trim().toLowerCase() === 'lite' ? 'lite' : 'full';
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function hasProviders(config) {
  return !!(config && config['proxy-providers'] && Object.keys(config['proxy-providers']).length);
}

function hasProxies(config) {
  return !!(config && Array.isArray(config.proxies) && config.proxies.length);
}

function uniqueProxyNames(proxies) {
  const reserved = new Set(['DIRECT', 'REJECT', 'PASS', ...DIRECT_PROXIES.map((p) => p.name)]);
  const seen = new Set();
  const names = [];
  for (const proxy of proxies || []) {
    const name = proxy && proxy.name;
    if (!name || reserved.has(name) || seen.has(name)) continue;
    seen.add(name);
    names.push(name);
  }
  return names;
}

function sanitizeProxies(proxies) {
  const seen = new Set();
  const result = [];
  for (const proxy of proxies || []) {
    if (!proxy || typeof proxy !== 'object' || !proxy.name || seen.has(proxy.name)) continue;
    if (DIRECT_PROXIES.some((p) => p.name === proxy.name)) continue;
    seen.add(proxy.name);
    result.push(proxy);
  }
  return result.concat(clone(DIRECT_PROXIES));
}

function providerSelector() {
  // provider 模式：用 include-all-providers 维持 YAML 的“全量 provider”行为。
  return { 'include-all-providers': true };
}

function baseGroup(name, type, extra = {}) {
  return { name, type, ...extra };
}

function buildProviderGroups() {
  const use = providerSelector();
  if (GROUP_MODE === 'lite') {
    return [
      baseGroup('代理连接', 'select', { ...use, proxies: ['最低延迟'], icon: 'https://mihomo.echs.top/img/icon/Global.webp' }),
      baseGroup('代理UDP', 'select', { proxies: ['PASS', 'REJECT'], icon: 'https://mihomo.echs.top/img/icon/Network_2.webp' }),
      baseGroup('直接连接', 'select', { proxies: ['DIRECT', 'IPV4优先', 'IPV6优先', '仅IPV4', '仅IPV6'], icon: 'https://mihomo.echs.top/img/icon/DIRECT.webp' }),
      baseGroup('代理DNS', 'select', { ...use, proxies: ['代理连接', '直接连接', '最低延迟', 'PASS', 'REJECT'], icon: 'https://mihomo.echs.top/img/icon/Server.webp' }),
      baseGroup('最低延迟', 'url-test', { ...COMMON_GROUP, ...use, tolerance: 30, hidden: true, icon: 'https://mihomo.echs.top/img/icon/Fast.webp' }),
      baseGroup('GLOBAL', 'select', { ...use, proxies: ['代理连接', '代理UDP', '直接连接', '代理DNS', '最低延迟'], icon: 'https://mihomo.echs.top/img/icon/Globefish.webp' }),
    ];
  }
  const regionNames = GROUP_MODE === 'full' && REGION_ENABLED && FAILOVER_ENABLED ? REGION_FILTERS.map(([name]) => name) : [];
  const serviceChoices = GROUP_MODE === 'lite'
    ? ['代理连接', '直接连接', '最低延迟', 'PASS', 'REJECT']
    : ['代理连接', '直接连接', '最低延迟', ...regionNames, 'PASS', 'REJECT'];
  const directProxyChoices = FAILOVER_ENABLED ? ['最低延迟', ...regionNames] : ['最低延迟'];
  const groups = [
    baseGroup('代理连接', 'select', { ...use, proxies: directProxyChoices, icon: 'https://mihomo.echs.top/img/icon/Global.webp' }),
    baseGroup('代理UDP', 'select', { proxies: ['PASS', 'REJECT'], icon: 'https://mihomo.echs.top/img/icon/Network_2.webp' }),
    baseGroup('直接连接', 'select', { proxies: ['DIRECT', 'IPV4优先', 'IPV6优先', '仅IPV4', '仅IPV6'], icon: 'https://mihomo.echs.top/img/icon/DIRECT.webp' }),
    baseGroup('代理DNS', 'select', { ...use, proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/Server.webp' }),
    baseGroup('FCM服务', 'select', { ...use, proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/FCM_Firebase_Cloud_Messaging.webp' }),
    baseGroup('人机验证', 'select', { ...use, proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/CloudFlare.webp' }),
    baseGroup('国外AI', 'select', { ...use, proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/AI.webp' }),
    baseGroup('TELEGRAM', 'select', { ...use, proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/Telegram.webp' }),
    baseGroup('GITHUB', 'select', { ...use, proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/GitHub.webp' }),
    baseGroup('国外媒体', 'select', { ...use, proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/Emby.webp' }),
    baseGroup('GOOGLE', 'select', { ...use, proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/Google.webp' }),
    baseGroup('TRACKER', 'select', { ...use, proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/Download_2.webp' }),
    baseGroup('最低延迟', 'url-test', { ...COMMON_GROUP, ...use, tolerance: 30, hidden: true, icon: 'https://mihomo.echs.top/img/icon/Fast.webp' }),
  ];
  if (GROUP_MODE === 'full' && REGION_ENABLED && FAILOVER_ENABLED) {
    groups.push(...REGION_FILTERS.map(([name, filter]) => baseGroup(name, 'fallback', { ...use, hidden: true, filter, icon: regionIcon(name) })));
  }
  if (GROUP_MODE === 'full') {
    groups.push(baseGroup('GLOBAL', 'select', { ...use, proxies: ['最低延迟', ...regionNames, '代理连接', '代理UDP', '直接连接', '代理DNS', 'FCM服务', '人机验证', '国外AI', 'TELEGRAM', 'GITHUB', '国外媒体', 'GOOGLE', 'TRACKER'], hidden: true, icon: 'https://mihomo.echs.top/img/icon/Globefish.webp' }));
  }
  return groups;
}

function buildProxyGroupsFromNames(names) {
  // proxies 模式：开启故障转移时按节点名过滤近似复现 fallback；关闭时退化为手动选节点。
  if (GROUP_MODE === 'lite') {
    return [
      baseGroup('代理连接', 'select', { proxies: ['最低延迟', ...names], icon: 'https://mihomo.echs.top/img/icon/Global.webp' }),
      baseGroup('代理UDP', 'select', { proxies: ['PASS', 'REJECT'], icon: 'https://mihomo.echs.top/img/icon/Network_2.webp' }),
      baseGroup('直接连接', 'select', { proxies: ['DIRECT', 'IPV4优先', 'IPV6优先', '仅IPV4', '仅IPV6'], icon: 'https://mihomo.echs.top/img/icon/DIRECT.webp' }),
      baseGroup('代理DNS', 'select', { proxies: ['代理连接', '直接连接', '最低延迟', ...names, 'PASS', 'REJECT'], icon: 'https://mihomo.echs.top/img/icon/Server.webp' }),
      baseGroup('最低延迟', 'url-test', { ...COMMON_GROUP, tolerance: 30, hidden: true, proxies: names, icon: 'https://mihomo.echs.top/img/icon/Fast.webp' }),
      baseGroup('GLOBAL', 'select', { proxies: ['代理连接', '代理UDP', '直接连接', '代理DNS', '最低延迟', ...names], icon: 'https://mihomo.echs.top/img/icon/Globefish.webp' }),
    ];
  }
  const hasRegionGroups = GROUP_MODE === 'full' && REGION_ENABLED && FAILOVER_ENABLED;
  const regionGroups = hasRegionGroups
    ? REGION_FILTERS.map(([name, filter]) => baseGroup(name, 'fallback', { proxies: names.filter((n) => matchRegion(n, filter)), hidden: true, icon: regionIcon(name) }))
    : [];
  const allRegionNames = hasRegionGroups ? REGION_FILTERS.map(([name]) => name) : [];
  const serviceChoices = GROUP_MODE === 'lite'
    ? ['代理连接', '直接连接', '最低延迟', 'PASS', 'REJECT']
    : (hasRegionGroups ? ['代理连接', '直接连接', '最低延迟', ...allRegionNames, 'PASS', 'REJECT'] : ['代理连接', '直接连接', '最低延迟', ...names, 'PASS', 'REJECT']);
  const directProxyChoices = hasRegionGroups ? ['最低延迟', ...allRegionNames] : ['最低延迟', ...names];
  return [
    baseGroup('代理连接', 'select', { proxies: directProxyChoices, icon: 'https://mihomo.echs.top/img/icon/Global.webp' }),
    baseGroup('代理UDP', 'select', { proxies: ['PASS', 'REJECT'], icon: 'https://mihomo.echs.top/img/icon/Network_2.webp' }),
    baseGroup('直接连接', 'select', { proxies: ['DIRECT', 'IPV4优先', 'IPV6优先', '仅IPV4', '仅IPV6'], icon: 'https://mihomo.echs.top/img/icon/DIRECT.webp' }),
    baseGroup('代理DNS', 'select', { proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/Server.webp' }),
    baseGroup('FCM服务', 'select', { proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/FCM_Firebase_Cloud_Messaging.webp' }),
    baseGroup('人机验证', 'select', { proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/CloudFlare.webp' }),
    baseGroup('国外AI', 'select', { proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/AI.webp' }),
    baseGroup('TELEGRAM', 'select', { proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/Telegram.webp' }),
    baseGroup('GITHUB', 'select', { proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/GitHub.webp' }),
    baseGroup('国外媒体', 'select', { proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/Emby.webp' }),
    baseGroup('GOOGLE', 'select', { proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/Google.webp' }),
    baseGroup('TRACKER', 'select', { proxies: serviceChoices, icon: 'https://mihomo.echs.top/img/icon/Download_2.webp' }),
    baseGroup('最低延迟', 'url-test', { ...COMMON_GROUP, tolerance: 30, hidden: true, proxies: names, icon: 'https://mihomo.echs.top/img/icon/Fast.webp' }),
    ...regionGroups,
    ...(GROUP_MODE === 'full' ? [baseGroup('GLOBAL', 'select', { proxies: ['最低延迟', ...allRegionNames, '代理连接', '代理UDP', '直接连接', '代理DNS', 'FCM服务', '人机验证', '国外AI', 'TELEGRAM', 'GITHUB', '国外媒体', 'GOOGLE', 'TRACKER', ...(hasRegionGroups ? [] : names)], hidden: true, icon: 'https://mihomo.echs.top/img/icon/Globefish.webp' })] : []),
  ];
}

function matchRegion(name, filter) {
  // YAML 中的 filter 带有 (?i) 前缀，JS 里改为显式大小写不敏感匹配。
  const pattern = filter.replace(/^\(\?i\)\|?/, '').replace(/^\(\?i\)/, '');
  try {
    return new RegExp(pattern, 'i').test(name);
  } catch {
    return false;
  }
}

function regionIcon(name) {
  const map = {
    '香港|故障转移': 'hk', '台湾|故障转移': 'tw', '新加坡|故障转移': 'sg', '日本|故障转移': 'jp', '韩国|故障转移': 'kr',
    '美国|故障转移': 'us', '加拿大|故障转移': 'ca', '德国|故障转移': 'de', '英国|故障转移': 'gb', '法国|故障转移': 'fr', '荷兰|故障转移': 'nl',
  };
  return `https://mihomo.echs.top/img/flags/${map[name] || 'us'}.svg`;
}

function applyGlobals(config) {
  config.ipv6 = true;
  config['allow-lan'] = false;
  config['bind-address'] = '*';
  config.mode = 'rule';
  config['log-level'] = 'error';
  config['unified-delay'] = true;
  config['tcp-concurrent'] = true;
  config['find-process-mode'] = 'off';
  config['disable-keep-alive'] = false;
  config['keep-alive-interval'] = 15;
  config['keep-alive-idle'] = 300;
  config['etag-support'] = true;
  config.profile = { 'store-selected': true, 'store-fake-ip': true };
  config.port = 0;
  config['socks-port'] = 0;
  config['mixed-port'] = 0;
  config['tproxy-port'] = 0;
  config['redir-port'] = 0;
}

function applyNetwork(config) {
  // hosts / dns / sniffer 直接按 YAML 复刻。
  config.hosts = {
    'dns.alidns.com': ['223.5.5.5', '223.6.6.6', '2400:3200::1', '2400:3200:baba::1'],
    'doh.pub': ['120.53.53.53', '1.12.12.21'],
    'dns.google': ['8.8.8.8', '8.8.4.4', '2001:4860:4860::8888', '2001:4860:4860::8844'],
    'dns.quad9.net': ['9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9'],
    'services.googleapis.cn': 'services.googleapis.com',
    'google.cn': 'google.com',
  };
  config.dns = {
    enable: true, 'cache-algorithm': 'arc', ipv6: true, 'prefer-h3': true, 'use-hosts': true, 'use-system-hosts': true, 'respect-rules': false,
    'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16', 'fake-ip-range6': 'fd00:bada:55ed::1/64', 'fake-ip-filter-mode': 'rule',
    'fake-ip-filter': [
      'RULE-SET,AWAvenue-Ads,fake-ip', 'RULE-SET,private,real-ip', 'RULE-SET,fcm,fake-ip', 'RULE-SET,captcha,fake-ip', 'RULE-SET,ai,fake-ip',
      'RULE-SET,telegram,fake-ip', 'RULE-SET,github,fake-ip', 'RULE-SET,media,fake-ip', 'RULE-SET,google,fake-ip', 'RULE-SET,trackerslist,fake-ip',
      'RULE-SET,apple-cn,real-ip', 'RULE-SET,microsoft-cn,real-ip', 'RULE-SET,games-cn,real-ip', 'RULE-SET,proxy_domain,fake-ip',
      'RULE-SET,direct_domain,real-ip', 'RULE-SET,proxy,fake-ip', 'RULE-SET,cn,real-ip', 'MATCH,fake-ip',
    ],
    'proxy-server-nameserver': DIRECT_DNS.slice(),
    'nameserver-policy': {
      'rule-set:AWAvenue-Ads': ['rcode://name_error'], 'rule-set:private': DIRECT_DNS.slice(), 'rule-set:fcm': ['https://dns.echs.top/dns-query#直接连接'],
      'rule-set:captcha': PROXY_DNS.slice(), 'rule-set:ai': PROXY_DNS.slice(), 'rule-set:telegram': PROXY_DNS.slice(), 'rule-set:github': PROXY_DNS.slice(),
      'rule-set:media': PROXY_DNS.slice(), 'rule-set:google': PROXY_DNS.slice(), 'rule-set:trackerslist': PROXY_DNS.slice(), 'rule-set:apple-cn': DIRECT_DNS.slice(),
      'rule-set:microsoft-cn': DIRECT_DNS.slice(), 'rule-set:games-cn': DIRECT_DNS.slice(), 'rule-set:proxy_domain': PROXY_DNS.slice(),
      'rule-set:direct_domain': DIRECT_DNS.slice(), 'rule-set:proxy': PROXY_DNS.slice(), 'rule-set:cn': DIRECT_DNS.slice(), 'rule-set:dnsmasq-china-add': DIRECT_DNS.slice(),
    },
    nameserver: PROXY_DNS.slice(), 'direct-nameserver': DIRECT_DNS.slice(), 'direct-nameserver-follow-policy': true,
  };
  config.sniffer = {
    enable: true, 'force-dns-mapping': true, 'parse-pure-ip': true, 'override-destination': false,
    sniff: { HTTP: { ports: [80, '8080-8880'] }, TLS: { ports: [443, 8443] }, QUIC: { ports: [443, 8443] } },
    'skip-domain': ['rule-set:private'], 'skip-src-address': ['rule-set:private_ip'], 'skip-dst-address': ['rule-set:private_ip'],
  };
  config.tun = {
    enable: true, stack: 'mixed', 'auto-route': true, 'auto-redirect': true, 'auto-detect-interface': true, 'strict-route': true,
    'disable-icmp-forwarding': true, 'dns-hijack': ['any:53', 'tcp://any:53'],
  };
}

function main(config) {
  if (!config || typeof config !== 'object') throw new Error('配置内容为空');
  const useProviders = hasProviders(config);
  const useProxies = hasProxies(config);
  if (!useProviders && !useProxies) throw new Error('未找到可用节点或 proxy-providers');

  applyGlobals(config);
  applyNetwork(config);
  // 始终注入直连伪节点，避免 provider 模式下分组引用不存在的代理名。
  config.proxies = sanitizeProxies(config.proxies);
  config['rule-providers'] = clone(RULE_PROVIDERS);
  config.rules = (GROUP_MODE === 'lite' ? LITE_RULES : RULES).slice();

  if (useProviders) {
    // provider 模式保留原始 provider 输入，并让组尽量使用 include-all-providers。
    config['proxy-groups'] = buildProviderGroups();
  } else {
    const names = uniqueProxyNames(config.proxies);
    if (!names.length) throw new Error('过滤后未剩余可用节点');
    config['proxy-groups'] = buildProxyGroupsFromNames(names);
  }

  return config;
}
