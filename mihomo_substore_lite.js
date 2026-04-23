// Super minimal Sub-Store Mihomo override script.
// Manual proxy selection only.

const HEALTHCHECK_URL = 'https://dns.google/generate_204';

const DIRECT_PROXIES = [
  { name: 'IPV4优先', type: 'direct', udp: true, 'ip-version': 'ipv4-prefer' },
  { name: 'IPV6优先', type: 'direct', udp: true, 'ip-version': 'ipv6-prefer' },
  { name: '仅IPV4', type: 'direct', udp: true, 'ip-version': 'ipv4' },
  { name: '仅IPV6', type: 'direct', udp: true, 'ip-version': 'ipv6' },
];

const DIRECT_DNS = [
  'https://dns.alidns.com/dns-query#直接连接',
  'https://doh.pub/dns-query#直接连接&h3=false',
];

const PROXY_DNS = [
  'https://dns.google/dns-query#代理DNS',
  'https://dns.quad9.net/dns-query#代理DNS',
];

const RULE_PROVIDERS = {
  private_ip: {
    type: 'http',
    interval: 86400,
    proxy: '代理连接',
    behavior: 'ipcidr',
    format: 'mrs',
    url: 'https://raw.githubusercontent.com/kongbaitt/proxy/main/rules/mrs/private_ip.mrs',
    path: './rules/private_ip.mrs',
  },
  'AWAvenue-Ads': {
    type: 'http',
    interval: 86400,
    proxy: '代理连接',
    behavior: 'domain',
    format: 'mrs',
    url: 'https://anti-ad.net/mihomo.mrs',
    path: './rules/AWAvenue-Ads.mrs',
  },
  private: {
    type: 'http',
    interval: 86400,
    proxy: '代理连接',
    behavior: 'domain',
    format: 'mrs',
    url: 'https://raw.githubusercontent.com/kongbaitt/proxy/main/rules/mrs/private.mrs',
    path: './rules/private.mrs',
  },
  proxy_domain: {
    type: 'http',
    interval: 86400,
    proxy: '代理连接',
    behavior: 'domain',
    format: 'mrs',
    url: 'https://raw.githubusercontent.com/kongbaitt/proxy/main/rules/mrs/proxy_domain.mrs',
    path: './rules/proxy_domain.mrs',
  },
  direct_domain: {
    type: 'http',
    interval: 86400,
    proxy: '代理连接',
    behavior: 'domain',
    format: 'mrs',
    url: 'https://raw.githubusercontent.com/kongbaitt/proxy/main/rules/mrs/direct_domain.mrs',
    path: './rules/direct_domain.mrs',
  },
  proxy: {
    type: 'http',
    interval: 86400,
    proxy: '代理连接',
    behavior: 'domain',
    format: 'mrs',
    url: 'https://raw.githubusercontent.com/kongbaitt/proxy/main/rules/mrs/proxy.mrs',
    path: './rules/proxy.mrs',
  },
  cn: {
    type: 'http',
    interval: 86400,
    proxy: '代理连接',
    behavior: 'domain',
    format: 'mrs',
    url: 'https://raw.githubusercontent.com/kongbaitt/proxy/main/rules/mrs/cn_domain.mrs',
    path: './rules/cn.mrs',
  },
  proxy_ip: {
    type: 'http',
    interval: 86400,
    proxy: '代理连接',
    behavior: 'ipcidr',
    format: 'mrs',
    url: 'https://raw.githubusercontent.com/kongbaitt/proxy/main/rules/mrs/proxy_ip.mrs',
    path: './rules/proxy_ip.mrs',
  },
  direct_ip: {
    type: 'http',
    interval: 86400,
    proxy: '代理连接',
    behavior: 'ipcidr',
    format: 'mrs',
    url: 'https://raw.githubusercontent.com/kongbaitt/proxy/main/rules/mrs/direct_ip.mrs',
    path: './rules/direct_ip.mrs',
  },
  cn_ip: {
    type: 'http',
    interval: 86400,
    proxy: '代理连接',
    behavior: 'ipcidr',
    format: 'mrs',
    url: 'https://raw.githubusercontent.com/kongbaitt/proxy/main/rules/mrs/cn_ip.mrs',
    path: './rules/cn_ip.mrs',
  },
};

const RULES = [
  'RULE-SET,private_ip,直接连接,no-resolve',
  'RULE-SET,AWAvenue-Ads,REJECT',
  'RULE-SET,private,直接连接',
  'RULE-SET,proxy_domain,代理连接',
  'RULE-SET,direct_domain,直接连接',
  'RULE-SET,proxy,代理连接',
  'RULE-SET,cn,直接连接',
  'RULE-SET,proxy_ip,代理连接',
  'RULE-SET,direct_ip,直接连接',
  'RULE-SET,cn_ip,直接连接',
  'MATCH,代理连接',
];

const GROUP_COMMON = {
  url: HEALTHCHECK_URL,
  interval: 900,
  timeout: 3000,
  lazy: false,
  'max-failed-times': 2,
};

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function hasProviders(config) {
  return !!(
    config &&
    config['proxy-providers'] &&
    typeof config['proxy-providers'] === 'object' &&
    Object.keys(config['proxy-providers']).length
  );
}

function hasProxies(config) {
  return !!(config && Array.isArray(config.proxies) && config.proxies.length);
}

function sourceSelector(useProviders) {
  const selector = {};
  selector[useProviders ? 'include-all-providers' : 'include-all'] = true;
  return selector;
}

function getProxyNames(proxies) {
  const directNames = new Set(DIRECT_PROXIES.map((proxy) => proxy.name));
  return (proxies || [])
    .map((proxy) => proxy && proxy.name)
    .filter((name) => name && !directNames.has(name));
}

function sanitizeProxies(proxies) {
  const directNames = new Set(DIRECT_PROXIES.map((proxy) => proxy.name));
  const seen = new Set();
  const sanitized = [];

  for (const proxy of proxies || []) {
    if (!proxy || typeof proxy !== 'object' || !proxy.name) {
      continue;
    }
    if (directNames.has(proxy.name) || seen.has(proxy.name)) {
      continue;
    }
    seen.add(proxy.name);
    sanitized.push(proxy);
  }

  return sanitized.concat(clone(DIRECT_PROXIES));
}

function buildGroupsFromProxyNames(proxyNames) {
  const manualChoices = ['最低延迟', ...proxyNames];
  const serviceChoices = ['代理连接', '直接连接', '最低延迟', ...proxyNames, 'PASS', 'REJECT'];

  return [
    {
      name: '代理连接',
      type: 'select',
      proxies: manualChoices,
      icon: 'https://mihomo.echs.top/img/icon/Global.webp',
    },
    {
      name: '直接连接',
      type: 'select',
      proxies: ['DIRECT', 'IPV4优先', 'IPV6优先', '仅IPV4', '仅IPV6'],
      icon: 'https://mihomo.echs.top/img/icon/DIRECT.webp',
    },
    {
      name: '代理DNS',
      type: 'select',
      proxies: serviceChoices,
      icon: 'https://mihomo.echs.top/img/icon/Server.webp',
    },
    {
      ...GROUP_COMMON,
      name: '最低延迟',
      type: 'url-test',
      tolerance: 30,
      hidden: true,
      proxies: proxyNames,
      icon: 'https://mihomo.echs.top/img/icon/Fast.webp',
    },
  ];
}

function buildGroupsFromProviders() {
  const source = sourceSelector(true);
  const serviceChoices = ['代理连接', '直接连接', '最低延迟', 'PASS', 'REJECT'];

  return [
    {
      ...source,
      name: '代理连接',
      type: 'select',
      proxies: ['最低延迟'],
      icon: 'https://mihomo.echs.top/img/icon/Global.webp',
    },
    {
      name: '直接连接',
      type: 'select',
      proxies: ['DIRECT', 'IPV4优先', 'IPV6优先', '仅IPV4', '仅IPV6'],
      icon: 'https://mihomo.echs.top/img/icon/DIRECT.webp',
    },
    {
      ...source,
      name: '代理DNS',
      type: 'select',
      proxies: serviceChoices,
      icon: 'https://mihomo.echs.top/img/icon/Server.webp',
    },
    {
      ...GROUP_COMMON,
      ...source,
      name: '最低延迟',
      type: 'url-test',
      tolerance: 30,
      hidden: true,
      icon: 'https://mihomo.echs.top/img/icon/Fast.webp',
    },
  ];
}

function buildProxyGroups(useProviders, proxies) {
  if (!useProviders) {
    return buildGroupsFromProxyNames(getProxyNames(proxies));
  }

  return buildGroupsFromProviders();
}

function main(config) {
  if (!config || typeof config !== 'object') {
    throw new Error('配置内容为空');
  }

  const inputHasProviders = hasProviders(config);
  const inputHasProxies = hasProxies(config);

  if (!inputHasProviders && !inputHasProxies) {
    throw new Error('未找到可用节点或 proxy-providers');
  }

  config.proxies = sanitizeProxies(config.proxies);
  if (!inputHasProviders && config.proxies.length === DIRECT_PROXIES.length) {
    throw new Error('未找到可用代理节点');
  }

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
  config.profile = {
    'store-selected': true,
    'store-fake-ip': true,
  };
  config.port = 0;
  config['socks-port'] = 0;
  config['mixed-port'] = 0;
  config['tproxy-port'] = 0;
  config['redir-port'] = 0;

  config['proxy-groups'] = buildProxyGroups(inputHasProviders, config.proxies);
  config['rule-providers'] = clone(RULE_PROVIDERS);
  config.rules = RULES.slice();

  config.hosts = {
    'dns.alidns.com': ['223.5.5.5', '223.6.6.6', '2400:3200::1', '2400:3200:baba::1'],
    'doh.pub': ['120.53.53.53', '1.12.12.21'],
    'dns.google': ['8.8.8.8', '8.8.4.4', '2001:4860:4860::8888', '2001:4860:4860::8844'],
    'dns.quad9.net': ['9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9'],
    'services.googleapis.cn': 'services.googleapis.com',
    'google.cn': 'google.com',
  };

  config.dns = {
    enable: true,
    'cache-algorithm': 'arc',
    ipv6: true,
    'prefer-h3': true,
    'use-hosts': true,
    'use-system-hosts': true,
    'respect-rules': false,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'fake-ip-range6': 'fd00:bada:55ed::1/64',
    'fake-ip-filter-mode': 'rule',
    'fake-ip-filter': [
      'RULE-SET,AWAvenue-Ads,fake-ip',
      'RULE-SET,private,real-ip',
      'RULE-SET,proxy_domain,fake-ip',
      'RULE-SET,direct_domain,real-ip',
      'RULE-SET,proxy,fake-ip',
      'RULE-SET,cn,real-ip',
      'MATCH,fake-ip',
    ],
    'proxy-server-nameserver': DIRECT_DNS.slice(),
    'nameserver-policy': {
      'rule-set:AWAvenue-Ads': ['rcode://name_error'],
      'rule-set:private': DIRECT_DNS.slice(),
      'rule-set:proxy_domain': PROXY_DNS.slice(),
      'rule-set:direct_domain': DIRECT_DNS.slice(),
      'rule-set:proxy': PROXY_DNS.slice(),
      'rule-set:cn': DIRECT_DNS.slice(),
    },
    nameserver: PROXY_DNS.slice(),
    'direct-nameserver': DIRECT_DNS.slice(),
    'direct-nameserver-follow-policy': true,
  };

  config.sniffer = {
    enable: true,
    'force-dns-mapping': true,
    'parse-pure-ip': true,
    'override-destination': false,
    sniff: {
      HTTP: { ports: [80, '8080-8880'] },
      TLS: { ports: [443, 8443] },
      QUIC: { ports: [443, 8443] },
    },
    'skip-domain': ['rule-set:private'],
    'skip-src-address': ['rule-set:private_ip'],
    'skip-dst-address': ['rule-set:private_ip'],
  };

  config.tun = {
    enable: true,
    stack: 'mixed',
    'auto-route': true,
    'auto-redirect': true,
    'auto-detect-interface': true,
    'strict-route': true,
    'disable-icmp-forwarding': true,
    'dns-hijack': ['any:53', 'tcp://any:53'],
  };

  return config;
}
