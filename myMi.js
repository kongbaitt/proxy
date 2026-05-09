// 默认广告拦截 mrs 地址；Sub-Store 未传参时使用这个地址
const DEFAULT_AD_RULE_URL = "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockmihomo.mrs";

// 自动测速地址：用于判断同一服务器内哪个节点当前更可用
const AUTO_TEST_URL = "https://www.gstatic.com/generate_204";

// 按节点的 server 字段分组，尽量保证自动切换只发生在同一个出口 IP / 同一台服务器内
function buildServerAutoGroups(proxies, groupPrefix) {
  const serverMap = new Map();

  for (const proxy of proxies) {
    if (!proxy || !proxy.name) continue;

    // 大多数订阅里，同一个 server 基本代表同一个服务器 IP 或域名
    const server = proxy.server || "未知服务器";

    if (!serverMap.has(server)) {
      serverMap.set(server, []);
    }

    serverMap.get(server).push(proxy.name);
  }

  return Array.from(serverMap.entries()).map(([server, names]) => ({
    name: `${groupPrefix}-${server}`,
    type: "url-test",
    proxies: names,
    url: AUTO_TEST_URL,

    // 手机端保守测速：每 5 分钟测速一次，降低耗电和频繁切换
    interval: 300,
    timeout: 2000,

    // 延迟差超过 100ms 才倾向切换，避免同服务器内节点来回跳
    tolerance: 100,

    // 懒测速：主要在当前分组被使用时测速，减少手机端后台耗电和流量消耗
    lazy: true
  }));
}

function main(config) {
  const oldProxies = config.proxies || [];
  const proxyNames = oldProxies.map(p => p.name).filter(Boolean);

  const proxyGroupName = "PROXY";
  const autoGroupPrefix = "自动切换";
  const adGroupName = "广告拦截";
  const serverAutoGroups = buildServerAutoGroups(oldProxies, autoGroupPrefix);
  const serverAutoGroupNames = serverAutoGroups.map(group => group.name);

  // 基础设置
  config.mode = "rule";
  config["allow-lan"] = true;
  config["bind-address"] = "*";
  config["log-level"] = "warning";
  config.ipv6 = false;
  config["unified-delay"] = true;
  config["tcp-concurrent"] = true;
  config["find-process-mode"] = "strict";
  config["global-client-fingerprint"] = "chrome";

  // 减少 fake-ip 持久化占用
  config.profile = {
    ...(config.profile || {}),
    "store-selected": true,
    "store-fake-ip": false
  };

  // TUN 接管流量和 DNS
  config.tun = {
    enable: true,
    stack: "mixed",
    "auto-route": true,
    "auto-detect-interface": true,
    "strict-route": true,
    "dns-hijack": [
      "any:53",
      "tcp://any:53"
    ]
  };

  // DNS 防泄露配置
  config.dns = {
    enable: true,
    listen: "0.0.0.0:1053",
    ipv6: false,
    "prefer-h3": false,
    "respect-rules": true,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",

    "fake-ip-filter": [
      "*.lan",
      "*.local",
      "localhost.ptlogin2.qq.com",
      "+.msftconnecttest.com",
      "+.msftncsi.com",
      "time.*.com",
      "time.*.gov",
      "time.*.edu.cn",
      "time.*.apple.com",
      "ntp.*.com",
      "ntp1.*.com",
      "ntp2.*.com",
      "ntp3.*.com",
      "ntp4.*.com",
      "ntp5.*.com",
      "ntp6.*.com",
      "ntp7.*.com",
      "+.pool.ntp.org",
      "+.stun.*.*",
      "+.stun.*.*.*"
    ],

    // 启动阶段解析 DNS 服务器、代理服务器域名
    "default-nameserver": [
      "223.5.5.5",
      "119.29.29.29"
    ],

    // 解析机场节点域名
    "proxy-server-nameserver": [
      "223.5.5.5",
      "119.29.29.29"
    ],

    // 直连域名解析用国内 DNS
    "direct-nameserver": [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ],

    // 默认 DNS，国内 App 速度优先
    nameserver: [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ],

    // 国内域名用国内 DNS，国外域名用国外 DNS
    "nameserver-policy": {
      "geosite:cn": [
        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query"
      ],
      "geosite:private": [
        "system"
      ],
      "geosite:geolocation-!cn": [
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/dns-query"
      ]
    },

    fallback: [
      "https://1.1.1.1/dns-query",
      "https://8.8.8.8/dns-query"
    ],

    "fallback-filter": {
      geoip: true,
      "geoip-code": "CN",
      ipcidr: [
        "240.0.0.0/4"
      ]
    }
  };

  // 全部规则集使用 mrs
  config["rule-providers"] = {
    ...(config["rule-providers"] || {}),

    // 广告拦截 mrs
    antiAD: {
      type: "http",
      behavior: "domain",
      format: "mrs",
      path: "./ruleset/anti-ad.mrs",
      url: DEFAULT_AD_RULE_URL,
      interval: 86400
    },

    // 国内域名
    cn_domain: {
      type: "http",
      behavior: "domain",
      format: "mrs",
      path: "./ruleset/cn_domain.mrs",
      url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs",
      interval: 86400
    },

    // 私有 IP
    private_ip: {
      type: "http",
      behavior: "ipcidr",
      format: "mrs",
      path: "./ruleset/private_ip.mrs",
      url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/private.mrs",
      interval: 86400
    },

    // 国内 IP
    cn_ip: {
      type: "http",
      behavior: "ipcidr",
      format: "mrs",
      path: "./ruleset/cn_ip.mrs",
      url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs",
      interval: 86400
    }
  };

  // 代理组
  // PROXY 是真正生效的总入口
  // 平时在 PROXY 里选择某个“自动切换-服务器”分组，只在同服务器内自动测速切换
  // 需要固定节点时，在 PROXY 里也保留具体节点可选
  config["proxy-groups"] = [
    {
      name: proxyGroupName,
      type: "select",
      proxies: serverAutoGroupNames.length
        ? [...serverAutoGroupNames, ...proxyNames]
        : ["DIRECT"]
    },
    ...serverAutoGroups,
    {
      name: adGroupName,
      type: "select",
      proxies: ["REJECT", "DIRECT"]
    }
  ];

  // 极简规则
  config.rules = [
    // 广告拦截
    "RULE-SET,antiAD,广告拦截",

    // 局域网 / 私有域名
    "DOMAIN-SUFFIX,local,DIRECT",
    "DOMAIN-SUFFIX,lan,DIRECT",

    // 私有 IP
    "RULE-SET,private_ip,DIRECT,no-resolve",

    // 国内域名直连
    "RULE-SET,cn_domain,DIRECT",

    // 国内 IP 直连
    "RULE-SET,cn_ip,DIRECT,no-resolve",

    // 其它全部代理
    "MATCH,PROXY"
  ];

  return config;
}
