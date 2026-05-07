// 默认广告拦截 mrs 地址；Sub-Store 未传参时使用这个地址
const DEFAULT_AD_RULE_URL = "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockmihomolite.mrs";

function main(config) {
  const oldProxies = config.proxies || [];
  const proxyNames = oldProxies.map(p => p.name).filter(Boolean);

  const proxyGroupName = "PROXY";
  const autoGroupName = "自动切换";
  const adGroupName = "广告拦截";

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

  // TCP Keep Alive：减少长连接空闲断开后的重连等待，提升持续使用时的稳定性
  config["keep-alive-idle"] = 600;
  config["keep-alive-interval"] = 15;

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

    // DNS 缓存算法：ARC 对重复解析更友好，可降低常用域名解析延迟
    "cache-algorithm": "arc",

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
  // 平时在 PROXY 里选“自动切换”
  // 需要固定节点时，在 PROXY 里直接选具体节点
  config["proxy-groups"] = [
    {
      name: proxyGroupName,
      type: "select",
      proxies: proxyNames.length
        ? [autoGroupName, ...proxyNames]
        : ["DIRECT"]
    },
    {
      name: autoGroupName,
      type: "fallback",
      proxies: proxyNames.length ? proxyNames : ["DIRECT"],
      url: "https://www.gstatic.com/generate_204",
      interval: 300,
      timeout: 3000,

      // 启动后主动进行健康检查，减少首次访问时才测速带来的等待
      lazy: false,

      "max-failed-times": 2
    },
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
