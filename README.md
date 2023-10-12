# nsloc

一个用于统计分析域名大致位置(域名托管服务器 IP 所属国家)的小工具。

## 使用

1. 预处理原始域名列表(比如: 从 DNS 请求日志中提取的域名表。包含多级域名。特殊字符域名。重复域名。。。)。过滤出 Public Suffix 的下一级域名 (可注册的域名)。

    ```sh
    nsloc preprocessing --psl psl.txt [--out psn.txt] raw_domain_list.txt ...
    ```

    - psl: 是 [Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat)。需要下载。
    - out: 输出文件。
    - raw_domain_list.txt: 域名表文件。可有多个。

2. 扫描域名的托管服务器 IP ，并识别其所属国家。

    ```sh
    nsloc scan -i input.txt -g geoip-country.mmdb [--cc 20] [--sps 100] [--out out.jsonl] [-u 8.8.8.8:53]
    ```

    - i: 输入文件。一般是 Public Suffix 的下一级域名构成的域名表 (aka. 上一步的 psn.txt)。
    - g: MaxMind mmdb 数据库。需要包含 country 数据。
    - cc: 扫描线程。
    - sps: 最大每秒扫描域名数。注意: 实际 DNS 请求数为该数值的 3~7 倍。
    - out: 输出文件。
    - u: 上游服务器地址。必需 IP，端口号不可省略。-u 参数出现多次。会随机请求。

## scan 输出格式

scan 输出一个 jsonl。每个域名扫描结果是一行 json。

示例和说明。

```jsonc
{
    "fqdn": "cloudflare.com.", // 扫描的域名。
    "elapsed_ms": 172, // 扫描用时。毫秒。
    "nss": [ // 域名所在服务器。可能为空。
        "ns3.cloudflare.com.",
        "ns4.cloudflare.com."
    ],
    "ns_addrs": [ // 域名所在服务器的 IP 地址。可能为空。
        "162.159.0.33",
        "2400:cb00:2049:1::a29f:837"
    ],
    "locs": [ // 根据 IP 识别出的 ISO_3166-1 国家代码。可能为空。
        "CA",
        "US"
    ],
    "errs": [ // 扫描遇到的错误。可能为空。
        "failed to lookup main ns, bad rcode 2"
    ]
}
```

## 其他

- 公共递归服务器有很低的 qps 限制。如果遇到大量报错，或者需要扫描大量域名，建议自建递归服务器。
