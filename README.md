# nsloc

一个用于统计分析域名大致位置(域名托管服务器 IP 所属国家)的小工具。

## 使用

1. 预处理原始域名列表(比如: 从 DNS 请求日志中提取的域名表。包含多级域名。重复域名。)。会进行 ascii 转换。过滤出 Public Suffix 的下一级域名。

    ```sh
    nsloc preprocessing --psl psl.txt [--out psn.txt] raw_domain_list.txt ...
    ```

    - psl: 是 [Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat/)。需要下载。
    - out: 输出文件。
    - raw_domain_list.txt: 域名表文件。可有多个。

2. 扫描域名的托管服务器 IP ，并识别其所属国家。

    ```sh
    nsloc scan -i input.txt -g geoip-country.mmdb [--cc 20] [--sps 100] [--out out.jsonl] [-u 8.8.8.8:53]
    ```

    - i: 输入文件。一般是 Public Suffix 的下一级域名构成的域名表 (aka. 上一步的 psn.txt)。
    - g: MaxMind mmdb 数据库。需要包含 country 数据。
    - cc: 扫描线程。
    - sps: 最大每秒扫描域名数。注意: 实际 DNS 请求数为该数值的 3 倍。
    - out: 输出文件。
    - u: 上游服务器地址。必需 IP，端口号不可省略。-u 参数出现多次。会随机请求。

## scan 输出格式

scan 输出一个 jsonl。每个域名扫描结果是一行 json。

示例和说明。

```jsonc
{
    "fqdn": "google.com.",   // 扫描的域名。
    "ns": "ns1.google.com.", // 域名的主服务器。可能为空。
    "loc": [   // 根据 IP 识别出的位置。是 ISO_3166-1 国家代码。可能为空。
        "US"
    ],
    "elapsed_ms": 1, // 扫描用时。毫秒。
    "ns_addr": [     // 域名主服务器的 IP 地址。可能为空。
        "216.239.32.10",
        "2001:4860:4802:32::a"
    ],
    "errs": [ // 扫描遇到的错误。
        "failed to lookup main ns, bad rcode 2"
    ]
}
```

## 其他

- scan 请求域名托管服务器 (aka. NS) 的方式是请求 SOA 记录。
