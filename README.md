# AdGuard_Home_Rules

---

<div align="center">
<h1>AdGuard Rule</h1>
  <p>
    一个简易的Java程序，用于合并与更新 AdGuard 过滤规则
</p>
</div>


<h2 id="a">📔 说明</h2>

本项目旨在按需求整合 `AdGuard` 规则。定时从上游订阅获取规则，去除`重复`和`不受支持`的规则并进行分类。如果存在误杀请手动放行。  
支持`AdGuard`、`AdGuard Home`,每`8小时`自动更新一次   

---

# 上游规则
<details>
<summary>点击查看</summary>
<ul>
      #常规 14个 在大多数设备上阻止跟踪和广告的列表
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt">1Hosts (Lite)</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_38.txt">1Hosts (mini)</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt">AdGuard DNS filter</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt">AdGuard DNS Popup Hosts filter</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt">AWAvenue Ads Rule</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt">Dan Pollock's List</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_34.txt">HaGeZi's Normal Blocklist</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt">HaGeZi's Pro Blocklist</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_51.txt">HaGeZi's Pro++ Blocklist</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_49.txt">HaGeZi's Ultimate Blocklist</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt">OISD Blocklist Small</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt">OISD Blocklist Big</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt">Peter Lowe's Blocklist</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt">Steven Black's List</a></li>
      #其它 9个 其他黑名单
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_39.txt">Dandelion Sprout's Anti Push Notifications</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_6.txt">Dandelion Sprout's Game Console Adblock List</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_45.txt">HaGeZi's Allowlist Referral</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_46.txt">HaGeZi's Anti-Piracy Blocklist</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_47.txt">HaGeZi's Gambling Blocklist</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_37.txt">No Google</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt">Perflyst and Dandelion Sprout's Smart-TV Blocklist</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_57.txt">ShadowWhisperer's Dating List</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_23.txt">WindowsSpyBlocker - Hosts spy rules</a></li>
      #区域 17个 专注于区域广告和跟踪服务器的列表
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt">CHN: AdRules DNS List</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt">CHN: anti-AD</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_35.txt">HUN: Hufilter</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_22.txt">IDN: ABPindo</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_19.txt">IRN: PersianBlocker list</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_43.txt">ISR: EasyList Hebrew</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_25.txt">KOR: List-KR DNS</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_15.txt">KOR: YousList</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_36.txt">LIT: EasyList Lithuania</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_20.txt">MKD: Macedonian Pi-hole Blocklist</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_13.txt">NOR: Dandelion Sprouts nordiske filtre</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_41.txt">POL: CERT Polska List of malicious domasters</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_14.txt">POL: Polish filters for Pi-hole</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_17.txt">SWE: Frellwit's Swedish Hosts File</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_26.txt">TUR: turk-adlist</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_40.txt">TUR: Turkish Ad Hosts</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_16.txt">VNM: ABPVN List</a></li>
      #安全 15个 专用于拦截恶意软件、钓鱼或欺诈域名的列表
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt">Phishing URL Blocklist (PhishTank and OpenPhish)</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt">Dandelion Sprout's Anti-Malware List</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_55.txt">HaGeZi's Badware Hoster Blocklist</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt">HaGeZi's DynDNS Blocklist</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt">HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_56.txt">HaGeZi's The World's Most Abused TLDs</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt">HaGeZi's Threat Intelligence Feeds</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt">NoCoin Filter List</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt">Phishing Army</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt">Scam Blocklist by DurableNapkin</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt">ShadowWhisperer's Malware List</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt">Stalkerware Indicators List</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt">The Big List of Hacked Malware Web Sites</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt">uBlock₀ filters – Badware risks</a></li>
    <li><a href="https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt">Malicious URL Blocklist (URLHaus)</a></li>
</ul>
</details>

---

# 本地规则
- [mylist](#)
> 主要是对上游规则的修正补充，根据日常使用体验，解除一些失误拦截

<h2 id="b">🎯 订阅</h2>

| 名称           | 说明                                                | GitHub订阅                                                                              | GitHub加速订阅                                                                        |
|--------------|---------------------------------------------------|---------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| `all.txt`    | 去重的规则合集，包含以下所有规则，适用于 `AdGuard` 客户端                | [✈️点此查看](https://raw.gitHubusercontent.com/743859910/AdGuard_Home_Rules/master/rule/all.txt)      | [🚀点此查看(延迟)](https://github.iaor.asia/https://github.com/743859910/743859910/blob/master/rule/all.txt)    |
| `adgh.txt`   | 针对 `AdGuardHome` 的规则，包含 `domaster.txt` `regex.txt`和`mylist.txt` | [✈️点此查看](https://raw.gitHubusercontent.com/743859910/AdGuard_Home_Rules/master/rule/adgh.txt)   | [🚀点此查看(延迟)](https://github.iaor.asia/https://github.com/743859910/743859910/blob/master/rule/adgh.txt)   |
| `domaster.txt` | 域名规则，`AdGuard`和`AdGuardHome`都支持                                       | [✈️点此查看](https://raw.gitHubusercontent.com/743859910/AdGuard_Home_Rules/master/rule/domaster.txt) | [🚀点此查看(延迟)](https://github.iaor.asia/https://github.com/743859910/743859910/blob/master/rule/domaster.txt) |
| `hosts.txt`  | `hosts` 规则，~~包含一些访问加速~~                           | [✈️点此查看](https://raw.gitHubusercontent.com/743859910/AdGuard_Home_Rules/master/rule/hosts.txt)  | [🚀点此查看(延迟)](https://github.iaor.asia/https://github.com/743859910/743859910/blob/master/rule/hosts.txt)  |
| `modify.txt` | 修饰规则，`AdGuard`支持                                      | [✈️点此查看](https://raw.gitHubusercontent.com/743859910/AdGuard_Home_Rules/master/rule/modify.txt) | [🚀点此查看(延迟)](https://github.iaor.asia/https://github.com/743859910/743859910/blob/master/rule/modify.txt) |
| `regex.txt` | 正则规则，`AdGuardHome`支持                                       | [✈️点此查看](https://raw.gitHubusercontent.com/743859910/AdGuard_Home_Rules/master/rule/regex.txt) | [🚀点此查看(延迟)](https://github.iaor.asia/https://github.com/743859910/743859910/blob/master/rule/regex.txt) |
| `mylist.txt` | 自用补充规则，人工更新                                       | [✈️点此查看](https://raw.gitHubusercontent.com/743859910/AdGuard_Home_Rules/master/rule/mylist.txt) | [🚀点此查看(延迟)](https://github.iaor.asia/https://github.com/743859910/743859910/blob/master/rule/mylist.txt) |

<br/>
<h2 id="c">🛠️ 配置</h2>

---

# 示例配置
```yaml
application:
  rule:       
    #远程规则订阅，仅支持http、https
    remote:
      - 'https://example.com/list.txt'
    #本地规则，请将文件移动到项目路径rule目录中
    local: 
      - 'mylist.txt'
  output:
    path: rule   #规则文件输出路径，相对路径默认从 项目目录开始
    files:
      all.txt:    #输出文件名
        - DOmaster  #域名规则，仅完整域名
        - REGEX   #正则规则，包含正则的域名规则，AdGH支持
        - MODIFY  #修饰规则，添加了一些修饰符号的规则，AdG支持
        - HOSTS   #Hosts规则
```

---

# 使用 GitHub Action
- fork本项目
- 参照示例配置，修改配置文件: `src/master/resources/application.yml`，注意本地规则文件应放入项目根目录 `rule` 文件夹
- 编辑 `.GitHub/workflows/auto-update.yml` 文件，将 `Commit Changes` 区块下邮箱与用户名修改为自己的（GitHub邮箱与用户名）
- 提交所有修改并等待 `GitHub Action` 执行，执行完成后相应规则生成在配置中指定的目录下

---

- 👉 特别感谢@fordes123
- 👉 特别感谢@hululu1068

---

<p align="center">
  <img src="https://raw.gitmirror.com/743859910/AdGuard_Home_Rules/master/img/1.webp">
</p>

<p align="center">
  <img src="https://raw.gitmirror.com/743859910/AdGuard_Home_Rules/master/img/2.webp">
</p>

<p align="center">
  <img src="https://raw.gitmirror.com/743859910/AdGuard_Home_Rules/master/img/3.webp">
</p>

<p align="center">
  <img src="https://raw.gitmirror.com/743859910/AdGuard_Home_Rules/master/img/4.webp">
</p>

<p align="center">
  <img src="https://raw.gitmirror.com/743859910/AdGuard_Home_Rules/master/img/5.webp">
</p>

---

![Visitor Count](https://profile-counter.glitch.me/{AdGuard_Home_Rules}/count.svg)

---

昵称：我只是你的过客

个性签名：每个人都是每个人的过客

国籍：中华人民共和国 / 现居：中国湖北省武汉市

---

MIT License

Copyright © 2008-2024 Powered by 743859910. Inc. All Rights Reserved. 我只是你的过客工作室. 版权所有

---
