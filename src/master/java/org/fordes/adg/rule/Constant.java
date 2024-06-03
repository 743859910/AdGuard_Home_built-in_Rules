package org.fordes.adg.rule;

import java.io.File;

public class Constant {

    public static final String ROOT_PATH = System.getProperty("user.dir");

    public static final String UPDATE = "# Update time: {}\r\n";

    public static final String REPO = "# Repo URL: AdGuard、AdGuardHome广告过滤规则合并/去重\r\n\r\n###################################   合并/去重自以下规则   ####################################\r\n# - 'https://cdn.jsdelivr.net/gh/hoshsadiq/adblock-nocoin-list/hosts.txt'  #adblock-nocoin-list\r\n# - 'https://cdn.jsdelivr.net/gh/durablenapkin/scamblocklist/adguard.txt' #Scam Blocklist\r\n# - 'https://someonewhocares.org/hosts/zero/hosts' #Dan Pollock's List\r\n# - 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=1&mimetype=plaintext' #Peter Lowe's List\r\n# - 'https://abp.oisd.nl/basic/' #OISD Blocklist Basic\r\n# - 'https://cdn.jsdelivr.net/gh/crazy-max/WindowsSpyBlocker/data/hosts/spy.txt' #WindowsSpyBlocker\r\n# - 'https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts' #大圣净化\r\n# - 'https://code.gitlink.org.cn/hacamer/AdRules/raw/branch/master/adguard-full.txt' #AdRules AdGuard Full List\r\n# - 'https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt' #adguard base\r\n# 自用添加↓\r\n# - 'https://anti-ad.net/easylist.txt' #name: anti-AD\r\n# - 'https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/combined_disguised_trackers.txt' #name: AdGuard CNAME 伪装跟踪器列表\r\n# - 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt' #name: AdGuard DNS filter\r\n# - 'https://raw.githubusercontent.com/Crystal-RainSlide/AdditionalFiltersCN/master/CN.txt' #name: AdditionalFiltersCN\r\n# - 'https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt' #name: ADgk 移动广告规则\r\n# - 'https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt' #name: 乘风 广告过滤规则\r\n# - 'https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt' #name: 乘风 视频过滤规则\r\n# - 'https://raw.githubusercontent.com/o0HalfLife0o/list/master/ad.txt' #name: HalfLife_合并自乘风视频广告过滤规则、EasylistChina、EasylistLite、CJX'sAnnoyance\r\n# - 'https://adaway.org/hosts.txt' #name: AdAway 官方的去广告 Host 规则\r\n# - 'https://easylist-downloads.adblockplus.org/antiadblockfilters.txt' #name: 去除禁止广告拦截提示规则\r\n# - 'https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts.txt' #name: Yhosts规则\r\n# - 'https://raw.githubusercontent.com/Cats-Team/AdRules/master/dns.txt' #name: 杏稍AdRules DNS List\r\n# - 'https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/AdGuard/Advertising/Advertising.txt' #name: AdGuard_blackmatrix7合并\r\n# - 'https://raw.githubusercontent.com/zsakvo/AdGuard-Custom-Rule/master/rule/zhihu.txt' #name: 知乎 普通版\r\n# - 'https://github.com/217heidai/adblockfilters' #name: 217heidai/adblockfilters去重合并(比较大)\r\n# - 'https://raw.githubusercontents.com/timlu85/AdGuard-Home_Youtube-Adfilter/master/Youtube-Adfilter-Web.txt' #name: Youtube-Adfilter-Web\r\n# - 'https://raw.githubusercontents.com/91ajames/ublock-filters-ulist-youtube/master/blocklist.txt' #name: ublock-filters-ulist-youtube\r\n# KoolProxy规则\r\n# - 'https://raw.iqiq.io/ilxp/koolproxy/master/rules/koolproxy.txt' #name:静态规则\r\n# - 'https://raw.iqiq.io/ilxp/koolproxy/master/rules/daily.txt' #name:每日规则\r\n# - 'https://raw.iqiq.io/ilxp/koolproxy/master/rules/steven.txt' #name:StevenBlack规则\r\n# uBlock内置规则\r\n# - 'https://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@master/filters/filters.txt' #name: uBlock filters\r\n# - 'https://ublockorigin.pages.dev/filters/badware.txt' #name: uBlock filters – Badware risks\r\n# - 'https://gitcdn.link/cdn/uBlockOrigin/uAssetsCDN/master/filters/privacy.txt' #name: uBlock filters – Privacy\r\n# - 'https://ublockorigin.github.io/uAssets/filters/quick-fixes.txt' #name: uBlock filters – Quick fixes\r\n# - 'https://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/master/filters/resource-abuse.txt' #name: uBlock filters – Resource abuse\r\n# - 'https://gitcdn.link/cdn/uBlockOrigin/uAssetsCDN/master/filters/unbreak.txt' #name: uBlock filters – Unbreak\r\n# - 'https://filters.adtidy.org/extension/ublock/filters/11.txt' #name: AdGuard Mobile Ads移动设备\r\n# 本地规则\r\n# - 'mylist.txt'\r\n###############################################################################################\r\n\r\n# 每8小时同步一次、如有误杀、请手动解除\r\n\r\n";

    public static final String LOCAL_RULE_SUFFIX = ROOT_PATH + File.separator + "rule";

    /**
     * 基本的有效性检测正则，!开头，[]包裹，非特殊标记的#号开头均视为无效规则
     */
    public static final String EFFICIENT_REGEX = "^!|^#[^#,^@,^%,^\\$]|^\\[.*\\]$";

    /**
     * 去除首尾基础修饰符号 的正则，方便对规则进行分类
     * 包含：@@、||、@@||、/ 开头，$important、/ 结尾
     */
    public static final String BASIC_MODIFY_REGEX = "^@@\\|\\||^\\|\\||^@@|\\$important$|\\s#[^#]*$";

}
保留这一行



      #常规 14个 在大多数设备上阻止跟踪和广告的列表↓\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt- ' #name: 1Hosts (Lite)\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_38.txt- ' #name: 1Hosts (mini)\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt- ' #name: AdGuard DNS filter\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt- ' #name: AdGuard DNS Popup Hosts filter\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt- ' #name: AWAvenue Ads Rule\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt- ' #name: Dan Pollock- 's List\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_34.txt- ' #name: HaGeZi- 's Normal Blocklist\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt- ' #name: HaGeZi- 's Pro Blocklist\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_51.txt- ' #name: HaGeZi- 's Pro++ Blocklist\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_49.txt- ' #name: HaGeZi- 's Ultimate Blocklist\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt- ' #name: OISD Blocklist Small\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt- ' #name: OISD Blocklist Big\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt- ' #name: Peter Lowe- 's Blocklist\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt- ' #name: Steven Black- 's List\r\n# 
      #其它 9个 其他黑名单↓\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_39.txt- ' #name: Dandelion Sprout- 's Anti Push Notifications\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_6.txt- ' #name: Dandelion Sprout- 's Game Console Adblock List\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_45.txt- ' #name: HaGeZi- 's Allowlist Referral\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_46.txt- ' #name: HaGeZi- 's Anti-Piracy Blocklist\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_47.txt- ' #name: HaGeZi- 's Gambling Blocklist\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_37.txt- ' #name: No Google\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt- ' #name: Perflyst and Dandelion Sprout- 's Smart-TV Blocklist\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_57.txt- ' #name: ShadowWhisperer- 's Dating List\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_23.txt- ' #name: WindowsSpyBlocker - - '- '- 'Hosts spy rules\r\n# 
      #区域 17个 专注于区域广告和跟踪服务器的列表↓\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt- ' #name: CHN: AdRules DNS List\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt- ' #name: CHN: anti-AD\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_35.txt- ' #name: HUN: Hufilter\r\n# - 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_22.txt- ' #name: IDN: ABPindo\r\n# - 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_19.txt- ' #name: IRN: PersianBlocker list\r\n# - 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_43.txt- ' #name: ISR: EasyList Hebrew\r\n# - 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_25.txt- ' #name: KOR: List-KR DNS\r\n# - 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_15.txt- ' #name: KOR: YousList\r\n# - 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_36.txt- ' #name: LIT: EasyList Lithuania\r\n# - 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_20.txt- ' #name: MKD: Macedonian Pi-hole Blocklist\r\n# - 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_13.txt- ' #name: NOR: Dandelion Sprouts nordiske filtre\r\n# - 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_41.txt- ' #name: POL: CERT Polska List of malicious domasters\r\n# - 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_14.txt- ' #name: POL: Polish filters for Pi-hole\r\n# - 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_17.txt- ' #name: SWE: Frellwit- 's Swedish Hosts File\r\n# - 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_26.txt- ' #name: TUR: turk-adlist\r\n# - 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_40.txt- ' #name: TUR: Turkish Ad Hosts\r\n# - 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_16.txt- ' #name: VNM: ABPVN List\r\n# 
      #安全 15个 专用于拦截恶意软件、钓鱼或欺诈域名的列表↓\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt- ' #name: Phishing URL Blocklist (PhishTank and OpenPhish)\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt- ' #name: Dandelion Sprout- 's Anti-Malware List\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_55.txt- ' #name: HaGeZi- 's Badware Hoster Blocklist\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt- ' #name: HaGeZi- 's DynDNS Blocklist\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt- ' #name: HaGeZi- 's Encrypted DNS/VPN/TOR/Proxy Bypass\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_56.txt- ' #name: HaGeZi- 's The World- 's Most Abused TLDs\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt- ' #name: HaGeZi- 's Threat Intelligence Feeds\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt- ' #name: NoCoin Filter List\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt- ' #name: Phishing Army\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt- ' #name: Scam Blocklist by DurableNapkin\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt- ' #name: ShadowWhisperer- 's Malware List\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt- ' #name: Stalkerware Indicators List\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt- ' #name: The Big List of Hacked Malware Web Sites\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt- ' #name: uBlock₀ filters – Badware risks\r\n# 
- 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt- ' #name: Malicious URL Blocklist (URLHaus)\r\n# 