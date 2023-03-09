# -*- coding: utf-8 -*-
import requests
info_list=[]
info_dict={'C2': '远控', 'Botnet': '僵尸网络', 'Hijacked': '劫持', 'Phishing': '钓鱼', 'Malware': '恶意软件', 'Exploit': '漏洞利用', 'Scanner': '扫描', 'Zombie': '傀儡机', 'Spam': '垃圾邮件', 'Suspicious': '可疑', 'Compromised': '失陷主机', 'Whitelist': '白名单', 'Brute Force': '暴力破解', 'Proxy': '代理', 'Info': '基础信息', 'MiningPool': '矿池', 'CoinMiner': '私有矿池', 'suspicious_application': '可疑恶意软件', 'suspicious_website': '可疑恶意站点', 'Fakewebsite': '仿冒网站', 'Sinkhole C2': '安全机构接管 C2', 'SSH Brute Force': 'SSH暴力破解', 'FTP Brute Force': 'FTP暴力破解', 'SMTP Brute Force': 'SMTP 暴力破解', 'Http Brute Force': 'HTTP AUTH暴力破解', 'Web Login Brute Force': '撞库', 'HTTP Proxy': 'HTTP Proxy', 'HTTP Proxy In': 'HTTP代理入口', 'HTTP Proxy Out': 'HTTP代理出口', 'Socks Proxy': 'Socks代理', 'Socks Proxy In': 'Socks代理入口', 'Socks Proxy Out': 'Socks代理出口', 'VPN': 'VPN代理', 'VPN In': 'VPN入口', 'VPN Out': 'VPN出口', 'Tor': 'Tor代理', 'Tor Proxy In': 'Tor入口', 'Tor Proxy Out': 'Tor出口', 'Bogon': '保留地址', 'FullBogon': '未启用IP', 'Gateway': '网关', 'IDC': 'IDC服务器', 'Dynamic IP': '动态IP', 'Edu': '教育', 'DDNS': '动态域名', 'Mobile': '移动基站', 'Search Engine Crawler': '搜索引擎爬虫', 'CDN': 'CDN服务器', 'Advertisement': '广告', 'DNS': 'DNS服务器', 'BTtracker': 'BT服务器', 'Backbone': '骨干网', 'ICP': 'ICP备案', 'IOT Device': '物联网设备', 'Web Plug Deployed': '部署网站插件', 'Gameserver': '游戏服务器','critical': '严重','high': '高','medium':'中','low':'低','info':'无威胁','University': '学校单位', 'Mobile Network': '移动网络', 'Unused': '已路由-未使用', 'Unrouted': '已分配-未路由', 'WLAN': 'WLAN', 'Anycast': 'Anycast', 'Infrastructure': '基础设施', 'Internet Exchange': '交换中心', 'Company': '企业专线', 'Hosting': '数据中心', 'Satellite Communication': '卫星通信', 'Residence': '住宅用户', 'Special Export': '专用出口', 'Institution': '组织机构', 'Cloud Provider': '云厂商','China Mobile':'中国移动','China Unicom':'中国联通','China Telecom':'中国电信'}

def zh(word):
  try:
    return info_dict[word]
  except:
    return word


url = "https://api.threatbook.cn/v3/scene/ip_reputation"

def chaxun(ip):
  query = {
    "apikey":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "resource":ip
  }

  response = requests.request("GET", url, params=query)


  ip_info = response.json()['data']

  ip=''
  for key in ip_info.keys():
    ip=key
  


  wxqb = ''
  if(len(ip_info[ip]['judgments']))>0:
    for i in ip_info[ip]['judgments']:
      word = zh(i)
      wxqb += word+' '


  gs=''
  jwd=''
  if bool(ip_info[ip]['basic']['location']):
    gs_list = ip_info[ip]['basic']['location']
    gs += ip_info[ip]['basic']['location']['country']+' '+ip_info[ip]['basic']['location']['province']+' '+ip_info[ip]['basic']['location']['city']
    jwd += ip_info[ip]['basic']['location']['lng']+" "+ip_info[ip]['basic']['location']['lat']
  
  yys = ''
  if bool(ip_info[ip]['basic']):
    yys+=zh(ip_info[ip]['basic']['carrier'])



  eyip = ''
  if ip_info[ip]['is_malicious']:
    eyip ='是'
  else:
    eyip ='否'


  aqsjxi = ''
  if len(ip_info[ip]['tags_classes'])>0:
    for i in ip_info[ip]['tags_classes'][0]['tags']:
      aqsjxi += i+' '
    aqsjxi += ip_info[ip]['tags_classes'][0]['tags_type']
  
  asn = ''
  if bool(ip_info[ip]['asn']):
    asn += ip_info[ip]['asn']['info']
  kxd = zh(ip_info[ip]['confidence_level'])
  severity = zh(ip_info[ip]['severity'])
  scene = zh(ip_info[ip]['scene'])
  update_time = ip_info[ip]['update_time']

  



  
  print("查询IP:\033[32m {}\033[0m".format(ip))
  print("威胁情报:\033[32m {}\033[0m".format(wxqb))
  print("归属:\033[32m {}\033[0m".format(gs))
  print("运营商:\033[32m {}\033[0m".format(yys))
  print("安全事件信息:\033[32m {}\033[0m".format(aqsjxi))
  print("是否恶意IP:\033[32m {}\033[0m".format(eyip))
  print("经纬度:\033[32m {}\033[0m".format(jwd))
  print("ASN:\033[32m {}\033[0m".format(asn))
  print("可信度:\033[32m {}\033[0m".format(kxd))
  print("情报危害程度:\033[32m {}\033[0m".format(severity))
  print("应用场景:\033[32m {}\033[0m".format(scene))
  print("最近更新时间:\033[32m {}\033[0m".format(update_time))
  print()

  str_info = ip+";"+wxqb+";"+gs+";"+yys+";"+aqsjxi+";"+eyip+";"+jwd+";"+asn+";"+kxd+";"+severity+";"+scene+";"+update_time

  info_list.append(str_info)


def write_info():
  print("[!]\033[32m查询{}条结果...\033[0m".format(len(info_list)))

  with open('search_result.txt', 'a+', encoding='utf-8') as f:
    f.seek(0)
    f.truncate()
    for i in info_list:
      f.write(i+'\n')
  print("\033[32m查询结果已写入search_result.txt\033[0m")

if __name__ == '__main__':
  import argparse
  parser = argparse.ArgumentParser(description='微步API情报查询\n Author:laohuan12138')
  parser.add_argument('-i', '--ip', help='IP地址 127.0.0.1')
  parser.add_argument('-f','--file',help="包含ip地址的txt,每个IP一行 ip.txt")
  args = parser.parse_args()

  if not args.ip and not args.file:
    print("\033[31m请输入-h查看帮助信息\n\033[0m")

  if args.ip:
    ip = args.ip
    chaxun(ip.strip())

  if args.file:
    ip_file = args.file
    with open(ip_file, 'r', encoding='utf-8') as f:
      for i in f:
        chaxun(i.strip())
    write_info()

 


















