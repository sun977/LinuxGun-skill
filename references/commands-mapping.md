# Linux 应急响应命令映射表

本文档提供各检查项到具体Linux命令的完整映射。命令按排查流程和检查项分类。

> 💡 **使用提示**：先在 `workflows.md` 中查找需要的检查项，再到本文档找到对应命令。

---

## 1. 系统信息排查

### IP 地址与网络基础
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| IP地址 | `ip -br a` | `<iface> <state> <ip/cidr> ...` | 未知网卡、异常公网IP、非预期路由 |
| 路由信息 | `ip route` | `default via <gw> dev <iface>` | 默认网关是否异常 |
| 主机名 | `hostname` | 主机名 | 主机名是否符合预期 |

### 系统基础信息
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| 内核版本 | `uname -a` | `Linux <host> <kernel> ...` | 判断已知漏洞面、内核版本异常 |
| 系统汇总 | `hostnamectl` | `Operating System: ...` | 主机名、内核、虚拟化等信息 |
| 发行版本 | `cat /etc/os-release` | `ID=<distro>` | 发行版与版本号 |
| 登录banner | `cat /etc/issue` | 登录前提示信息 | 是否被篡改 |
| 虚拟化类型 | `systemd-detect-virt` | `kvm\|vmware\|docker\|none` | 是否容器/云主机 |
| Hypervisor | `lscpu \| grep -i hypervisor` | 是否有Hypervisor提示 | 虚拟化检测补充 |

### 用户信息分析
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| 当前登录用户 | `w` | `USER TTY FROM LOGIN@ ...` | 陌生IP、异常登录时间、异常终端 |
| 登录用户列表 | `who` | 当前登录用户列表 | 用户来源信息 |
| 最近登录历史 | `last -n 20` | `<user> <tty> <from> <time>` | 结合日志确认爆破/异地登录 |
| 失败登录 | `lastb -n 20` | 失败登录记录 | 暴力破解痕迹 |
| 全部用户 | `cat /etc/passwd` | 用户:口令:UID:GID:注释:家目录:Shell | 异常UID/GID、异常Shell |
| 可登录用户 | `awk -F: '$7 !~ /(nologin\|false)$/ {print $1"\t"$3"\t"$7}' /etc/passwd` | 用户名 UID Shell | 应当有登录shell的用户 |
| **UID=0用户** | `awk -F: '$3==0{print $1}' /etc/passwd` | 用户名列表 | 除root外出现即高风险 |
| **重复UID** | `cut -d: -f3 /etc/passwd \| sort \| uniq -d` | UID列表 | 克隆账号线索 |
| 非系统用户 | `awk -F: '$3>=1000 && $3<65534 {print $1"\t"$3"\t"$7}' /etc/passwd` | 用户 UID Shell | 依据发行版调整阈值（部分系统500起） |
| **空口令用户** | `awk -F: '($2==""){print $1}' /etc/shadow` | 用户名列表 | 直接可被登录利用 |
| 口令未加密 | `awk -F: '($2!="x"){print $1"\t"$2}' /etc/passwd` | 用户 口令 | 现代系统应为x |

### 用户组分析
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| 全部组 | `cat /etc/group` | 组名:口令:GID:成员列表 | 组信息概览 |
| 特权组 | `egrep '^(sudo\|wheel):' /etc/group` | 特权组成员 | 成员是否异常增加 |
| **重复GID** | `cut -d: -f3 /etc/group \| sort \| uniq -d` | GID列表 | 结合组名/成员变化定位异常 |

### 计划任务分析
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| 系统cron配置 | `cat /etc/crontab` | `分 时 日 月 周 用户 命令` | 可疑下载/执行 |
| 系统cron目录 | `ls -la /etc/cron.*` | 目录内容 | 各周期任务文件 |
| 当前用户cron | `crontab -l` | 用户定时任务 | 当前定时任务 |
| 全部用户cron | `ls -la /var/spool/cron/` | 用户cron文件列表 | 可能存在异常用户任务 |

### 历史命令分析
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| 当前会话历史 | `history \| tail -200` | 序号 命令 | 近期操作概览 |
| bash历史（当前） | `cat ~/.bash_history 2>/dev/null \| tail -200` | 逐行命令 | 当前用户行为 |
| bash历史（root） | `cat /root/.bash_history 2>/dev/null \| tail -200` | 逐行命令 | root用户行为 |
| 脚本下载行 | `grep -Ein '(^\|[[:space:]])(wget\|curl)[[:space:]]' ~/.bash_history /root/.bash_history 2>/dev/null` | 命令匹配行 | 下载行为，结合落地文件确认 |
| 临时文件近24h | `find /tmp /var/tmp /dev/shm -maxdepth 2 -type f -mmin -1440 2>/dev/null` | 文件路径 | 可能的落地文件 |
| 文件传输行 | `grep -Ein '(^\|[[:space:]])(scp\|sftp\|ftp\|tftp\|rsync)[[:space:]]' ~/.bash_history /root/.bash_history 2>/dev/null` | 命令匹配行 | 文件传输行为，查对端IP |
| 账号操作行 | `grep -Ein '(^\|[[:space:]])(useradd\|userdel\|usermod\|groupadd\|groupdel\|passwd\|chage)[[:space:]]' ~/.bash_history /root/.bash_history 2>/dev/null` | 命令匹配行 | 结合passwd/group修改时间、日志验证 |
| 黑客工具行 | `grep -Ein '(^\|[[:space:]])(nc\|ncat\|netcat\|socat\|proxychains\|frp\|ngrok\|msfconsole\|nmap)[[:space:]]' ~/.bash_history /root/.bash_history 2>/dev/null` | 命令匹配行 | 命中后查进程/端口/二进制 |
| 敏感命令行 | `grep -Ein '(^\|[[:space:]])(chmod\|chattr\|iptables\|nft\|firewall-cmd\|setenforce\|getenforce\|crontab\|systemctl)[[:space:]]' ~/.bash_history /root/.bash_history 2>/dev/null` | 命令匹配行 | 定位持久化、清痕、关闭防护行为 |
| 所有历史文件 | `find / -maxdepth 4 -type f -name '.*history' 2>/dev/null` | 文件路径列表 | 不同shell的历史文件 |
| 所有用户bash历史 | `for f in /home/*/.bash_history /root/.bash_history; do [ -e "$f" ] && echo "===== $f =====" && tail -200 "$f"; done 2>/dev/null` | 按文件分段 | 区分不同用户行为 |
| 数据库操作行 | `grep -Ein '(^\|[[:space:]])(mysql\|mysqldump\|psql\|redis-cli\|mongo\|mongosh)[[:space:]]' ~/.bash_history /root/.bash_history 2>/dev/null` | 命令匹配行 | 数据访问/导出，结合审计/慢日志 |

---

## 2. 网络连接排查

### 网络基础分析
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| ARP邻居表 | `ip neigh` | `<ip> dev <iface> lladdr <mac> REACHABLE` | 同一IP对应MAC频繁变化 |
| ARP缓存（旧） | `arp -an 2>/dev/null` | IP MAC类型状态 | 辅助ARP分析 |
| **网络连接** | `ss -antup` | `ESTAB\|LISTEN ... users:(("proc",pid=...))` | 外联陌生公网、长连接、异常进程名 |
| 连接（旧） | `netstat -antup 2>/dev/null` | 同上 | 备用工具 |
| 混杂模式 | `ip link \| grep -E '^[0-9]+:\|PROMISC'` | 网卡flags含PROMISC | 嗅探/抓包，需结合进程时间判断 |
| 路由表 | `ip route show` | 路由条目 | 异常静态路由 |
| 策略路由 | `ip rule show` | 策略路由条目 | 流量导向非预期网关 |
| **IPv4转发** | `sysctl net.ipv4.ip_forward` | `net.ipv4.ip_forward = 0\|1` | 转发开启常见于代理/隧道/横向 |
| IPv6转发 | `sysctl net.ipv6.conf.all.forwarding` | 同上 | 同上 |
| iptables规则 | `iptables -S 2>/dev/null` | 规则链/表 | 放行可疑端口、特定IP白名单、出站异常 |
| nftables规则 | `nft list ruleset 2>/dev/null` | 规则表 | 新系统防火墙规则 |
| firewalld概览 | `firewall-cmd --list-all 2>/dev/null` | 区域规则概览 | firewalld环境使用 |

### 端口检测
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| **TCP监听** | `ss -lntp` | `LISTEN <addr>:<port> users:(("proc",pid=...))` | 0.0.0.0/::上的异常端口、非预期服务对外监听 |
| TCP监听（旧） | `netstat -lntp 2>/dev/null` | 同上 | 备用工具 |
| TCP高危规则 | `awk '{print $1}' checkrules/dangerstcpports.txt 2>/dev/null` | 端口列表 | 自定义高危端口规则（仓库内） |
| **TCP监听端口** | `ss -lntp \| awk 'NR>1{print $4}' \| sed 's/.*://g' \| sort -n \| uniq` | 端口列表 | 与规则交叉比对 |
| **UDP监听** | `ss -lnup` | `UNCONN <addr>:<port> users:(...)` | 异常UDP监听与可疑进程 |
| UDP监听（旧） | `netstat -lnup 2>/dev/null` | 同上 | 备用工具 |
| UDP高危规则 | `awk '{print $1}' checkrules/dangersudpports.txt 2>/dev/null` | 端口列表 | 自定义高危端口规则 |
| **UDP监听端口** | `ss -lnup \| awk 'NR>1{print $5}' \| sed 's/.*://g' \| sort -n \| uniq` | 端口列表 | 与规则交叉比对 |

### DNS相关
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| DNS配置 | `cat /etc/resolv.conf` | `nameserver <ip>` | 陌生公网DNS |
| 静态解析 | `grep -v '^[[:space:]]*#' /etc/hosts` | IP主机映射 | 对常见域名做了异常指向（投毒/劫持） |

---

## 3. 进程排查

### 基础进程分析
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| 全部进程BSD | `ps aux` | `USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND` | 可疑命令行、异常用户、伪装进程名 |
| 全部进程SYSV | `ps -ef` | `UID PID PPID ... CMD` | 同上 |
| **CPU Top20** | `ps aux --sort=-%cpu \| head -20` | 按CPU降序排列 | 持续高占用且命令行可疑的进程 |
| **内存Top20** | `ps aux --sort=-%mem \| head -20` | 按内存降序排列 | 同上 |
| top快照 | `top -b -n 1 \| head -80` | 负载、CPU、内存、Top进程 | 取样多次对比 |
| **敏感进程** | `ps -ef \| egrep -i '(nc\|ncat\|netcat\|socat\|frp\|ngrok\|proxychains\|ssh -[NRD])'` | 命令行命中 | 做网络连接映射、二进制路径/哈希确认 |

### 高级进程检测
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| 进程树启动 | `ps -eo pid,ppid,user,tty,stat,lstart,cmd --sort=ppid \| head -200` | PID PPID USER ... LSTART CMD | PPID异常、TTY缺失且长期驻留、启动时间落在攻击窗口 |
| **孤儿进程** | `ps -eo pid,ppid,cmd \| awk '$2==1{print $0}' \| head -50` | PID PPID CMD | 不一定恶意，但可作为守护化/持久化线索 |
| **进程网络映射** | `ss -antup` | 连接与进程 | 外联进程二进制路径、父进程 |
| 网络端口映射 | `lsof -i -n -P 2>/dev/null \| head -200` | `COMMAND PID USER FD TYPE ... NAME` | 端口与打开的socket |
| 进程内存映射 | `pmap -x <PID> 2>/dev/null \| head -80` | address perms offset dev inode pathname | 映射到/tmp、/dev/shm、匿名可执行段等 |
| 内存映射（通用） | `cat /proc/<PID>/maps 2>/dev/null \| head -80` | 同上 | 直接查看映射，无需pmap |
| **进程FD** | `ls -l /proc/<PID>/fd 2>/dev/null \| head -50` | FD列表文件 | 指向已删除文件（deleted）、异常大量FD、可疑socket |
| **进程打开文件** | `lsof -p <PID> 2>/dev/null \| head -80` | 进程打开文件/网络 | 若lsof存在 |
| 系统调用表 | `grep -n "sys_call_table" /proc/kallsyms 2>/dev/null` | `<addr> <type> sys_call_table` | 符号消失/不可读 = 可能rootkit，结合内核模块与完整性校验 |
| 进程启动时间 | `ps -eo pid,lstart,cmd --sort=lstart \| head -50` | PID LSTART CMD | 最早启动的一批进程 |
| 最新进程 | `ps -eo pid,lstart,cmd --sort=-lstart \| head -50` | PID LSTART CMD | 最新启动的一批进程，对齐告警/日志时间 |
| **进程环境变量** | `tr '\0' '\n' < /proc/<PID>/environ 2>/dev/null \| head -80` | KEY=VALUE | LD_PRELOAD、PATH异常、代理变量等劫持线索 |

---

## 4. 文件排查

### 系统服务
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| 服务文件列表 | `systemctl list-unit-files --type=service 2>/dev/null \| head -200` | `UNIT FILE STATE` | 定位"新增服务/异常service文件" |
| **自启动服务** | `systemctl list-unit-files --type=service 2>/dev/null \| grep enabled` | enabled列表 | 可疑服务名、可疑ExecStart路径、脚本落地位置 |
| rc.local | `cat /etc/rc.local 2>/dev/null` | 内容 | 自启动脚本 |
| 正在运行服务 | `systemctl --type=service --state=running 2>/dev/null \| head -200` | `UNIT LOAD ACTIVE SUB DESCRIPTION` | 业务外服务、名称伪装 |
| 用户级服务 | `systemctl --user list-unit-files --type=service 2>/dev/null \| head -200` | 用户服务列表 | 无root落地时的持久化 |

### 敏感目录
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| **临时目录** | `ls -alh /tmp /var/tmp /dev/shm 2>/dev/null \| head -200` | 权限 用户 组 大小 时间 文件名 | 可执行文件、最近修改、随机命名脚本/ELF |
| root隐藏文件 | `ls -al /root 2>/dev/null \| grep '^\.' \|\| true` | 隐藏文件/目录 | 异常.ssh、隐藏脚本、隐藏配置/可执行文件 |

### SSH配置
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| 当前用户.ssh | `ls -al ~/.ssh 2>/dev/null` | 文件列表权限 | 目录权限过宽（777/775）、异常新增文件 |
| root .ssh | `ls -al /root/.ssh 2>/dev/null` | 同上 | 同上 |
| **公钥私钥** | `ls -al ~/.ssh/id_* /root/.ssh/id_* 2>/dev/null` | key文件列表 | 与基线对比指纹 |
| 公钥指纹 | `ssh-keygen -lf ~/.ssh/id_rsa.pub 2>/dev/null` | `<bits> <fingerprint> <comment>` | 确认是否为授权运维密钥 |
| **授权密钥** | `cat ~/.ssh/authorized_keys 2>/dev/null` | 逐行公钥 | 持久化首要检查，确认来源与变更窗口 |
| root授权密钥 | `cat /root/.ssh/authorized_keys 2>/dev/null` | 同上 | 同上 |
| 已知主机 | `cat ~/.ssh/known_hosts 2>/dev/null \| tail -50` | 记录 | 辅助还原曾经连接的主机 |
| sshd生效配置 | `grep -v '^[[:space:]]*#' /etc/ssh/sshd_config 2>/dev/null` | 配置行 | Key Value对 |
| sshd最终配置 | `sshd -T 2>/dev/null \| head -200` | 解析后配置 | 若支持 |
| **空口令登录** | `sshd -T 2>/dev/null \| grep -i '^permitemptypasswords'` | `permitemptypasswords yes\|no` | yes通常高风险 |
| 空口令配置(原) | `grep -i '^[[:space:]]*PermitEmptyPasswords' /etc/ssh/sshd_config 2>/dev/null` | 配置行 | 备用 |
| **root登录** | `sshd -T 2>/dev/null \| grep -i '^permitrootlogin'` | `permitrootlogin yes\|no\|prohibit-password` | 业务不需要时建议禁用 |
| root登录(原) | `grep -i '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null` | 配置行 | 备用 |
| **SSH版本** | `ssh -V` | `OpenSSH_X.YpZ ...` (到stderr) | 判断已知漏洞、异常版本替换 |
| SSH服务版本 | `sshd -V 2>&1 \| head -1` | 同上（部分发行版） | 同上 |

### 环境变量与静态解析
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| 全局profile | `cat /etc/profile 2>/dev/null` | 内容/权限 | PATH/LD_PRELOAD/alias注入、可疑远程下载执行 |
| 用户启动文件 | `ls -la ~/.bashrc ~/.bash_profile 2>/dev/null` | 权限 | 同上 |
| **环境变量** | `env \| sort \| head -200` | KEY=VALUE | 代理变量、LD_*变量、PATH异常顺序 |
| 静态解析 | `cat /etc/hosts` | IP主机映射 | 对常见域名/更新源做了异常指向 |

### 敏感文件权限
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| shadow权限 | `ls -l /etc/shadow /etc/gshadow 2>/dev/null` | 权限字符串 | 权限异常（可被普通用户读取） |
| shadow属性 | `stat /etc/shadow /etc/gshadow 2>/dev/null` | 详属性 | 同上 |
| shadow扩展属性 | `lsattr /etc/shadow /etc/gshadow 2>/dev/null` | `----i--------` | 被加immutable需要重点核查 |

### 文件变动与危险权限
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| **24h变动** | `find / -mtime -1 -type f 2>/dev/null \| head -200` | 文件路径 | 结合/tmp、/dev/shm、web目录、启动项目录定向排查 |
| **SUID文件** | `find / -perm -4000 -type f 2>/dev/null \| head -200` | 文件路径 | 提权常见入口，与系统基线比对 |
| **SGID文件** | `find / -perm -2000 -type f 2>/dev/null \| head -200` | 文件路径 | 同上 |

---

## 5. 日志文件分析

### 认证登录日志
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| ZMODEM传输 | `grep -Ein 'rz\|sz\|ZMODEM' /var/log/messages* 2>/dev/null \| head -50` | `文件:行号:内容` | 交互式传输，结合时间轴深挖 |
| DNS行为 | `grep -Ein 'named\|dnsmasq\|resolv\|DNS' /var/log/messages* 2>/dev/null \| head -50` | 同上 | DNS相关活动 |
| 登录/失败/无效 | `grep -Ein 'Accepted \|Failed password\|Invalid user' /var/log/secure* /var/log/auth.log* 2>/dev/null \| head -80` | 时间主机进程[PID]:消息 | 爆破/撞库判断、定位新增账号时间点与来源IP |
| 新增用户/组 | `grep -Ein 'useradd\|userdel\|usermod\|groupadd\|groupdel' /var/log/secure* /var/log/auth.log* 2>/dev/null \| head -80` | 同上 | 新增用户/组线索 |

### 其他关键日志
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| cron运行 | `grep -Ein 'CRON\|cron' /var/log/cron* /var/log/messages* /var/log/syslog* 2>/dev/null \| head -120` | 时间主机CRON[PID]: (user) | 定时下载/定时执行脚本等持久化行为 |
| yum安装 | `grep -Ein 'Installed:\|Updated:\|Erased:' /var/log/yum.log* /var/log/dnf.log* 2>/dev/null \| tail -200` | 时间操作:包名-版本 | 定位可疑工具安装、异常卸载清痕 |
| **内核消息** | `dmesg \| tail -200` | `[timestamp] message` | 内核模块加载、硬件/驱动异常、OOM等关键事件 |
| 失败登录(btmp) | `lastb -n 50 2>/dev/null` | 失败登录记录 | 与secure/auth日志互证 |
| 所有用户最后登录 | `lastlog \| head -200` | 最后登录记录 | 同上 |
| 登录历史(wtmp) | `last -n 50` | 登录历史 | 同上 |
| **journctl最近24h** | `journalctl --since "24 hours ago" --no-pager \| tail -200` | 时间主机单元[PID]:消息 | systemd统一日志入口 |
| auditd状态 | `systemctl status auditd 2>/dev/null \| head -120` | Active/Loaded/Recent logs | 审计开启影响"是否能还原关键操作" |
| rsyslog主配置 | `cat /etc/rsyslog.conf 2>/dev/null` | 配置内容 | 被改写转发到陌生日志服务器、屏蔽关键设施日志 |
| rsyslog分段 | `ls -la /etc/rsyslog.d 2>/dev/null` | 文件列表 | 分段配置文件 |

---

## 6. 后门排查

### 标准后门检测
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| LD_PRELOAD共享库 | `cat /etc/ld.so.preload 2>/dev/null` | 路径或空 | 核验对应so文件来源、时间线与引用进程 |
| **LD_PRELOAD变量** | `echo "$LD_PRELOAD"` | 值或空 | 环境变量劫持，同上 |

---

## 7. 隧道检测

### SSH隧道特征
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| **sshd连接** | `ss -antp \| grep sshd` | `ESTAB ... users:(("sshd",pid=...))` | 同一pid多个外联、来源/目的异常，查进程树与启动参数 |
| sshd连接(旧) | `netstat -anpot 2>/dev/null \| grep sshd` | 同上 | 备用 |
| **SSH转发参数** | `ps -ef \| egrep -i 'ssh .*(-L\|-R\|-D)[[:space:]]'` | 命令行包含-L/-R/-D | 结合ss确认是否形成实际转发通道 |
| **SSH持久化** | `ps -ef \| egrep -i '(autossh\|ssh .*ServerAliveInterval\|ssh .*ControlMaster)'` | 命令行命中 | 常见保活/复用，结合启动项/cron联动 |

### 其他隧道工具
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| 常见隧道工具 | `ps -ef \| egrep -i '(iodine\|dnscat\|chisel\|frp\|ngrok)'` | 命令行命中 | 二进制来源、配置文件、网络端口与落地路径核验 |

---

## 8-12. 其他专项排查

| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| **web目录扫描** | `find /var/www /srv -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.aspx' \) 2>/dev/null \| head -200` | 文件路径 | 定位常见web目录脚本 |
| WebShell危险函数 | `grep -RInE '(eval\(\|base64_decode(\|gzinflate(\|assert(\|system(\|passthru(\)' /var/www 2>/dev/null \| head -200` | 文件:行号:内容 | 命中后结合访问日志与文件时间线 |
| **RPM已安装** | `rpm -qa 2>/dev/null \| head -200` | 软件包列表 | 结合yum/dnf/apt日志与业务白名单定位可疑工具 |
| **DEB已安装** | `dpkg -l 2>/dev/null \| head -200` | 同上 | 同上 |
| **内存概览** | `free -h` | `Mem: total used free ...` | 定位异常占用进程 |
| **内核模块** | `lsmod \| head -200` | `Module Size Used by` | 异常模块名、加载时间线、来源路径 |
| 模块信息 | `modinfo <module> 2>/dev/null \| head -80` | 模块详细信息 | 可疑模块详情 |
| 黑客工具规则 | `cat checkrules/hackertoolslist.txt 2>/dev/null \| head -200` | 工具关键字 | 自定义匹配规则 |
| 黑客工具匹配 | `ps -ef \| egrep -i "$(tr '\n' '\|' < checkrules/hackertoolslist.txt 2>/dev/null \| sed 's/\|$//')" 2>/dev/null \| head -200` | 进程列表 | 关键字命中，用二进制路径+哈希+连接三要素确认 |

---

## 13. 其他排查

| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| 临时目录脚本 | `find /tmp /var/tmp /dev/shm -type f \( -name '*.sh' -o -name '*.py' -o -name '*.pl' \) 2>/dev/null \| head -200` | 文件路径 | 结合修改时间、属主、执行位、脚本内容关键字判断 |
| 持久化脚本 | `find /etc /usr/local -type f -name '*.sh' 2>/dev/null \| head -200` | 同上 | 常见持久化脚本目录 |
| **文件MD5** | `md5sum <file>` | `<md5> <path>` | 计算单个文件 |
| **MD5校验清单** | `md5sum -c <md5_list_file>` | `<path>: OK\|FAILED` | 按基线清单校验 |
| **命令定位** | `which <cmd> 2>/dev/null` | 路径 | 定位命令来源路径 |
| **RPM归属** | `rpm -qf <path> 2>/dev/null` | 包名或无匹配 | 判断二进制是否来自系统包 |
| **DEB归属** | `dpkg -S <path> 2>/dev/null` | 包名或无匹配 | 同上 |

---

## 14. Kubernetes排查

| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| **k8s版本** | `kubectl version --short 2>/dev/null` | 版本输出 | 若已安装/配置 |
| **kubeconfig/凭据** | `find /etc /var/lib -maxdepth 4 -type f \( -name '*.kubeconfig' -o -name 'admin.conf' \) 2>/dev/null \| head -200` | 文件路径 | 命中后立即做权限核查与旋转，避免横向扩散 |

---

## 15. 系统性能分析

| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| **磁盘使用率** | `df -h` | `Filesystem Size Used Avail Use% Mounted on` | 磁盘满可能导致日志丢失/服务异常 |
| **CPU概览** | `top -b -n 1 \| head -40` | `%Cpu(s): ...` + 进程列表 | 关注持续异常占用，结合进程排查 |
| **内存概览** | `free -h` | `Mem: total used free ...` | 缓存/可用内存变化与异常swap使用 |
| **系统负载** | `uptime` | `load average: 1m, 5m, 15m` | 负载异常需综合CPU/IO/内存判断 |
| **网卡统计** | `ip -s link` | `RX: bytes packets errors dropped ...` | 流量异常可提示数据外传/隧道活动 |

---

## 16. 基线检查

### 账号与密码策略
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| 全部用户（账号审查） | `cat /etc/passwd` | 用户列表 | 核心是"是否出现新增/异常账号" |
| **UID=0用户** | `awk -F: '$3==0{print $1}' /etc/passwd` | 用户名列表 | 同系统信息排查 |
| **PASS策略** | `grep -v '^[[:space:]]*#' /etc/login.defs \| grep -E '^PASS_'` | `PASS_MAX_DAYS <n>` 等 | 基线合规、弱策略更易爆破 |
| PAM策略 | `grep -v '^[[:space:]]*#' /etc/pam.d/system-auth 2>/dev/null` | PAM配置行 | CentOS/RHEL |
| PAM策略 | `grep -v '^[[:space:]]*#' /etc/pam.d/common-password 2>/dev/null` | PAM配置行 | Debian/Ubuntu |
| **密码过期用户** | `awk -F: -v today="$(($(date +%s)/86400))" '($5!="" && today>$3+$5){print $1}' /etc/shadow 2>/dev/null` | 用户名列表 | 长期无人维护/策略失效，结合登录日志 |
| **TMOUT超时** | `grep -n 'TMOUT' /etc/profile 2>/dev/null` | `TMOUT=<seconds>` 或无输出 | 未设置/过大导致共享终端风险 |

### 系统安全配置
| 检查项 | 命令 | 输出格式 | 解读重点 |
|--------|------|----------|----------|
| **grub2密码** | `grep -nE '^[[:space:]]*password_pbkdf2' /boot/grub2/grub.cfg 2>/dev/null` | 命中行或无输出 | 引导层保护，云环境可防止低层篡改 |
| hosts.allow | `grep -v '^[[:space:]]*#' /etc/hosts.allow 2>/dev/null` | 规则行或空 | 是否加入异常放行IP/网段 |
| hosts.deny | `grep -v '^[[:space:]]*#' /etc/hosts.deny 2>/dev/null` | 规则行或空 | 策略被清空导致放大暴露面 |
| **firewalld区域** | `firewall-cmd --get-active-zones 2>/dev/null` | 活跃区域 | 若firewalld存在 |
| **firewalld规则** | `firewall-cmd --list-all 2>/dev/null` | 区域规则概览 | 若firewalld存在 |
| iptables规则 | `iptables -L -n -v 2>/dev/null` | 规则表 | 若iptables存在 |
| **SELinux模式** | `getenforce 2>/dev/null` | `Enforcing\|Permissive\|Disabled` | 当前模式 |
| SELinux状态 | `sestatus 2>/dev/null \| head -50` | 状态摘要 | 详细状态 |
| SELinux默认模式 | `grep '^SELINUX=' /etc/selinux/config 2>/dev/null` | 配置行 | 默认启动模式 |
| 关键文件权限 | `stat -c '%A %U %G %n' /etc/passwd /etc/group /etc/securetty /etc/services 2>/dev/null` | `<perm> <owner> <group> <path>` | 权限异常可能导致提权/信息泄露 |
| core dump策略 | `grep -nE '^\\*\\s+(soft\|hard)\\s+core\\s+0' /etc/security/limits.conf 2>/dev/null` | 匹配行 | 未禁用可能泄露敏感内存信息 |

---

## 使用建议

1. **选择性执行** - 根据排查需求选择对应流程的命令
2. **优先级执行** - 优先标注 ⚠️ 的关键检查项
3. **交叉验证** - 多个命令结果互相验证
4. **时间线对齐** - 将发现的问题与日志时间对齐构建攻击时间线
