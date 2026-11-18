# Baseline: rules only (test set, seed 2, 72h)

Log lines: **7,188** (5,200 malicious) · rules: 15 · detection throughput: 99,830 events/s

## Summary

| Metric | Value |
|---|---|
| Attack incidents detected (recall) | 30/35 (86%) |
| Alerts raised | 72 |
| Alert precision (alerts that were real attacks) | 94% |
| False-positive alerts | 4 |
| Alert reduction (log lines → alerts) | 99.00% |
| Median time to detect | 18.0 s |
| Event-level precision / recall / F1 | 0.99 / 0.20 / 0.33 |

## Detection by attack type

| Scenario | Detected | Recall | Median time to detect |
|---|---|---|---|
| brute_force | 5/5 | 100% | 17 s |
| brute_force_success | 5/5 | 100% | 17 s |
| distributed_brute_force | 5/5 | 100% | 112 s |
| insider_privesc | 5/5 | 100% | 13 s |
| low_and_slow | 0/5 | 0% | – |
| password_spray | 5/5 | 100% | 99 s |
| recon_scan | 5/5 | 100% | 18 s |

## Per rule

| Rule | Title | Alerts | True positive | Precision |
|---|---|---|---|---|
| AT-001 | SSH brute force from single source | 10 | 10 | 100% |
| AT-002 | Password spraying (many usernames from one IP) | 5 | 5 | 100% |
| AT-003 | Successful login after repeated failures | 6 | 5 | 83% |
| AT-004 | SSH reconnaissance / scanning | 5 | 5 | 100% |
| AT-005 | New local user account created | 3 | 2 | 67% |
| AT-006 | Interactive root shell via sudo | 11 | 10 | 91% |
| AT-007 | Password hash file accessed | 9 | 9 | 100% |
| AT-008 | Remote script downloaded and executed | 7 | 7 | 100% |
| AT-010 | Cron job created or edited | 1 | 0 | 0% |
| AT-011 | SUID/SGID bit set on a file | 1 | 1 | 100% |
| AT-012 | Log files deleted or truncated | 4 | 4 | 100% |
| AT-013 | Repeated sudo authentication failures | 5 | 5 | 100% |
| AT-015 | Distributed brute force against one account | 5 | 5 | 100% |

## False positives

| Rule | Example log line |
|---|---|
| AT-006 | `Nov 16 21:04:45 web01 sudo:    ops : TTY=pts/0 ; PWD=/home/ops ; USER=root ; COMMAND=/bin/bash` |
| AT-005 | `Nov 16 21:06:46 web01 useradd[13347]: new user: name=newhire, UID=1005, GID=1005, home=/home/newhire, shell=/bin/bash, from=/dev/pts/0` |
| AT-010 | `Nov 16 21:09:45 web01 sudo:    ops : TTY=pts/1 ; PWD=/home/ops ; USER=root ; COMMAND=/usr/bin/crontab -e` |
| AT-003 | `Nov 18 11:30:00 web01 sshd[13264]: Failed password for dave from 10.0.2.21 port 40180 ssh2` |
