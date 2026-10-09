"""Sample data for demo mode."""

SAMPLE_EMAIL = """From: security-noreply@paypa1-verify.com
To: john.doe@company.com
Subject: URGENT: Your PayPal account has been suspended - Action Required

Dear Customer,

We have detected unusual activity on your PayPal account and it has been temporarily suspended.

Please click the link below immediately to restore access and verify your identity:
http://paypa1-secure-login.xyz/restore?token=abc123&redirect=verify

If you do not act within 24 hours, your account will be permanently closed and all funds frozen.

Your account details:
IP Address: 103.45.67.89
Last login attempt from: 185.220.101.1

Failure to respond will result in permanent suspension.

Click here to verify: http://trk.click/secure-paypal-restore

Thank you,
PayPal Security Team
paypal-security@paypa1.com
"""

SAMPLE_LOG = """Oct  5 14:23:11 server sshd[12345]: Failed password for root from 103.45.67.89 port 52341 ssh2
Oct  5 14:23:13 server sshd[12345]: Failed password for root from 103.45.67.89 port 52342 ssh2
Oct  5 14:23:15 server sshd[12345]: Failed password for admin from 103.45.67.89 port 52343 ssh2
Oct  5 14:23:17 server sshd[12345]: Failed password for root from 103.45.67.89 port 52344 ssh2
Oct  5 14:23:19 server sshd[12345]: Failed password for ubuntu from 103.45.67.89 port 52345 ssh2
Oct  5 14:23:21 server sshd[12345]: Failed password for invalid user deploy from 103.45.67.89 port 52346 ssh2
Oct  5 14:23:23 server sshd[12345]: Failed password for root from 103.45.67.89 port 52347 ssh2
Oct  5 14:23:25 server sshd[12346]: Failed password for root from 185.220.101.1 port 42100 ssh2
Oct  5 14:23:27 server sshd[12346]: Failed password for admin from 185.220.101.1 port 42101 ssh2
Oct  5 14:23:29 server sshd[12346]: Failed password for user from 185.220.101.1 port 42102 ssh2
Oct  5 14:23:31 server sshd[12346]: Failed password for root from 185.220.101.1 port 42103 ssh2
Oct  5 14:23:33 server sshd[12346]: Failed password for root from 185.220.101.1 port 42104 ssh2
Oct  5 14:23:35 server sshd[12346]: Failed password for root from 185.220.101.1 port 42105 ssh2
Oct  5 14:24:01 server sudo: john : TTY=pts/1 ; PWD=/home/john ; USER=root ; COMMAND=/usr/bin/passwd admin
Oct  5 14:24:15 server sshd[12350]: Accepted password for john from 10.0.0.5 port 33210 ssh2
Oct  5 14:24:45 server crontab[12391]: (root) edited by john
Oct  5 14:25:01 server kernel: SYN_RECV from 45.142.212.100:80
Oct  5 14:25:03 server kernel: SYN_RECV from 45.142.212.100:443
Oct  5 14:25:05 server kernel: SYN_RECV from 45.142.212.100:8080
Oct  5 14:26:10 server sshd[12400]: Failed password for root from 45.142.212.100 port 55001 ssh2
Oct  5 14:26:11 server sshd[12400]: Failed password for root from 45.142.212.100 port 55002 ssh2
Oct  5 14:26:12 server sshd[12400]: Failed password for oracle from 45.142.212.100 port 55003 ssh2
Oct  5 14:26:13 server sshd[12400]: Failed password for root from 45.142.212.100 port 55004 ssh2
Oct  5 14:26:14 server sshd[12400]: Failed password for root from 45.142.212.100 port 55005 ssh2
Oct  5 14:26:15 server sshd[12400]: Failed password for test from 45.142.212.100 port 55006 ssh2
"""

SAMPLE_IPS = "103.45.67.89, 185.220.101.1, 45.142.212.100"
