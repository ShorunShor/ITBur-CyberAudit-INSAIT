#!/usr/bin/env python3
"""
ITBur Cyber Auditor 
Полный аудит безопасности Linux с учётом всех требований конкурса и реальных bit26-находок
Автор: Команда [INSAIT]
Версия: 3.0
"""

import os
import sys
import subprocess
import json
import re
import sqlite3
import glob
import socket
import pwd
import grp
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ---------- Цвета для красивого вывода ----------
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

# ---------- Основной класс аудитора ----------
class ITBurCyberAuditor:
    def __init__(self):
        self.findings = []               # Найденные проблемы
        self.flags = set()                # Найденные флаги (уникальные)
        self.ctf_hints = defaultdict(list)  # Подсказки для CTF
        self.scan_time = datetime.now().isoformat()
        self.hostname = subprocess.getoutput("hostname")
        self.current_user = subprocess.getoutput("whoami")
        self.start_time = datetime.now()

    def run_cmd(self, cmd, use_sudo=False):
        """Безопасное выполнение команд с обработкой ошибок"""
        try:
            if use_sudo and self.current_user != 'root':
                cmd = f"sudo {cmd}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            return result.stdout.strip()
        except Exception:
            return ""

    def add_finding(self, level, category, description, recommendation, data=None):
        """Добавление проблемы в отчёт с цветным выводом"""
        finding = {
            'level': level,
            'category': category,
            'description': description,
            'recommendation': recommendation,
            'data': data or {}
        }
        self.findings.append(finding)

        # Цветной вывод
        color_map = {
            'КРИТИЧЕСКИЙ': Colors.RED,
            'ВЫСОКИЙ': Colors.YELLOW,
            'СРЕДНИЙ': Colors.BLUE,
            'ИНФО': Colors.CYAN
        }
        color = color_map.get(level, Colors.END)
        print(f"{color}[{level}]{Colors.END} {category}: {description}")
        print(f"  → {Colors.CYAN}Исправление:{Colors.END} {recommendation}\n")

    # ---------- БЛОК 1: Анализ прав доступа ----------
    def audit_file_permissions(self):
        """Поиск опасных прав доступа (777, 666, SUID, SGID) и конфиденциальных данных"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[1] Анализ прав доступа{Colors.END}")

        critical_dirs = ['/etc', '/var', '/home', '/root', '/opt', '/tmp']

        for d in critical_dirs:
            if not os.path.exists(d):
                continue

            # Файлы с правами 777
            for f in self.run_cmd(f"find {d} -type f -perm 0777 2>/dev/null").split('\n'):
                if f:
                    self.add_finding('КРИТИЧЕСКИЙ', 'Права 777',
                                     f"Файл {f} доступен на запись и чтение всем",
                                     f"sudo chmod 644 {f}")

            # Файлы с правами 666
            for f in self.run_cmd(f"find {d} -type f -perm 0666 2>/dev/null").split('\n'):
                if f:
                    self.add_finding('ВЫСОКИЙ', 'Права 666',
                                     f"Файл {f} доступен на запись всем",
                                     f"sudo chmod 644 {f}")

            # SUID-бит
            for f in self.run_cmd(f"find {d} -type f -perm -4000 2>/dev/null").split('\n'):
                if f:
                    self.add_finding('ВЫСОКИЙ', 'SUID-бит',
                                     f"Файл {f} имеет SUID (выполнение от владельца)",
                                     f"sudo chmod u-s {f} (если не требуется)")

            # SGID-бит
            for f in self.run_cmd(f"find {d} -type f -perm -2000 2>/dev/null").split('\n'):
                if f:
                    self.add_finding('СРЕДНИЙ', 'SGID-бит',
                                     f"Файл {f} имеет SGID",
                                     f"sudo chmod g-s {f}")

        # Поиск конфиденциальных данных (пароли, ключи)
        print(f"{Colors.BLUE}  Поиск конфиденциальных данных...{Colors.END}")
        patterns = ['password', 'passwd', 'secret', 'key', 'cred', 'IDENTIFIED BY']
        for pat in patterns:
            for f in self.run_cmd(f"grep -r -l '{pat}' /etc/ /home/ /var/ 2>/dev/null | head -30").split('\n'):
                if f and os.path.isfile(f) and os.access(f, os.R_OK):
                    content = self.run_cmd(f"grep -m1 '{pat}' {f}")
                    self.add_finding('ВЫСОКИЙ', 'Конфиденциальные данные',
                                     f"Файл {f} содержит '{pat}': {content[:100]}",
                                     f"Проверьте содержимое: cat {f}")

        # Проверка истории MariaDB/MySQL (из первого кода)
        history_files = [os.path.expanduser("~/.mariadb_history"), "/root/.mariadb_history",
                         os.path.expanduser("~/.mysql_history"), "/root/.mysql_history"]
        for h in history_files:
            if os.path.exists(h):
                self.add_finding('ВЫСОКИЙ', 'История БД',
                                 f"Найден файл истории БД: {h} (может содержать пароли)",
                                 f"Удалите или очистите: sudo rm {h}")

        # Проверка ярлыков меню на повышение привилегий (из первого кода)
        desktop_files = self.run_cmd("grep -rE 'pkexec|sudo' /usr/share/applications/*.desktop 2>/dev/null")
        if desktop_files:
            self.add_finding('СРЕДНИЙ', 'Ярлыки меню',
                             "Найдены ярлыки запуска от root (pkexec/sudo). Риск NOPASSWD.",
                             "Проверьте файл /etc/sudoers и правила Polkit")

    # ---------- БЛОК 2: Сетевой аудит ----------
    def audit_network(self):
        """Анализ открытых портов, опасных сервисов, баннеров, анонимного FTP"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[2] Сетевой аудит{Colors.END}")

        ss_out = self.run_cmd("ss -tulpn")
        dangerous_ports = {
            21: ('FTP', 'анонимный доступ, передача в открытом виде'),
            23: ('Telnet', 'нешифрованное соединение'),
            513: ('rlogin', 'устаревший протокол'),
            514: ('rsh', 'устаревший протокол'),
            111: ('RPC', 'потенциально опасен'),
            2049: ('NFS', 'без шифрования'),
            3306: ('MySQL', 'без пароля?'),
            5432: ('PostgreSQL', 'без пароля?'),
            6379: ('Redis', 'без пароля?'),
            27017: ('MongoDB', 'без пароля?')
        }

        for line in ss_out.split('\n'):
            if 'LISTEN' in line:
                m = re.search(r':(\d+)', line)
                if m:
                    port = int(m.group(1))
                    if port in dangerous_ports:
                        svc, risk = dangerous_ports[port]
                        self.add_finding('ВЫСОКИЙ', 'Опасный порт',
                                         f"Порт {port} ({svc}) открыт. {risk}",
                                         f"sudo ufw deny {port} или остановите сервис",
                                         {'port': port, 'line': line})

        # Проверка баннеров (могут содержать флаги)
        for port in [21, 25, 80, 443, 3306, 5432]:
            banner = self.run_cmd(f"timeout 2 nc -v localhost {port} 2>&1 | head -1")
            if 'bit26{' in banner:
                flag = re.search(r'(bit26\{[^}]+\})', banner)
                if flag:
                    self.flags.add(flag.group(1))
                    print(f"{Colors.GREEN}[+] Флаг в баннере порта {port}: {flag.group(1)}{Colors.END}")

        # Проверка анонимного FTP
        ftp_test = self.run_cmd("echo 'quit' | ftp -n localhost 2>/dev/null | grep '230 '")
        if ftp_test:
            self.add_finding('КРИТИЧЕСКИЙ', 'FTP анонимный доступ',
                             "Анонимный вход разрешён",
                             "Отключите anonymous_enable в /etc/vsftpd.conf")

    # ---------- БЛОК 3: Аудит пакетов и CVE ----------
    def audit_packages(self):
        """Сбор версий пакетов и проверка по базе уязвимостей (реальные CVE)"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[3] Аудит пакетов{Colors.END}")

        kernel = self.run_cmd("uname -r")
        self.add_finding('ИНФО', 'Ядро Linux',
                         f"Версия: {kernel}",
                         "sudo apt update && sudo apt upgrade linux-image")

        # База уязвимых версий (реальные CVE)
        vuln_db = {
            'openssh-server': [('1:', 'CVE-2024-6387 (regreSSHion)'), ('8.9', 'CVE-2023-38408'), ('7.9', 'CVE-2021-28041')],
            'apache2': [('2.4.49', 'CVE-2021-42013'), ('2.4.50', 'CVE-2021-42013')],
            'nginx': [('1.20.0', 'CVE-2021-23017'), ('1.18.0', 'CVE-2021-23017')],
            'mysql-server': [('5.7', 'CVE-2023-21912'), ('8.0.36', 'CVE-2024-20973')],
            'postgresql': [('14', 'CVE-2023-2454'), ('15', 'CVE-2023-2455')],
            'vsftpd': [('2.3.4', 'CVE-2011-2523')],
            'samba': [('4.17', 'CVE-2023-3347'), ('4.18', 'CVE-2023-3347')],
            'openssl': [('1.1.1', 'CVE-2023-3817'), ('3.0', 'CVE-2023-3817')]
        }

        for pkg, versions in vuln_db.items():
            ver = self.run_cmd(f"dpkg-query -W -f='${{Version}}' {pkg} 2>/dev/null")
            if ver:
                vulnerable = False
                for bad_ver, cve in versions:
                    if bad_ver in ver:
                        vulnerable = True
                        self.add_finding('КРИТИЧЕСКИЙ', f'Уязвимый пакет {pkg}',
                                         f"{pkg} {ver} — {cve}",
                                         f"sudo apt update && sudo apt upgrade {pkg}")
                        break
                if not vulnerable:
                    self.add_finding('ИНФО', f'Пакет {pkg}',
                                     f"Версия {ver} (не найдена в базе уязвимостей)",
                                     f"sudo apt upgrade {pkg} (рекомендуется обновить)")

    # ---------- БЛОК 4: Поиск CTF-флагов () ----------
    def search_ctf_flags(self):
        """Многоуровневый поиск флагов bit26{...} во всех местах, где ты находил"""
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}[4] Поиск CTF-флагов{Colors.END}")

        # 4.1. Рекурсивный поиск по файловой системе
        search_paths = ['/home', '/root', '/var/www', '/etc', '/opt', '/tmp', '/boot', '/var/log', '/mnt', '/media']
        for path in search_paths:
            if os.path.exists(path):
                out = self.run_cmd(f"sudo grep -r -E 'bit26\\{{[^}}]+\\}}' {path} 2>/dev/null | head -200")
                for line in out.split('\n'):
                    m = re.search(r'(bit26\{[^}]+\})', line)
                    if m:
                        self.flags.add(m.group(1))
                        print(f"{Colors.GREEN}[+] Флаг в файле: {m.group(1)}{Colors.END}")

        # 4.2. Firefox (закладки и история)
        for profile in glob.glob('/home/*/.mozilla/firefox/*.default*/places.sqlite'):
            try:
                conn = sqlite3.connect(profile)
                c = conn.cursor()
                c.execute("SELECT url, title FROM moz_places WHERE url LIKE '%bit26%' OR title LIKE '%bit26%'")
                for url, title in c.fetchall():
                    for text in [url, title]:
                        m = re.search(r'(bit26\{[^}]+\})', str(text))
                        if m:
                            self.flags.add(m.group(1))
                            print(f"{Colors.GREEN}[+] Флаг в Firefox: {m.group(1)}{Colors.END}")
                conn.close()
            except Exception:
                pass

        # 4.3. История команд (bash)
        for hist in ['/root/.bash_history'] + glob.glob('/home/*/.bash_history'):
            if os.path.exists(hist):
                content = self.run_cmd(f"cat {hist} | grep bit26")
                for line in content.split('\n'):
                    m = re.search(r'(bit26\{[^}]+\})', line)
                    if m:
                        self.flags.add(m.group(1))
                        print(f"{Colors.GREEN}[+] Флаг в истории команд: {m.group(1)}{Colors.END}")

        # 4.4. Переменные окружения
        env_out = self.run_cmd("env | grep bit26")
        for line in env_out.split('\n'):
            m = re.search(r'(bit26\{[^}]+\})', line)
            if m:
                self.flags.add(m.group(1))
                print(f"{Colors.GREEN}[+] Флаг в переменных окружения: {m.group(1)}{Colors.END}")

        # 4.5. Cron
        cron_out = self.run_cmd("crontab -l 2>/dev/null | grep bit26")
        for line in cron_out.split('\n'):
            m = re.search(r'(bit26\{[^}]+\})', line)
            if m:
                self.flags.add(m.group(1))
                print(f"{Colors.GREEN}[+] Флаг в cron: {m.group(1)}{Colors.END}")

        # 4.6. GRUB загрузчик
        grub = self.run_cmd("cat /boot/grub/grub.cfg 2>/dev/null | grep bit26")
        for line in grub.split('\n'):
            m = re.search(r'(bit26\{[^}]+\})', line)
            if m:
                self.flags.add(m.group(1))
                print(f"{Colors.GREEN}[+] Флаг в GRUB: {m.group(1)}{Colors.END}")

        # 4.7. Базы данных (MySQL/MariaDB) — если доступны без пароля
        db_test = self.run_cmd("mysql -u root -e 'show databases;' 2>/dev/null")
        if 'information_schema' in db_test:
            # Попробуем найти таблицу с флагами (например, flag, ctf, flags)
            for db in ['cff', 'ctf', 'flags', 'test']:
                tables = self.run_cmd(f"mysql -u root -D {db} -e 'show tables;' 2>/dev/null")
                if tables:
                    flags_in_db = self.run_cmd(f"mysql -u root -D {db} -e 'select * from flag;' 2>/dev/null")
                    for line in flags_in_db.split('\n'):
                        m = re.search(r'(bit26\{[^}]+\})', line)
                        if m:
                            self.flags.add(m.group(1))
                            print(f"{Colors.GREEN}[+] Флаг в БД ({db}): {m.group(1)}{Colors.END}")

        # 4.8. Systemd журнал
        journal = self.run_cmd("sudo journalctl | grep -E 'bit26\\{[^}]+\\}' | tail -50")
        for line in journal.split('\n'):
            m = re.search(r'(bit26\{[^}]+\})', line)
            if m:
                self.flags.add(m.group(1))
                print(f"{Colors.GREEN}[+] Флаг в journalctl: {m.group(1)}{Colors.END}")

        # 4.9. Шифрованные строки (поиск подсказок, как в твоём опыте)
        encrypted_hints = self.run_cmd("grep -r -E 'СМИОТЗУИЯВРП|ОАТН|ИЬТУАСР' /home/ /root/ 2>/dev/null")
        if encrypted_hints:
            self.ctf_hints['encrypted'].append(encrypted_hints)
            print(f"{Colors.YELLOW}[!] Найдены зашифрованные строки (возможно, флаг после расшифровки){Colors.END}")

        # 4.10. HTML-комментарии на веб-сервере
        web_files = self.run_cmd("grep -r -l '<!--' /var/www/html/ 2>/dev/null | head -20").split('\n')
        for f in web_files:
            if f:
                content = self.run_cmd(f"cat {f} | grep bit26")
                for line in content.split('\n'):
                    m = re.search(r'(bit26\{[^}]+\})', line)
                    if m:
                        self.flags.add(m.group(1))
                        print(f"{Colors.GREEN}[+] Флаг в HTML-комментарии: {m.group(1)}{Colors.END}")

    # ---------- БЛОК 5: Проверка привилегий (sudo) ----------
    def check_privileges(self):
        """Анализ прав sudo и поиск подозрительных процессов"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[5] Проверка привилегий{Colors.END}")

        sudo_l = self.run_cmd("sudo -l")
        if '(ALL : ALL) ALL' in sudo_l:
            self.add_finding('КРИТИЧЕСКИЙ', 'Sudo ALL',
                             f"Пользователь {self.current_user} имеет полный доступ sudo",
                             "Отредактируйте /etc/sudoers, ограничьте права")
        if 'NOPASSWD' in sudo_l:
            self.add_finding('КРИТИЧЕСКИЙ', 'Sudo NOPASSWD',
                             "Обнаружены правила sudo без запроса пароля",
                             "Удалите NOPASSWD из /etc/sudoers")

        # Подозрительные процессы (возможные руткиты)
        suspicious = self.run_cmd("ps aux | grep -E 'kworkerd|udevd|\\[kthreadd\\]' | grep -v grep")
        if suspicious:
            self.add_finding('ВЫСОКИЙ', 'Подозрительные процессы',
                             "Обнаружены процессы, маскирующиеся под системные",
                             "Проверьте систему антивирусом: chkrootkit, rkhunter")

    # ---------- БЛОК 6: Аудит системных журналов ----------
    def audit_logs(self):
        """Проверка логов на попытки взлома и аномалии"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[6] Аудит журналов{Colors.END}")

        # Неудачные попытки входа
        failed = self.run_cmd("sudo grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -5")
        if failed:
            self.add_finding('ВЫСОКИЙ', 'Неудачные входы',
                             "Обнаружены множественные неудачные попытки входа",
                             "Проверьте /var/log/auth.log, заблокируйте атакующие IP")

        # Смена паролей
        passwd_changes = self.run_cmd("sudo grep 'password changed' /var/log/auth.log 2>/dev/null | tail -3")
        if passwd_changes:
            self.add_finding('СРЕДНИЙ', 'Смена паролей',
                             "Недавняя смена паролей пользователей",
                             "Убедитесь, что изменения санкционированы")

    # ---------- БЛОК 7: Проверка брандмауэра ----------
    def check_firewall(self):
        """Проверка состояния ufw/firewalld"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[7] Проверка брандмауэра{Colors.END}")

        ufw_status = self.run_cmd("ufw status 2>/dev/null")
        if ufw_status:
            if 'inactive' in ufw_status.lower():
                self.add_finding('КРИТИЧЕСКИЙ', 'Брандмауэр UFW отключён',
                                 "UFW установлен, но не активен. Система без защиты.",
                                 "sudo ufw enable && sudo ufw default deny incoming && sudo ufw default allow outgoing")
            elif 'active' in ufw_status.lower():
                # Проверим правила по умолчанию
                default_in = self.run_cmd("ufw status verbose | grep 'Default:' | grep incoming")
                if 'deny' not in default_in.lower():
                    self.add_finding('ВЫСОКИЙ', 'Настройки UFW',
                                     f"Правило для входящих: {default_in} (должно быть deny)",
                                     "sudo ufw default deny incoming")
                print(f"{Colors.GREEN}[+] UFW активен{Colors.END}")
        else:
            # UFW не установлен, проверим firewalld
            firewalld = self.run_cmd("systemctl is-active firewalld 2>/dev/null")
            if firewalld == 'active':
                print(f"{Colors.GREEN}[+] firewalld активен{Colors.END}")
            elif firewalld == 'inactive':
                self.add_finding('КРИТИЧЕСКИЙ', 'firewalld отключён',
                                 "firewalld установлен, но не активен",
                                 "sudo systemctl enable --now firewalld")
            else:
                self.add_finding('КРИТИЧЕСКИЙ', 'Брандмауэр отсутствует',
                                 "Не установлен ни UFW, ни firewalld",
                                 "sudo apt install ufw && sudo ufw enable")

    # ---------- Генерация отчёта ----------
    def generate_report(self):
        """Формирование JSON-отчёта и итогового вывода"""
        duration = (datetime.now() - self.start_time).total_seconds()

        report = {
            'scan_info': {
                'hostname': self.hostname,
                'user': self.current_user,
                'timestamp': self.scan_time,
                'duration_seconds': round(duration, 2),
                'total_findings': len(self.findings),
                'total_flags': len(self.flags)
            },
            'flags_found': sorted(list(self.flags)),
            'findings': self.findings,
            'ctf_hints': dict(self.ctf_hints)
        }

        filename = f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        # Красивый итог в консоли
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}ИТОГОВЫЙ ОТЧЁТ АУДИТА{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.END}")
        print(f"Хост: {self.hostname}")
        print(f"Пользователь: {self.current_user}")
        print(f"Время сканирования: {duration:.2f} сек")
        print(f"Найдено проблем: {len(self.findings)}")
        print(f"Найдено флагов: {len(self.flags)}")

        if self.flags:
            print(f"\n{Colors.BOLD}Флаги CTF:{Colors.END}")
            for flag in sorted(self.flags):
                print(f"  {Colors.GREEN}{flag}{Colors.END}")

        print(f"\n{Colors.BOLD}Полный отчёт сохранён в файл:{Colors.END} {filename}")

    # ---------- Запуск всех проверок ----------
    def run_all(self):
        """Последовательный запуск всех модулей аудита"""
        print(f"{Colors.BOLD}{Colors.CYAN}ITBur Cyber Auditor v3.0 (Финальная версия){Colors.END}")
        print(f"{Colors.CYAN}Запуск полного аудита безопасности...{Colors.END}\n")

        self.audit_file_permissions()
        self.audit_network()
        self.audit_packages()
        self.search_ctf_flags()
        self.check_privileges()
        self.audit_logs()
        self.check_firewall()
        self.generate_report()


# ---------- Точка входа ----------
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}Предупреждение: для полного аудита рекомендуется запуск с sudo.{Colors.END}\n")

    auditor = ITBurCyberAuditor()
    auditor.run_all()
