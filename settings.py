"""
Файл с настройками
"""
import os
from datetime import datetime

from updater import update_aa_txt, update_cer_by_ssh

# ------ Настройки для лога ------

# Для продакшена
LOG_FOLDER = '/var/log/letsencrypt-certificate'
# Для тестов
# LOG_FOLDER = os.path.join(os.path.dirname(__file__), 'log')

LOG_HTTP_SERVER_ENABLE = True
LOG_HTTP_SERVER_IP = '***secret***'
LOG_HTTP_SERVER_PORT = '***secret***'
LOG_HTTP_SERVER_PORT_GUI = '***secret***'
LOG_HTTP_SERVER_PATH = 'letsencrypt-certificate'

TELEGRAM_SOCKS5_ENABLE = True
TELEGRAM_SOCKS5 = {
    'proxy_username': '***secret***',
    'proxy_pass': '***secret***',
    'proxy_hostport': '***secret***',
}
TELEGRAM = {
    'token': '***secret***',
    'recipient': '***secret***',
}

# Нельзя торогать!!
# Создание папки для лога
os.makedirs(LOG_FOLDER, exist_ok=True)
# Создание переменной для имени файла лога
_log_file_name = '%s.log' % datetime.now().strftime('%Y.%m.%d_%H_%M')
LOG_FILE = os.path.join(LOG_FOLDER, _log_file_name)
# Создание URL пути для HTTP лога
if LOG_HTTP_SERVER_PATH[0] != '/':
    LOG_HTTP_SERVER_PATH = '/' + LOG_HTTP_SERVER_PATH
LOG_HTTP_SERVER_PATH = os.path.join(LOG_HTTP_SERVER_PATH, _log_file_name)

# ------ Настройки модуля сертификата, которые зависят от letsencrypt ------

# Если что-то изменится во внешнем мире, то нужно править эти настройки

# ACME-V2 api для Let's Encrypt.
# Про протокол ACME можно почитать тут: https://tools.ietf.org/html/rfc8555
# https://letsencrypt.org/docs/acme-protocol-updates/
# Для тестов
# DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
# Для продакшена
DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory'

# Хз зачем, но работает.
# Скорей всего это описано в спецификации протокола ACME
USER_AGENT = 'python-acme'
# Размер ключа аккаунта
ACC_KEY_BITS = 2048
# Размер закрытого ключа сертификата
CERT_PKEY_BITS = 2048

# ------ Настройки модуля сертификата ------

# Задержка (в секундах) между запросами к DNS серверам
TIME_SLEEP = 300
# Максимальное кол-во запросов к DNS серверам
# Итоговое время ожидания обновления TXT записи можно вычислить по формуле:
# TIME_SLEEP + MAX_COUNT_REQUEST (секунд)
# Если за это время TXT запись не обновится на ВСЕХ dns сервера
# (Список DNS серверов можно посмотеть в функции get_letsencrypt_certificate._get_dns_ns),
# то скрипт завершит работу (новых сертификатов не будет)
MAX_COUNT_REQUEST = 60
# Куда сохранять сертификаты
CERTIFICATE_FOLDER = os.path.join(os.path.dirname(__file__), 'certificate')

# Электронная почта для регистрации на letsencrypt.org
EMAIL = '***secret***'
# Словарь с настройками
# TODO: Описать
CERTIFICATE = {    
    'telebot.aliter.spb.ru': {
        'email': EMAIL,
        'domain': ['***secret***'],
        'port': [8443],
        'update_txt': update_aa_txt,

        'update_cert': update_cer_by_ssh,
        'ssh_host': '***secret***',
        'ssh_username': '***secret***',
        'ssh_pkey_path': os.path.join(os.path.dirname(__file__), 'keys', '***secret***'),
        'ssh_private_path': '***secret***',
        'ssh_fullchain_path': '***secret***',
        'ssh_commands': ['sudo systemctl restart redir.service'],
    },
    'aliter.spb.ru': {
        'email': EMAIL,
        'domain': ['***secret***', '***secret***'],
        'port': [443],
        'update_txt': update_aa_txt,

        'update_cert': update_cer_by_ssh,
        'ssh_host': '***secret***',
        'ssh_username': '***secret***',
        'ssh_pkey_path': os.path.join(os.path.dirname(__file__), 'keys', '***secret***'),
        'ssh_private_path': '***secret***',
        'ssh_fullchain_path': '***secret***',
        'ssh_commands': ['killall nginx', 'nginx'],
    },
    'mail.aliter.spb.ru': {
        'email': EMAIL,
        'domain': ['***secret***'],
        'port': [465, 993],
        'update_txt': update_aa_txt,

        'update_cert': update_cer_by_ssh,
        'ssh_host': '***secret***',
        'ssh_username': '***secret***',
        'ssh_pkey_path': os.path.join(os.path.dirname(__file__), 'keys', '***secret***'),
        'ssh_private_path': '/***secret***',
        'ssh_fullchain_path': '***secret***',
        'ssh_commands': ['sudo systemctl restart postfix', 'sudo systemctl restart dovecot'],
    },
}

# ------ Настройки для DNS хостинга NIC ------

NIC_APP_LOGIN = '***secret***'
NIC_APP_PASSWORD = '***secret***'
NIC_OAUTH_CONFIG = {
    'APP_LOGIN': NIC_APP_LOGIN,
    'APP_PASSWORD': NIC_APP_PASSWORD
}
NIC_USERNAME = '***secret***'
NIC_PASSWORD = '***secret***'
NIC_MY_SERVICE = '***secret***'
NIC_MY_DOMAIN = '***secret***'

NIC_TOKEN_FOLDER = os.path.dirname(__file__)
NIC_TOKEN_FILENAME = os.path.join(NIC_TOKEN_FOLDER, 'nic_token.json')
