import os
import shutil

import paramiko
from scp import SCPClient
from subprocess import Popen, PIPE
import lib.nic_api as nic_api


def update_aa_txt(domain, validation, ttl=1):
    """Обновление TXT записи для NIC хостинга"""
    # В этом импорте нет ошибки
    # Если поместить его вверх, будет ошибка циклического импорта
    from logger import logger
    from settings import (NIC_MY_DOMAIN,
                          NIC_MY_SERVICE,
                          NIC_OAUTH_CONFIG,
                          NIC_USERNAME,
                          NIC_PASSWORD,
                          NIC_TOKEN_FILENAME)

    # Создаю правильное имя (хост) для ТХТ записи
    if domain == NIC_MY_DOMAIN:
        name = '_acme-challenge'
    else:
        name = domain.replace('.' + NIC_MY_DOMAIN, '')
        name = '_acme-challenge.' + name

    # Подключение к api NIC
    api = nic_api.DnsApi(NIC_OAUTH_CONFIG)
    api.logger = logger
    api.authorize(
        username=NIC_USERNAME,
        password=NIC_PASSWORD,
        token_filename=NIC_TOKEN_FILENAME)

    # Получаю все записи из DNS
    # API не умеет обновлять TXT запись, поэтому её сначала нужно удалить
    records = api.records(NIC_MY_SERVICE, NIC_MY_DOMAIN)
    for record in records:
        if hasattr(record, 'name'):
            if record.name == name:
                logger.info('Удаляю TXT запись: (id: %s, name: %s)' % (record.id, record.name))
                api.delete_record(record.id, NIC_MY_SERVICE, NIC_MY_DOMAIN)

    # Создаю TXT запись
    txt_record = nic_api.models.TXTRecord(name=name, txt=validation, ttl=ttl)
    api.add_record(txt_record, NIC_MY_SERVICE, NIC_MY_DOMAIN)
    # Применяю изменения в DNS зоне
    api.commit(NIC_MY_SERVICE, NIC_MY_DOMAIN)

    # Удаляю файл с токеном
    if os.path.isfile(NIC_TOKEN_FILENAME):
        os.remove(NIC_TOKEN_FILENAME)


def update_cer_by_ssh(settings):
    """Обновление сертификата на удаленном сервере"""
    # В этом импорте нет ошибки
    # Если поместить его вверх, будет ошибка циклического импорта
    from logger import logger

    with paramiko.SSHClient() as ssh:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ssh_host = settings.get('ssh_host')
        ssh_username = settings.get('ssh_username')
        ssh_pkey_file = settings.get('ssh_pkey_path')
        private_path = settings.get('private_path')
        fullchain_path = settings.get('fullchain_path')
        ssh_private_path = settings.get('ssh_private_path')
        ssh_fullchain_path = settings.get('ssh_fullchain_path')
        ssh_commands = settings.get('ssh_commands')

        logger.info('Обновляю сертификат на %s' % ssh_host)

        # Подтверждаем ключи от хостов автоматически
        privkey = paramiko.RSAKey.from_private_key_file(ssh_pkey_file)
        ssh.connect(ssh_host, username=ssh_username, pkey=privkey)
        with SCPClient(ssh.get_transport()) as scp:
            scp.put(private_path, remote_path=ssh_private_path)
            scp.put(fullchain_path, remote_path=ssh_fullchain_path)
            for command in ssh_commands:
                logger.info('%s: ssh-command: %s' % (ssh_host, command))
                stdin, stdout, stderr = ssh.exec_command(command)
                stdout = stdout.read().decode('utf-8')
                stderr = stderr.read().decode('utf-8')
                if stdout:
                    logger.info('%s: ssh-stdout: %s' % (ssh_host, stdout))
                if stderr:
                    logger.error('%s: ssh-stderr: %s' % (ssh_host, stderr))


def update_cer_local(settings):
    """Обновление сертификата на локальном сервере"""
    # В этом импорте нет ошибки
    # Если поместить его вверх, будет ошибка циклического импорта
    from logger import logger

    local_host = os.uname()[1]
    local_commands = settings.get('local_commands')
    private_path = settings.get('private_path')
    fullchain_path = settings.get('fullchain_path')
    local_private_path = settings.get('local_private_path')
    local_fullchain_path = settings.get('local_fullchain_path')

    logger.info('Обновляю сертификат на %s' % local_host)
    shutil.copyfile(private_path, local_private_path)
    shutil.copyfile(fullchain_path, local_fullchain_path)

    for command in local_commands:
        logger.info('%s: local_command: %s' % (local_host, command))
        process = Popen(command, stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = process.communicate()
        stdout = stdout.decode('utf-8')
        stderr = stderr.decode('utf-8')
        if stdout:
            logger.info('%s: local-stdout: %s' % (local_host, stdout))
        if stderr:
            logger.error('%s: local-stderr: %s' % (local_host, stderr))
