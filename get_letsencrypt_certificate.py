"""VEK 2019/06/04
Скрпит для получения сертификата letsencrypt для одного домена.
Подтверждение права собственности на домен происходит с помощью
создания txt записи в dns.

За основу взят https://github.com/certbot/certbot/blob/master/acme/examples/http01_example.py
"""
import os
import shutil
from datetime import datetime
from time import sleep

import OpenSSL
import dns.resolver
import josepy as jose
from acme import challenges
from acme import client
from acme import crypto_util
from acme import messages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from logger import logger
from settings import (ACC_KEY_BITS,
                      CERT_PKEY_BITS,
                      DIRECTORY_URL,
                      USER_AGENT,
                      TIME_SLEEP,
                      MAX_COUNT_REQUEST,
                      CERTIFICATE_FOLDER)

# Переменная для выполнения dns запросов
dns_resolver = dns.resolver.Resolver(configure=False)


def _get_dns_ns(domain):
    """
    Запрос ip адресов dns серверов обслуживающие домен
    :param domain: Домен
    :return: Массив ip адресов dns серверов
    """
    _dns_resolver = dns.resolver.Resolver(configure=False)
    _dns_resolver.nameservers = ['8.8.8.8']

    ns_servers = list()
    answer = None
    while answer is None:
        try:
            logger.info('Запрос NS записи для %s' % domain)
            answer = _dns_resolver.query(domain, dns.rdatatype.NS)
            for ns in answer:
                ns_servers.append(str(ns))
            logger.info('NS записи для %s: %s' % (domain, ns_servers))
        except dns.resolver.NoAnswer:
            # Удаляет поддомен. test.domain.ru -> domain.ru
            logger.warning('NS запись для %s не найдена' % domain)
            domain = domain[len(domain.split('.')[0]) + 1:]
        except Exception:
            message = 'Не существует домена %s' % domain
            logger.error(message)
            raise Exception(message)

    ip_addresses = list()
    for ns in ns_servers:
        answer = _dns_resolver.query(ns, dns.rdatatype.A)
        for ip in answer:
            ip_addresses.append(str(ip))

    logger.info('IP адреса DNS серверов, которые обслуживают домен %s: %s' % (domain, ip_addresses))

    return ip_addresses


def _dns_query_and_check(domain, dns_servers, validation):
    """
    Проверка TXT записи на DNS серверах
    :param domain: Домен
    :param dns_servers: DNS сервера для проверки.
                        Если на dns сервера запись совпадает с validation,
                        то этот сервер удаляется из массива.
    :param validation: Строка для проверки
    :return: None, но изменяется массив dns_servers!!!
    """
    remove_dns = list()
    for dns_server in dns_servers:
        dns_resolver.nameservers = [dns_server]
        txt = dns_resolver.query('_acme-challenge.%s' % domain, dns.rdatatype.TXT)[0].strings[0].decode('utf-8')
        if txt == validation:
            remove_dns.append(dns_server)
    for rd in remove_dns:
        dns_servers.remove(rd)


def _check_txt(domain, validation):
    """
    Главная функция для проверки TXT записи
    :param domain: Домен
    :param validation: Строка для проверки
    :return: None. Тормозит поток пока не будет актуальная запись на всех
             DNS серверах. Список DNS серверов можно посмотеть в функции _get_dns_ns
    """
    dns_servers = _get_dns_ns(domain)
    name_servers = dns_servers.copy()

    time_start = datetime.now()

    count_request = 0
    while len(name_servers) != 0:
        count_request += 1
        if count_request > MAX_COUNT_REQUEST:
            message = 'Превышено максимальное кол-во DNS запросов (%d)! ' \
                      'Домен: %s' % (MAX_COUNT_REQUEST, domain)
            logger.error(message)
            raise Exception(message)
        sleep(TIME_SLEEP)
        try:
            _dns_query_and_check(domain, name_servers, validation)
            count_dns_servers = len(dns_servers)
            count_actual = count_dns_servers - len(name_servers)
            logger.info('Актуальная TXT запись на %2d DNS серверах. '
                        'Всего DNS серверов: %2d. '
                        'Не актуальна на: %s' % (count_actual, count_dns_servers, name_servers))
        except dns.resolver.NXDOMAIN:
            logger.warning('TXT записи не существует _acme-challenge.%s' % domain)
    time_total = datetime.now() - time_start
    logger.info('Итого затрачено времени: %s' % str(time_total))


def _new_csr_comp(domain_name, pkey_pem=None):
    """
    Create certificate signing request.
    Создание ключей для подписания запросов
    """
    if pkey_pem is None:
        # Create private key.
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, CERT_PKEY_BITS)
        pkey_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                  pkey)
    csr_pem = crypto_util.make_csr(pkey_pem, domain_name)
    return pkey_pem, csr_pem


def _select_dns01_chall(order):
    """Extract authorization resource from within order resource."""
    # Authorization Resource: authz.
    # This object holds the offered challenges by the server and their status.
    authz_list = order.authorizations

    dns_challenges = list()
    for authz in authz_list:
        # Choosing challenge.
        # authz.body.challenges is a set of ChallengeBody objects.
        is_no_dns = True
        for i in authz.body.challenges:
            # Find the supported challenge.
            if isinstance(i.chall, challenges.DNS01):
                dns_challenges.append({
                    'domain': authz.body.identifier.value,
                    'challenge': i,
                })
                is_no_dns = False
        if is_no_dns:
            raise Exception('DNS-01 challenge was not offered by the CA server.')
    return dns_challenges


def _move_to_archive(directory, path_file, name_file):
    """Перемещение файла в архив"""
    if os.path.exists(path_file):
        mtime = os.path.getmtime(path_file)
        mtime_str = datetime.utcfromtimestamp(mtime).strftime('%Y.%m.%d_%H_%M')
        archive_dir = os.path.join(directory, 'archive', mtime_str)

        # TODO: Поиграться с правами
        os.makedirs(archive_dir, mode=0o777, exist_ok=True)

        shutil.move(path_file, os.path.join(archive_dir, name_file))


def _save_certificate(directory, pkey_pem, fullchain_pem):
    """
    Функция сохраняет сертификат и приватный ключ в файл
    :param directory: Каталог куда сохранять
    :param pkey_pem: Приватный ключ
    :param fullchain_pem: Сертификат
    :return: None
    """
    # TODO: Поиграться с правами
    # Создание каталога
    os.makedirs(directory, mode=0o777, exist_ok=True)

    # Имена файлов
    private_name_file = 'private.pem'
    fullchain_name_file = 'fullchain.pem'

    # Абсолютный путь до файлов
    private_path = os.path.join(directory, private_name_file)
    fullchain_path = os.path.join(directory, fullchain_name_file)

    # Проверка на существование файлов
    # Если существуют, то перемещает их в архив
    _move_to_archive(directory, private_path, private_name_file)
    _move_to_archive(directory, fullchain_path, fullchain_name_file)

    # Сохраняю файлы
    with open(private_path, 'wb', ) as f_pkey:
        f_pkey.write(pkey_pem)
        logger.info('Сертификат готов (приватный ключ): %s' % private_path)
    with open(fullchain_path, 'w') as f_fullchain:
        f_fullchain.write(fullchain_pem)
        logger.info('Сертификат готов (сертификат): %s' % fullchain_path)
    return private_path, fullchain_path


def get_letsencrypt_certificate(email, domain, update_txt, directory=CERTIFICATE_FOLDER, check_txt=_check_txt):
    """
    Функция для получения letsencrypt сертификата
    :param email:      Электронная почта для регистрации аккаунта
    :param domain:     Домен для которого нужно выпустить сертификат.
                       Тип tuple. пример ('test.ru') или ('test.ru', 'www.test.ru')
    :param directory:  Абсолютный путь до каталога куда будут сохранены сертификаты.
                       Путь к сертификатам будет directory + domain
    :param update_txt: Функция для обновления txt записи в DNS. Входные параметры: domain, validation
    :param check_txt:  Функция для проверки txt записи в DNS. Входные параметры: domain, validation
                       Функция должна тормозить основной поток пока не будет создана и ПРОВЕРЕНА TXT запись
    :return:           Приватный ключ pkey_pem, Сертификат fullchain_pem
    """
    try:
        if not isinstance(domain, list):
            raise ValueError('Тип переменной domain не list')

        # Генерация ключа аккаунта
        acc_key = jose.JWKRSA(
            key=rsa.generate_private_key(public_exponent=65537,
                                         key_size=ACC_KEY_BITS,
                                         backend=default_backend()))

        # Регистрация аккаунта
        net = client.ClientNetwork(acc_key, user_agent=USER_AGENT)
        directory_acme = messages.Directory.from_json(net.get(DIRECTORY_URL).json())
        client_acme = client.ClientV2(directory_acme, net=net)

        regr = client_acme.new_account(
            messages.NewRegistration.from_data(
                email=email, terms_of_service_agreed=True))

        # Создать личный ключ домена и CSR
        pkey_pem, csr_pem = _new_csr_comp(domain)

        # Создание запроса на выдачу сертификата
        order = client_acme.new_order(csr_pem)

        # Выбор подтверждение права собственности на домен с помощью DNS-01
        # в рамках предложенных задач сервером CA
        dns_challenges = _select_dns01_chall(order)

        for dns_challenge in dns_challenges:
            challb = dns_challenge.get('challenge')
            response, validation = challb.response_and_validation(client_acme.net.key)
            dns_challenge['response'] = response
            dns_challenge['validation'] = validation

        # Создание записи txt в dns
        for dns_challenge in dns_challenges:
            update_txt(dns_challenge.get('domain'), dns_challenge.get('validation'))
        # Проверка записи txt в dns
        for dns_challenge in dns_challenges:
            check_txt(dns_challenge.get('domain'), dns_challenge.get('validation'))

        # Let the CA server know that we are ready for the challenge.
        # Пусть сервер CA знает, что мы готовы к вызову.
        for dns_challenge in dns_challenges:
            challb = dns_challenge.get('challenge')
            response = dns_challenge.get('response')
            client_acme.answer_challenge(challb, response)

        # Wait for challenge status and then issue a certificate.
        # It is possible to set a deadline time.
        # Подождите, пока статус вызова, а затем выдать сертификат.
        # Можно установить крайний срок.
        finalized_order = client_acme.poll_and_finalize(order)

        # The certificate is ready to be used in the variable "fullchain_pem".
        # Сертификат готов к использованию в переменной "fullchain_pem".
        fullchain_pem = finalized_order.fullchain_pem

        # Сохранения приватного ключа и сертификата в файл
        private_path, fullchain_path = _save_certificate(os.path.join(directory, '_'.join(domain)),
                                                         pkey_pem,
                                                         fullchain_pem)

        # TODO: Проверить нужно/можно ли деактивировать аккаунт
        # Deactivate account/registration
        # regr = client_acme.deactivate_registration(regr)

        return {'private_path': private_path, 'fullchain_path': fullchain_path}
    except Exception as e:
        logger.error(str(e), exc_info=True)
