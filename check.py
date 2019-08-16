import ssl
from datetime import datetime, timedelta

import OpenSSL

from logger import logger


def check_ssl(host, port):
    """Проверка сертификатов"""
    cert = ssl.get_server_certificate((host, port))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    not_after = datetime.strptime(x509.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%SZ")
    not_before = datetime.strptime(x509.get_notBefore().decode('utf-8'), "%Y%m%d%H%M%SZ")
    # Попровка на часовой пояс MSK (UTC+3)
    not_before += timedelta(hours=3)
    not_after += timedelta(hours=3)

    logger.info('Сертификат %s:%s. '
                'Выпущен: %s. '
                'Истекает: %s. '
                'Часовой пояс MSK (UTC+3) ' % (host, port, not_before, not_after))
    if not_before.date() == datetime.now().date():
        logger.info('Сертификат проверен %s:%s. Все хорошо' % (host, port))
        return True
    else:
        logger.error('Сертификат не обновлен %s:%s.' % (host, port))
        return False
