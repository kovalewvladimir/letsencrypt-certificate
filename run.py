import os
from time import sleep

from check import check_ssl
from get_letsencrypt_certificate import get_letsencrypt_certificate
from lib.ThreadWithReturnValue import ThreadWithReturnValue
from logger import (logger, send_message_telegram)
from settings import (CERTIFICATE,
                      LOG_HTTP_SERVER_IP,
                      LOG_HTTP_SERVER_PORT_GUI,
                      LOG_HTTP_SERVER_PATH,
                      LOG_FILE)

if __name__ == "__main__":
    try:
        send_message_telegram(
            '<b>Запускаю скрипт обновления сертификатов</b>\n'
            'Скрипт:\n'
            '    <code>%(hn)s:%(script)s</code>\n'
            'Логи:\n'
            '    • <a href="http://%(h_url)s:%(p_url)s%(url)s">http://%(h_url)s:%(p_url)s%(url)s</a>\n'
            '    • <code>%(hn)s:%(file)s</code> \n' % {
                'h_url': LOG_HTTP_SERVER_IP,
                'p_url': LOG_HTTP_SERVER_PORT_GUI,
                'url': LOG_HTTP_SERVER_PATH,
                'hn': os.uname()[1],
                'file': LOG_FILE,
                'script': __file__,
            }
        )

        # Запуск нескольких потоков для получения сертификатов
        for name, settings in CERTIFICATE.items():
            domain = settings.get('domain')
            email = settings.get('email')
            update_txt = settings.get('update_txt')
            worker = ThreadWithReturnValue(target=get_letsencrypt_certificate,
                                           args=(email, domain, update_txt),
                                           name=name)
            settings['worker'] = worker
            worker.daemon = True
            worker.start()
            # Задержка между стартами потоков
            # Если убрать, то будет конфликт при обновлении TXT записи
            # тк одновременно будут пытаться обновиться TXT записи на одном DNS хостинге
            sleep(60)
        for name, settings in CERTIFICATE.items():
            worker = settings.get('worker')
            worker_result = worker.join()
            if worker_result is None:
                raise Exception('Нет файлов сертификата')
            settings['private_path'] = worker_result.get('private_path')
            settings['fullchain_path'] = worker_result.get('fullchain_path')

        # Обновляем сертификаты на серверах
        for name, settings in CERTIFICATE.items():
            update_cer = settings.get('update_cert')
            update_cer(settings)

        # Проверяем обновились ли сертификаты
        msg = '<b>Сертификаты:</b>\n'
        success = u'\U00002705'
        error = u'\U0000274C'
        warning = u'\U000026A0'
        msg_error = ''
        for key, value in CERTIFICATE.items():
            hosts = value.get('domain')
            ports = value.get('port')
            for host in hosts:
                for port in ports:
                    if check_ssl(host, port):
                        msg += '    %s - %s:%s\n' % (success, host, port)
                    else:
                        msg_error = '\n%(warning)s\n' \
                                    '<b>Проверьте логи</b>\n' \
                                    'или выпускайте сертификаты вручную ' \
                                    '<code>S:\_WORK\Инструкции\_NEW' \
                                    '\Обновление всех сертификатов letsencrypt.docx</code>\n' \
                                    '%(warning)s' % {'warning': warning*10}
                        msg += '    %s - %s:%s\n' % (error, host, port)
        msg += msg_error
        send_message_telegram(msg)
    except KeyboardInterrupt:
        logger.error('Принудительный выход')
    except Exception as e:
        logger.error(str(e), exc_info=True)

        warning = u'\U000026A0'
        send_message_telegram(
            '%(warning)s\n'
            '<b>Ошибка при обновлении сертификатов</b>\n'
            '%(error)s\n' 
            '%(warning)s\n' % {
                'error': str(e),
                'warning': warning*10,
            }
        )
