import logging.config
import sys

import telebot

from settings import (LOG_FILE,
                      LOG_HTTP_SERVER_ENABLE,
                      LOG_HTTP_SERVER_PATH,
                      LOG_HTTP_SERVER_IP,
                      LOG_HTTP_SERVER_PORT,
                      TELEGRAM_SOCKS5_ENABLE,
                      TELEGRAM_SOCKS5,
                      TELEGRAM
                      )

# Стандартный лог
handlers = ['fileHandler', 'consoleHandler']
log_config = {
    'version': 1,
    'handlers': {
        'fileHandler': {
            'class': 'logging.FileHandler',
            'formatter': 'verbose',
            'filename': LOG_FILE,
        },
        'consoleHandler': {
            'class': 'logging.StreamHandler',
            'stream': sys.stderr,
            'formatter': 'verbose'
        },
        'httpHandler': {
            'class': 'lib.SimpleHttpHandler.SimpleHttpHandler',
            'host': '%s:%s' % (LOG_HTTP_SERVER_IP, LOG_HTTP_SERVER_PORT),
            'url': LOG_HTTP_SERVER_PATH,
            'method': 'POST',
            'secure': False,
            'no_date': 'true',
            'formatter': 'verbose'
        },
    },
    'loggers': {
        'default': {
            'handlers': handlers,
            'level': 'INFO',
        }
    },
    'formatters': {
        'verbose': {
            'format': '%(asctime)s\t%(threadName)s:\t%(levelname)s:\t%(message)s'
        }
    }
}

if LOG_HTTP_SERVER_ENABLE:
    handlers.append('httpHandler')

logging.config.dictConfig(log_config)
logger = logging.getLogger('default')

# Лог в телеграмм
if TELEGRAM_SOCKS5_ENABLE:
    telebot.apihelper.proxy = {
        'https': 'socks5://%s:%s@%s' % (
            TELEGRAM_SOCKS5['proxy_username'],
            TELEGRAM_SOCKS5['proxy_pass'],
            TELEGRAM_SOCKS5['proxy_hostport']
        )
    }
    bot = telebot.TeleBot(TELEGRAM['token'])
else:
    bot = telebot.TeleBot(TELEGRAM['token'])


def send_message_telegram(msg, parse_mode='HTML'):
    bot.send_message(TELEGRAM['recipient'], msg, parse_mode=parse_mode)
