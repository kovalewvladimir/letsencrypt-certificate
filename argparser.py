import argparse

parser = argparse.ArgumentParser(description='Обновляет сертификаты.')
parser.add_argument('--socks5',
                    default="yes",
                    help="Вкл/откл использование socks5 при отправке сообщений в Telegram(yes/no)")
args = parser.parse_args()