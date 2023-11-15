import ssl
import socket
import sqlite3
from OpenSSL import crypto

# Функция для определения версии SSL
def get_ssl_version(host, port):
    context = ssl.create_default_context()
    connection = context.wrap_socket(socket.create_connection((host, port)), server_hostname=host)
    return connection.version()

# Функция для получения доменов из SSL-сертификата
def get_ssl_cert_domains(host, port):
    cert_data = ssl.get_server_certificate((host, port))
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
    domains = [name.decode() for name, _ in x509.get_subject().get_components() if name == b'CN']
    return domains

# Функция для записи результатов в базу данных SQLite
def write_to_database(host, port, ssl_version, domains):
    conn = sqlite3.connect('ssl_info.db')
    cursor = conn.cursor()

    # Создаем таблицу, если она не существует
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ssl_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT,
            port INTEGER,
            ssl_version TEXT,
            domains TEXT,
            UNIQUE(host, port)
        )
    ''')

    # Используем INSERT OR REPLACE с подзапросом для выбора уникальных записей
    cursor.execute('''
        INSERT OR REPLACE INTO ssl_info (host, port, ssl_version, domains)
        SELECT ?, ?, ?, ?
        WHERE NOT EXISTS (SELECT 1 FROM ssl_info WHERE host = ? AND port = ?)
    ''', (host, port, ssl_version, ', '.join(domains), host, port))

    conn.commit()
    conn.close()



# Чтение данных из файла
with open('hosts.txt', 'r') as file:
    for line in file:
        host, port = line.strip().split(':')
        port = int(port)

        ssl_version = get_ssl_version(host, port)
        domains = get_ssl_cert_domains(host, port)

        print(f"Host: {host}, Port: {port}, SSL Version: {ssl_version}, Domains: {domains}")

        # Запись результатов в базу данных
        write_to_database(host, port, ssl_version, domains)

