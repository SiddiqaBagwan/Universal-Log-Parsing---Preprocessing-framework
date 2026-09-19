import psycopg2

DB_CONFIG = {
    "host": "localhost",
    "database": "lognexus",
    "user": "postgres",
    "password": "@Sid786Fir",
    "port": 5432
}


def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)


def init_db():
    conn = get_db_connection()
    conn.close()