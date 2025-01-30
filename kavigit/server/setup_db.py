import sqlite3

DATABASE = 'vpn_project.db'

def create_tables():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER,
            message TEXT,
            message_hash TEXT,
            is_received BOOLEAN,
            FOREIGN KEY (client_id) REFERENCES clients(id)
        );
    ''')
    conn.commit()
    conn.close()

if __name__ == "__main__":
    create_tables()
