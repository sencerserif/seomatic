import sqlite3

DATABASE_NAME = 'seomatic_users.db'

def init_db():
    """Veritabanını başlatır ve kullanıcı tablosunu oluşturur."""
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def add_user(username, password):
    """Yeni bir kullanıcı ekler."""
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    try:
        # Gerçek bir uygulamada parolayı HASH'lemelisiniz (örn: bcrypt)
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Kullanıcı adı zaten mevcut
    finally:
        conn.close()

def verify_user(username, password):
    """Kullanıcı adı ve parolayı doğrular."""
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    # Gerçek bir uygulamada HASH'lenmiş parolayı doğrulamalısınız
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = c.fetchone()
    conn.close()
    return user is not None

# Kurulum sırasında varsayılan bir kullanıcı ekle (Demo amaçlı):
init_db()
if not verify_user('seomatic', '12345'):
    add_user('seomatic', '12345') # Varsayılan Kullanıcı: seomatic / 12345