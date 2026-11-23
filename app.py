
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from contextlib import closing
from functools import wraps
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from email.message import EmailMessage
import sqlite3
import os
import smtplib

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "gamehub-chiave-segreta-da-cambiare"
)

DATABASE = os.path.join(app.root_path, "database.db")

# CONFIGURAZIONE EMAIL

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").strip().lower()


# DATABASE

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():

    with closing(get_db_connection()) as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                is_verified INTEGER NOT NULL DEFAULT 0
            )
        """)

        # Aggiornamento per database già esistenti

        columns = conn.execute(
            "PRAGMA table_info(users)"
        ).fetchall()

        column_names = [column["name"] for column in columns]

        if "is_verified" not in column_names:

            conn.execute("""
                ALTER TABLE users
                ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 1
            """)

        # Promozione dell'account amministratore

        if ADMIN_EMAIL:

            conn.execute("""
                UPDATE users
                SET role = 'admin'
                WHERE email = ?
            """, (ADMIN_EMAIL,))

        conn.commit()


# SISTEMA EMAIL

def generate_token(email):

    serializer = URLSafeTimedSerializer(app.secret_key)

    return serializer.dumps(
        email,
        salt="email-confirmation"
    )


def verify_token(token):

    serializer = URLSafeTimedSerializer(app.secret_key)

    try:

        email = serializer.loads(
            token,
            salt="email-confirmation",
            max_age=86400
        )

        return email

    except (SignatureExpired, BadSignature):

        return None


def send_confirmation_email(email):

    token = generate_token(email)

    link = url_for(
        "verify_email",
        token=token,
        _external=True
    )

    # Modalità di sviluppo senza SMTP

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:

        print("\nLINK DI CONFERMA EMAIL:")
        print(link)
        print()

        return False

    message = EmailMessage()

    message["Subject"] = "Conferma il tuo account GameHub"
    message["From"] = SMTP_USER
    message["To"] = email

    message.set_content(f"""
Benvenuto su GameHub!

Per attivare il tuo account clicca sul link:

{link}

Il link scade dopo 24 ore.

Se non hai richiesto la registrazione, ignora questa email.
""")

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:

        server.starttls()

        server.login(SMTP_USER, SMTP_PASSWORD)

        server.send_message(message)

    return True


# DECORATORI PER I PERMESSI

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            flash("Devi effettuare il login.")

            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def admin_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            flash("Devi effettuare il login.")

            return redirect(url_for("login"))

        if session.get("role") != "admin":

            flash("Non hai i permessi per accedere.")

            return redirect(url_for("home"))

        return function(*args, **kwargs)

    return wrapper


# HOMEPAGE

@app.route("/")
def home():

    return render_template("index.html")


# REGISTRAZIONE

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        if not username or not email or not password:

            flash("Compila tutti i campi.")

            return redirect(url_for("register"))

        if len(password) < 8:

            flash("La password deve avere almeno 8 caratteri.")

            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        # Assegna il ruolo admin solo all'email configurata

        role = "admin" if email == ADMIN_EMAIL and ADMIN_EMAIL else "user"

        with closing(get_db_connection()) as conn:

            try:

                conn.execute("""
                    INSERT INTO users
                    (username, email, password, role, is_verified)
                    VALUES (?, ?, ?, ?, 0)
                """, (username, email, password_hash, role))

                conn.commit()

            except sqlite3.IntegrityError:

                flash("Questa email è già registrata.")

                return redirect(url_for("register"))

        try:

            sent = send_confirmation_email(email)

            if sent:

                flash("Registrazione completata! Controlla la tua email.")

            else:

                flash("Registrazione completata. In sviluppo, il link è nel terminale.")

        except Exception:

            flash("Account creato, ma invio email non riuscito. Contatta l'amministratore.")

        return redirect(url_for("login"))

    return render_template("register.html")


# CONFERMA EMAIL

@app.route("/verify/<token>")
def verify_email(token):

    email = verify_token(token)

    if email is None:

        flash("Link non valido oppure scaduto.")

        return redirect(url_for("login"))

    with closing(get_db_connection()) as conn:

        user = conn.execute("""
            SELECT * FROM users WHERE email = ?
        """, (email,)).fetchone()

        if user is None:

            flash("Account non trovato.")

            return redirect(url_for("register"))

        conn.execute("""
            UPDATE users
            SET is_verified = 1
            WHERE email = ?
        """, (email,))

        conn.commit()

    flash("Email confermata! Ora puoi accedere.")

    return redirect(url_for("login"))


# LOGIN

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].strip().lower()
        password = request.form["password"]

        with closing(get_db_connection()) as conn:

            user = conn.execute("""
                SELECT * FROM users WHERE email = ?
            """, (email,)).fetchone()

        if user and check_password_hash(user["password"], password):

            if not user["is_verified"]:

                flash("Devi prima confermare la tua email.")

                return redirect(url_for("login"))

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            flash("Accesso effettuato!")

            return redirect(url_for("home"))

        flash("Email o password non corretti.")

        return redirect(url_for("login"))

    return render_template("login.html")


# LOGOUT

@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    flash("Hai effettuato il logout.")

    return redirect(url_for("home"))


# DASHBOARD AMMINISTRATORE

@app.route("/dashboard")
@admin_required
def dashboard():

    with closing(get_db_connection()) as conn:

        users = conn.execute("""
            SELECT id, username, email, role, is_verified
            FROM users
            ORDER BY id DESC
        """).fetchall()

        total_users = conn.execute("""
            SELECT COUNT(*) FROM users
        """).fetchone()[0]

        total_admins = conn.execute("""
            SELECT COUNT(*) FROM users
            WHERE role = 'admin'
        """).fetchone()[0]

        verified_users = conn.execute("""
            SELECT COUNT(*) FROM users
            WHERE is_verified = 1
        """).fetchone()[0]

    return render_template(
        "dashboard.html",
        users=users,
        total_users=total_users,
        total_admins=total_admins,
        verified_users=verified_users
    )


# MODIFICA RUOLO UTENTE

@app.route("/admin/change-role/<int:user_id>", methods=["POST"])
@admin_required
def change_role(user_id):

    new_role = request.form.get("role")

    if new_role not in ["user", "admin"]:

        flash("Ruolo non valido.")

        return redirect(url_for("dashboard"))

    if user_id == session["user_id"] and new_role != "admin":

        flash("Non puoi rimuovere il tuo ruolo amministratore.")

        return redirect(url_for("dashboard"))

    with closing(get_db_connection()) as conn:

        target = conn.execute("""
            SELECT * FROM users WHERE id = ?
        """, (user_id,)).fetchone()

        if target is None:

            flash("Utente non trovato.")

            return redirect(url_for("dashboard"))

        if target["role"] == "admin" and new_role == "user":

            admins = conn.execute("""
                SELECT COUNT(*) FROM users
                WHERE role = 'admin'
            """).fetchone()[0]

            if admins <= 1:

                flash("Deve rimanere almeno un amministratore.")

                return redirect(url_for("dashboard"))

        conn.execute("""
            UPDATE users
            SET role = ?
            WHERE id = ?
        """, (new_role, user_id))

        conn.commit()

    flash("Ruolo aggiornato correttamente.")

    return redirect(url_for("dashboard"))


# ELIMINAZIONE UTENTE

@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):

    if user_id == session["user_id"]:

        flash("Non puoi eliminare il tuo account dalla dashboard.")

        return redirect(url_for("dashboard"))

    with closing(get_db_connection()) as conn:

        user = conn.execute("""
            SELECT * FROM users WHERE id = ?
        """, (user_id,)).fetchone()

        if user is None:

            flash("Utente non trovato.")

            return redirect(url_for("dashboard"))

        if user["role"] == "admin":

            admins = conn.execute("""
                SELECT COUNT(*) FROM users
                WHERE role = 'admin'
            """).fetchone()[0]

            if admins <= 1:

                flash("Non puoi eliminare l'ultimo amministratore.")

                return redirect(url_for("dashboard"))

        conn.execute("""
            DELETE FROM users
            WHERE id = ?
        """, (user_id,))

        conn.commit()

    flash("Utente eliminato correttamente.")

    return redirect(url_for("dashboard"))


# AVVIO APPLICAZIONE

if __name__ == "__main__":

    init_db()

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )
