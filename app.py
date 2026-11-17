
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from contextlib import closing
import sqlite3
import os

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "gamehub-chiave-segreta-da-cambiare"
)

DATABASE = os.path.join(app.root_path, "database.db")


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
                role TEXT NOT NULL DEFAULT 'user'
            )
        """)
        conn.commit()


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

        with closing(get_db_connection()) as conn:

            try:
                conn.execute("""
                    INSERT INTO users (username, email, password)
                    VALUES (?, ?, ?)
                """, (username, email, password_hash))

                conn.commit()

            except sqlite3.IntegrityError:
                flash("Questa email è già registrata.")
                return redirect(url_for("register"))

        flash("Registrazione completata! Ora puoi accedere.")
        return redirect(url_for("login"))

    return render_template("register.html")


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


# AVVIO APPLICAZIONE

if __name__ == "__main__":

    init_db()

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )

