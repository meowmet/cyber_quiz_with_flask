import os
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from cryptography.fernet import Fernet
import re


KEY_FILE = "key.key"
def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

FERNET_KEY = load_or_generate_key()
cipher_suite = Fernet(FERNET_KEY)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
def validate_password(password):
    if len(password) < 8:
        print("Password validation failed: too short")
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        print("Password validation failed: missing uppercase letter")
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        print("Password validation failed: missing lowercase letter")
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        print("Password validation failed: missing digit")
        return "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("Password validation failed: missing special character")
        return "Password must contain at least one special character."
    print("Password validated successfully")
    return None

def get_db_connection():
    conn = sqlite3.connect("finance.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("You must log in to access this page.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

STOCKS = {
    "AAPL": {"name": "Apple Inc.", "price": 254},
    "GOOG": {"name": "Alphabet Inc.", "price": 195},
    "AMZN": {"name": "Amazon.com Inc.", "price": 225},
    "MSFT": {"name": "Microsoft Corp.", "price": 434},
    "TSLA": {"name": "Tesla Inc.", "price": 428},
    "NFLX": {"name": "Netflix Inc.", "price": 910},
    "FB": {"name": "Meta Platforms Inc.", "price": 598},
    "NVDA": {"name": "NVIDIA Corp.", "price": 138},
    "BABA": {"name": "Alibaba Group", "price": 85},
    "TWTR": {"name": "Twitter Inc.", "price": 53},
}

def init_db():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hash TEXT NOT NULL,
            cash REAL NOT NULL DEFAULT 10000.0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            symbol TEXT NOT NULL,
            shares INTEGER NOT NULL,
            price REAL NOT NULL,
            type TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    conn.commit()
    conn.close()


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username or not password or not confirmation:
            flash("All fields are required", "error")
            return redirect("/register")
        if password != confirmation:
            flash("Passwords must match", "error")
            return redirect("/register")

        validation_error = validate_password(password)
        if validation_error:
            flash(validation_error, "error")
            return redirect("/register")

        encrypted_password = cipher_suite.encrypt(password.encode())
        conn = get_db_connection()

        try:
            conn.execute("INSERT INTO users (username, hash) VALUES (?, ?)", (username, encrypted_password))
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Username already exists", "error")
            return redirect("/register")
        finally:
            conn.close()

        flash("Registration successful! Please log in.", "success")
        return redirect("/login")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("All fields are required", "error")
            return redirect("/login")

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if not user:
            flash("Invalid username or password", "error")
            return redirect("/login")

        try:
            decrypted_password = cipher_suite.decrypt(user["hash"]).decode()
        except Exception as e:
            flash("Error decrypting password", "error")
            return redirect("/login")

        if password != decrypted_password:
            flash("Invalid username or password", "error")
            return redirect("/login")

        session["user_id"] = user["id"]
        flash("Logged in successfully!", "success")
        return redirect("/")
    return render_template("login.html")

@app.route("/")
@login_required
def index():
    user_id = session["user_id"]
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    transactions = conn.execute("""
        SELECT symbol, SUM(shares) AS shares
        FROM transactions
        WHERE user_id = ?
        GROUP BY symbol
        HAVING SUM(shares) > 0
    """, (user_id,)).fetchall()
    conn.close()

    portfolio = []
    total_value = user["cash"]
    for transaction in transactions:
        symbol = transaction["symbol"]
        shares = transaction["shares"]
        price = STOCKS[symbol]["price"]
        total_value += shares * price
        portfolio.append({
            "symbol": symbol,
            "name": STOCKS[symbol]["name"],
            "shares": shares,
            "price": price,
            "total": shares * price
        })

    return render_template("index.html", cash=user["cash"], portfolio=portfolio, total_value=total_value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        if not symbol or symbol not in STOCKS:
            return redirect(url_for("apology", message="Invalid stock symbol."))

        try:
            shares = int(shares)
            if shares <= 0:
                raise ValueError
        except ValueError:
            return redirect(url_for("apology", message="Invalid number of shares."))

        user_id = session["user_id"]
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        price = STOCKS[symbol]["price"]
        total_cost = price * shares

        if user["cash"] < total_cost:
            conn.close()
            return redirect(url_for("apology", message="You cannot afford this transaction."))

        conn.execute("UPDATE users SET cash = cash - ? WHERE id = ?", (total_cost, user_id))
        conn.execute("""
            INSERT INTO transactions (user_id, symbol, shares, price, type)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, symbol, shares, price, "buy"))
        conn.commit()
        conn.close()

        flash(f"Successfully bought {shares} shares of {symbol}!", "success")
        return redirect("/")

    return render_template("buy.html", stocks=STOCKS)


@app.route("/history")
@login_required
def history():
    """
    Displays the user's transaction history.
    """
    user_id = session["user_id"]
    conn = get_db_connection()

    transactions = conn.execute("""
        SELECT symbol, shares, price, type, timestamp
        FROM transactions
        WHERE user_id = ?
        ORDER BY timestamp DESC
    """, (user_id,)).fetchall()
    conn.close()

    return render_template("history.html", transactions=transactions)

@app.route("/apology")
def apology():
    message = request.args.get("message", "Something went wrong!")
    return render_template("apology.html", message=message)

@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()

        if not symbol or symbol not in STOCKS:
            return redirect(url_for("apology", message="Invalid stock symbol."))

        stock = STOCKS[symbol]

        return render_template("quoted.html", symbol=symbol, name=stock["name"], price=stock["price"])

    return render_template("quote.html")


@app.route("/logout")
def logout():
    
    session.clear()
    flash("You have been logged out.", "info")
    return render_template("logout.html")

@app.route("/symbols")
@login_required
def symbols():
   
    stock_list = [
        {"symbol": symbol, "name": data["name"], "price": data["price"]}
        for symbol, data in STOCKS.items()
    ]

    return render_template("symbols.html", stocks=stock_list)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        if not symbol or symbol not in STOCKS:
            return redirect(url_for("apology", message="Invalid stock symbol."))

        try:
            shares = int(shares)
            if shares <= 0:
                raise ValueError
        except ValueError:
            return redirect(url_for("apology", message="Invalid number of shares."))

        user_id = session["user_id"]
        conn = get_db_connection()
        holdings = conn.execute("""
            SELECT SUM(shares) AS shares
            FROM transactions
            WHERE user_id = ? AND symbol = ?
            GROUP BY symbol
        """, (user_id, symbol)).fetchone()

        if not holdings or holdings["shares"] < shares:
            conn.close()
            return redirect(url_for("apology", message="You don't own enough shares to sell."))

        price = STOCKS[symbol]["price"]
        total_income = price * shares
        conn.execute("UPDATE users SET cash = cash + ? WHERE id = ?", (total_income, user_id))
        conn.execute("""
            INSERT INTO transactions (user_id, symbol, shares, price, type)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, symbol, -shares, price, "sell"))
        conn.commit()
        conn.close()

        flash(f"Successfully sold {shares} shares of {symbol}!", "success")
        return redirect("/")

    return render_template("sell.html", stocks=STOCKS)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
