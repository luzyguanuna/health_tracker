app.pyimport os
import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)

    cash = cash_db[0]["cash"]

    total = cash

    transactions = db.execute(
        "SELECT symbol, SUM(shares) AS shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0",
        user_id,
    )

    for stock in transactions:
        quote = lookup(stock["symbol"])
        stock["name"] = quote["name"]
        stock["price"] = quote["price"]
        total += stock["price"] * stock["shares"]

    return render_template(
        "index.html", cash=cash, total=total, transactions=transactions
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # Check for if symbol is not provided
        if not symbol:
            return apology("must provide symbol")

        # Lookup the symbol
        stock = lookup(symbol.upper())

        # Check for if the symbol does not exist
        if stock == None:
            return apology("symbol does not exist")

        # Check for if the user provided an invalid number of shares
        if request.form.get("shares").isdigit() == False:
            return apology("number of shares must be a positive integer")

        # Check for if the user did not provide shares
        if not request.form.get("shares"):
            return apology("must provide number of shares")

        # Save the integer value of the number of shares
        shares = int(request.form.get("shares"))

        # Check that the user chose a positive number of shares
        if shares < 1:
            return apology("you must buy at least one share")

        # Create variables to hold the overall value and get the amount of cash
        value = shares * stock["price"]
        user_id = session["user_id"]
        cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        cash = cash_db[0]["cash"]

        # Return an error if there are insufficient funds for the purchase
        if cash < value:
            return apology("insufficient funds for purchase")

        # Update remaining cash after purchase
        cash = cash - value

        # Update the database with the transaction info
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, user_id)
        date_time = datetime.datetime.now()
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price, date_time) VALUES (?, ?, ?, ?, ?)",
            user_id,
            symbol,
            shares,
            stock["price"],
            date_time,
        )

        return redirect("/")

    # User reached route via GET
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Fetches the transaction history for the user
    user_id = session["user_id"]
    transactions = db.execute("SELECT * FROM transactions WHERE user_id  = ?", user_id)
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # User reached route via POST
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # Ensure symbol was submitted
        if not symbol:
            return apology("must provide symbol", 400)

        # Lookup the symbol
        result = lookup(symbol.upper())

        # Check for nonexistent symbol
        if result == None:
            return apology("symbol does not exist")

        # Return name, price, and symbol
        return render_template(
            "quoted.html",
            name=result["name"],
            price=result["price"],
            symbol=result["symbol"],
        )

    # User reached route via GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST
    if request.method == "POST":
        # Get username, password, and confirmation from forms
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        # Ensure password was re-submitted
        elif not confirm:
            return apology("must re-enter password", 400)

        # Ensure password contains a lowercase letter, uppercase letter, number, and symbol
        # Create count variables for each type
        lower, upper, number, symbol = 0, 0, 0, 0

        # Check frequency of each type and udate count variables
        for character in password:
            if character.islower():
                lower += 1
            if character.isupper():
                upper += 1
            if character.isdigit():
                number += 1
            if (
                character == "@"
                or character == "$"
                or character == "!"
                or character == "_"
            ):
                symbol += 1

        # Return error message if password does not meet security requirements
        if lower == 0 or upper == 0 or number == 0 or symbol == 0:
            return apology(
                "password must contain at least one lowercase letter, uppercase letter, number, and symbol"
            )

        # Ensure passwords match
        if password != confirm:
            return apology("passwords must match", 400)

        # Generate hash
        hash = generate_password_hash(password)

        # Add info to database
        try:
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)", username, hash
            )
        except:
            return apology("username already exists")

        # Redirect user to login form
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User reached route via POST
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # Check for if symbol not provided
        if not symbol:
            return apology("must provide symbol")

        # Lookup symbol
        stock = lookup(symbol.upper())

        # Check for if stock exists or not
        if stock == None:
            return apology("symbol does not exist")

        # Check for if shares is a valid integer
        if request.form.get("shares").isdigit() == False:
            return apology("number of shares must be a positive integer")

        # Check for if shares is provided or not
        if not request.form.get("shares"):
            return apology("must provide number of shares")

        # Store shares as an int
        shares = int(request.form.get("shares"))

        # Check for if shares is a positive integer
        if shares < 1:
            return apology("you must buy at least one share")

        # Calculate value of investments and fetch cash
        value = shares * stock["price"]
        user_id = session["user_id"]
        cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        cash = cash_db[0]["cash"]

        # I'm getting this weird bug when I use ? as a placeholder, so using the alternative method here instead
        # Get the current shares owned
        current_shares_db = db.execute(
            "SELECT shares FROM transactions WHERE user_id = :id AND symbol = :symbol GROUP BY symbol",
            id=user_id,
            symbol=symbol,
        )
        current_shares = current_shares_db[0]["shares"]

        # shares, user_id, symbol
        # Ensure user only sells shares they own
        if shares > current_shares:
            return apology("you cannot sell more shares than you own")

        # Update cash and database after sale
        cash = cash + value
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, user_id)
        date_time = datetime.datetime.now()
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price, date_time) VALUES (?, ?, ?, ?, ?)",
            user_id,
            symbol,
            shares * (-1),
            stock["price"],
            date_time,
        )

        return redirect("/")

    # User reached route via GET
    else:
        user_id = session["user_id"]

        # I'm getting this weird bug when I use ? as a placeholder, so using the alternative method here instead
        symbols = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = :id GROUP BY symbol HAVING SUM(shares) > 0",
            id=user_id,
        )
        return render_template(
            "sell.html", symbols=[stock["symbol"] for stock in symbols]
        )
