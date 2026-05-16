import json
import logging
from datetime import datetime

import pymysql
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Log de app en JSON (canal secundario, semántico)
app_logger = logging.getLogger("webapp")
handler = logging.FileHandler("/var/log/app/app.log")
handler.setFormatter(logging.Formatter("%(message)s"))
app_logger.addHandler(handler)
app_logger.setLevel(logging.INFO)


def log_event(event_type, **kwargs):
    app_logger.info(json.dumps({
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        **kwargs,
    }))


def get_db():
    return pymysql.connect(
        host="127.0.0.1",
        user="webapp",
        password="webapp123",
        database="webapp",
        cursorclass=pymysql.cursors.Cursor,
    )


LOGIN_PAGE = """
<!DOCTYPE html><html><body>
<h1>Login</h1>
<form method="POST">
  <input name="username" placeholder="Usuario"><br>
  <input name="password" type="password" placeholder="Password"><br>
  <button type="submit">Entrar</button>
</form>
{% if message %}<p>{{ message }}</p>{% endif %}
</body></html>
"""


@app.route("/health")
def health():
    return "ok", 200


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABILIDAD INTENCIONAL: SQL injection
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

        try:
            db = get_db()
            c = db.cursor()
            c.execute(query)
            result = c.fetchone()
            db.close()

            if result:
                log_event("authentication_success",
                          username=username,
                          role=result[3],
                          source_ip=request.remote_addr)
                return render_template_string(
                    LOGIN_PAGE,
                    message=f"Bienvenido {result[1]}, rol: {result[3]}"
                )
            else:
                log_event("authentication_failure",
                          username=username,
                          source_ip=request.remote_addr)
                return render_template_string(LOGIN_PAGE,
                    message="Credenciales inválidas")

        except pymysql.Error as e:
            log_event("database_error", error=str(e), username=username)
            return render_template_string(LOGIN_PAGE, message=f"Error: {e}")

    return render_template_string(LOGIN_PAGE, message=None)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
