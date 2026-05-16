from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route('/health')
def health():
    return 'ok'


@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    # Vulnerabilidad intencional: command injection sin sanitización
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True, capture_output=True, text=True, timeout=5
    )
    return result.stdout + result.stderr


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
