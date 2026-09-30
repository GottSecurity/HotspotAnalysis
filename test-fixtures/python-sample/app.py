# Deliberate insecure sample for the hotspot navigator. Not a real application.

from flask import request, render_template_string
import pickle
import subprocess
import requests

DEBUG = True
password = "dev-only-example-key"


@app.route("/search")
def search():
    name = request.args.get("name")
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    subprocess.run(name, shell=True)
    requests.get(request.args.get("url"))
    pickle.loads(request.get_data())
    logger.info("password %s", password)
    return render_template_string(name)


@login_required
def account():
    return "ok"


@csrf_exempt
def update():
    User.objects.create(**request.form)
    resp.set_cookie("session", "abc")
    return "saved"
