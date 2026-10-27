import sys
import os
import re
from urllib.parse import urlparse

from flask import Flask, render_template, request


# ==========================================
# Add src folder to Python path
# ==========================================

SRC_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "src"
    )
)

sys.path.insert(0, SRC_PATH)


# ==========================================
# Import PhishGuard AI V6
# ==========================================

from predict_v6 import predict_url


# ==========================================
# Flask application
# ==========================================

app = Flask(__name__)


# ==========================================
# URL validation
# ==========================================

def validate_url(url):

    if not url:
        return False, "Please enter a URL before scanning."

    normalized_url = url.strip()

    if not re.match(r"^https?://", normalized_url, re.IGNORECASE):
        normalized_url = "https://" + normalized_url

    try:
        parsed = urlparse(normalized_url)

        hostname = parsed.hostname

        if not hostname:
            return False, "Please enter a valid website URL."

        if "." not in hostname:
            return False, "Please enter a complete website address, such as https://example.com."

        if " " in hostname:
            return False, "The URL contains spaces. Please enter a valid website address."

        if len(hostname) > 253:
            return False, "The website address is too long."

        return True, ""

    except ValueError:
        return False, "Please enter a valid website URL."


# ==========================================
# Home page
# ==========================================

@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    error = None

    if request.method == "POST":

        url = request.form.get(
            "url",
            ""
        ).strip()

        is_valid, validation_error = validate_url(url)

        if not is_valid:

            error = validation_error

        else:

            try:

                result = predict_url(url)
                print("FLASK RESULT:", repr(result))
                print("FLASK RESULT TYPE:", type(result))     
                if not result:
                    error = "The scanner did not return a result. Please try again."

            except Exception as exc:

                print(f"PhishGuard scan error: {exc}")

                error = (
                    "The URL could not be analyzed safely. "
                    "Please check the URL format and try again."
                )

    return render_template(
        "index.html",
        result=result,
        error=error
    )


# ==========================================
# Global error handler
# ==========================================

@app.errorhandler(500)
def internal_server_error(error):

    print(f"Flask internal error: {error}")

    return render_template(
        "index.html",
        result=None,
        error="Something went wrong while processing the request. Please try again."
    ), 500


# ==========================================
# Run Flask
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )
# ==========================================
# Run Flask
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )