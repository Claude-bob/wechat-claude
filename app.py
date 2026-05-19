"""Entry point for Railway / Render deployment."""
from api.webhook import app

# Railway / Render expect `app` at module level
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
