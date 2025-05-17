from dotenv import load_dotenv
import threading
from core.utlis import generate_post_with_ai
load_dotenv()

def create_post_in_background(commit_message, tone, secret_key):
    def _worker():
        try:
            generate_post_with_ai(commit_message, tone, secret_key)
        except Exception as e:
            # Optional: log this error
            print(f"[PostCreationError] {commit_message} - Commit Message,  {tone} - Tone: {str(e)}")

    threading.Thread(target=_worker, daemon=True).start()
