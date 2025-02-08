from requests_oauthlib import OAuth1Session
import os
import json
from datetime import datetime

# In your terminal please set your environment variables by running the following lines of code.
# export 'CONSUMER_KEY'='<your_consumer_key>'
# export 'CONSUMER_SECRET'='<your_consumer_secret>'

CONSUMER_KEY = ""
CONSUMER_SECRET = ""
#
# pydantic==2.10.5
# pydantic_core==2.27.2
# pygraphviz==1.14

# File to save access tokens for reuse
TOKEN_FILE = "twitter_tokens.json"

def save_tokens(access_token, access_token_secret):
    """Save access tokens to a file."""
    with open(TOKEN_FILE, "w") as file:
        json.dump({"access_token": access_token, "access_token_secret": access_token_secret}, file)
    print("Access tokens saved for future use.")

def load_tokens():
    """Load access tokens from a file."""
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as file:
            tokens = json.load(file)
        return tokens.get("access_token"), tokens.get("access_token_secret")
    return None, None

def get_request_token():
    """Step 1: Get a request token and return the authorization URL."""
    request_token_url = "https://api.twitter.com/oauth/request_token?oauth_callback=oob&x_auth_access_type=write"
    oauth = OAuth1Session(CONSUMER_KEY, client_secret=CONSUMER_SECRET)

    try:
        fetch_response = oauth.fetch_request_token(request_token_url)
    except ValueError as e:
        print("Error fetching request token:", e)
        return None

    resource_owner_key = fetch_response.get("oauth_token")
    resource_owner_secret = fetch_response.get("oauth_token_secret")

    base_authorization_url = "https://api.twitter.com/oauth/authorize"
    authorization_url = oauth.authorization_url(base_authorization_url)

    return authorization_url, resource_owner_key, resource_owner_secret

def get_access_token(resource_owner_key, resource_owner_secret):
    """Step 2: Exchange verifier for access token."""
    verifier = input("Enter the PIN provided after authorization: ")
    access_token_url = "https://api.twitter.com/oauth/access_token"

    oauth = OAuth1Session(
        CONSUMER_KEY,
        client_secret=CONSUMER_SECRET,
        resource_owner_key=resource_owner_key,
        resource_owner_secret=resource_owner_secret,
        verifier=verifier,
    )

    try:
        oauth_tokens = oauth.fetch_access_token(access_token_url)
        access_token = oauth_tokens.get("oauth_token")
        access_token_secret = oauth_tokens.get("oauth_token_secret")

        print("Access token:", access_token)
        print("Access token secret:", access_token_secret)

        # Save tokens for reuse
        save_tokens(access_token, access_token_secret)
        return access_token, access_token_secret

    except Exception as e:
        print("Error fetching access token:", e)
        return None, None

def post_tweet(access_token, access_token_secret, tweet_text="Hello world!"):
    """Step 3: Post a tweet using the access token."""
    # Add a timestamp to ensure unique tweets
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    unique_tweet_text = f"{tweet_text} - {timestamp}"

    payload = {"text": unique_tweet_text}
    post_tweet_url = "https://api.twitter.com/2/tweets"

    oauth = OAuth1Session(
        CONSUMER_KEY,
        client_secret=CONSUMER_SECRET,
        resource_owner_key=access_token,
        resource_owner_secret=access_token_secret,
    )

    response = oauth.post(post_tweet_url, json=payload)

    if response.status_code == 201:
        print("Tweet posted successfully!")
        print(json.dumps(response.json(), indent=4))
    else:
        print("Error posting tweet:", response.status_code, response.text)

if __name__ == "__main__":
    # Step 1: Check if access tokens are already saved
    access_token, access_token_secret = load_tokens()

    if not access_token or not access_token_secret:
        print("No saved tokens found. Please authorize the app.")

        # Step 2: Get the authorization URL
        auth_url, owner_key, owner_secret = get_request_token()
        if auth_url:
            print(f"Go to this URL and authorize the app: {auth_url}")

            # Step 3: Fetch access token
            access_token, access_token_secret = get_access_token(owner_key, owner_secret)

    if access_token and access_token_secret:
        # Step 4: Post a unique tweet
        print("\nPosting a tweet...")
        post_tweet(access_token, access_token_secret)