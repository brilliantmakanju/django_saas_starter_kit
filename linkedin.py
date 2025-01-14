import requests
import time
import webbrowser
from urllib.parse import urlencode

# Step 1: Set your LinkedIn API credentials and redirect URI
LINKEDIN_CLIENT_ID = ''  # Replace with your LinkedIn app's client ID
LINKEDIN_CLIENT_SECRET = ''  # Replace with your LinkedIn app's client secret
LINKEDIN_REDIRECT_URI = ''  # This should match the redirect URI you set in LinkedIn app settings
LINKEDIN_SCOPE = ''

# Step 2: Generate LinkedIn authorization URL
def generate_linkedin_authorization_url():
    auth_url = f"https://www.linkedin.com/oauth/v2/authorization?{urlencode({
        'response_type': 'code',
        'client_id': LINKEDIN_CLIENT_ID,
        'redirect_uri': LINKEDIN_REDIRECT_URI,
        'scope': LINKEDIN_SCOPE
    })}"

    return auth_url

# Step 3: Get the access token using the authorization code
def get_linkedin_access_token(authorization_code):
    token_url = "https://www.linkedin.com/oauth/v2/accessToken"
    payload = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': LINKEDIN_REDIRECT_URI,
        'client_id': LINKEDIN_CLIENT_ID,
        'client_secret': LINKEDIN_CLIENT_SECRET,
    }

    retries = 5  # Number of retry attempts
    for attempt in range(retries):
        response = requests.post(token_url, data=payload)

        if response.status_code == 200:
            print("Access token retrieved successfully!")
            print(response.json(), "Tokens ")
            return response.json().get('access_token')
        elif response.status_code == 429:
            retry_after = int(response.headers.get('Retry-After', 60))  # Use 'Retry-After' header if available
            print(f"Rate limited. Retrying in {retry_after} seconds...")
            time.sleep(retry_after)
        else:
            print(f"Error: {response.status_code} - {response.text}")
            break  # Exit loop for non-retriable errors

    return None

def get_linkedin_member_id(access_token):
    me_url = "https://api.linkedin.com/v2/userinfo"
    headers = {
        "Authorization": f"Bearer {access_token}",
    }
    print("Bearer", access_token)

    response = requests.get(me_url, headers=headers)

    if response.status_code == 200:
        return response.json().get("sub")  # This is the LinkedIn member ID
    else:
        print(f"Failed to fetch LinkedIn member ID. Error: {response.status_code} - {response.text}")
        return None

# Step 4: Post content to LinkedIn
def post_on_linkedin(access_token, post_content):
    # Fetch the LinkedIn member ID
    member_id = get_linkedin_member_id(access_token)
    if not member_id:
        print("Unable to retrieve LinkedIn member ID. Aborting post.")
        return


    post_url = "https://api.linkedin.com/v2/ugcPosts"

    # Step 4: Prepare the post data
    post_data = {
        "author": f"urn:li:person:{member_id}",  # Use the fetched member ID
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary": {
                    "text": post_content
                },
                "shareMediaCategory": "NONE"
            }
        },
        "visibility": {
            "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
        }
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Restli-Protocol-Version": "2.0.0"
    }

    response = requests.post(post_url, json=post_data, headers=headers)
    if response.status_code == 201:
        print("Post successfully made on LinkedIn!")
    else:
        print(f"Failed to post on LinkedIn. Error: {response.status_code} - {response.text}")

# Step 5: Main function to authenticate and post
def main():
    # Step 1: Generate LinkedIn authorization URL and open it in a web browser
    print("Opening LinkedIn authorization URL...")
    # auth_url = generate_linkedin_authorization_url()
    # webbrowser.open(auth_url)

    # Step 2: User needs to copy the authorization code from LinkedIn after login
    authorization_code = input("Enter the authorization code from LinkedIn: ")

    # Step 3: Get the access token using the authorization code
    access_token = get_linkedin_access_token(authorization_code)
    if not access_token:
        print("Failed to get access token.")
        return

    # Step 4: Post content on LinkedIn
    post_content = """
    Your GitHub commits already tell a story—why not share it with the world? 🌍

    With DevPulse, transform your commit messages into engaging social media posts effortlessly. 🚀
    Let AI and automation handle the sharing while you focus on building amazing things. 🔧✨
    """

    post_on_linkedin(access_token, post_content)

if __name__ == '__main__':
    main()
