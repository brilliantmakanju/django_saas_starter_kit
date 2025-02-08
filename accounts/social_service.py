from requests_oauthlib import OAuth1Session
from django.http import JsonResponse
from core.models import SocialMediaAccount
from django.conf import settings
import requests
from urllib.parse import urlencode


# Twitter Function to post on user behalf
def twitter_initiate_oauth(request):
    """
    Initiates the Twitter OAuth process and returns the authorization URL.
    """
    request_token_url = "https://api.twitter.com/oauth/request_token?oauth_callback=oob&x_auth_access_type=write"
    oauth = OAuth1Session(settings.TWITTER_API_KEY, client_secret=settings.TWITTER_API_SECRET)

    try:
        fetch_response = oauth.fetch_request_token(request_token_url)
        resource_owner_key = fetch_response.get("oauth_token")
        resource_owner_secret = fetch_response.get("oauth_token_secret")
    except ValueError as e:
        return JsonResponse({"error": "Error fetching request token", "details": str(e)}, status=500)

    # Save the keys in the session for tracking
    request.session["resource_owner_key"] = resource_owner_key
    request.session["resource_owner_secret"] = resource_owner_secret

    # Generate the authorization URL
    base_authorization_url = "https://api.twitter.com/oauth/authorize"
    authorization_url = oauth.authorization_url(base_authorization_url)

    return JsonResponse({"authorization_url": authorization_url})

def twitter_callback_oauth(request, organization):
    """
    Handles the callback and exchanges the verifier code for access tokens.
    """
    verifier = request.data.get("code")  # Or passed from the frontend input
    resource_owner_key = request.session.get("resource_owner_key")
    resource_owner_secret = request.session.get("resource_owner_secret")

    if not verifier or not resource_owner_key or not resource_owner_secret:
        return JsonResponse({"error": "Missing verifier or session data."}, status=400)

    access_token_url = "https://api.twitter.com/oauth/access_token"
    oauth = OAuth1Session(
        settings.TWITTER_API_KEY,
        client_secret=settings.TWITTER_API_SECRET,
        resource_owner_key=resource_owner_key,
        resource_owner_secret=resource_owner_secret,
        verifier=verifier,
    )

    try:
        oauth_tokens = oauth.fetch_access_token(access_token_url)
        access_token = oauth_tokens.get("oauth_token")
        access_token_secret = oauth_tokens.get("oauth_token_secret")

        # Save tokens in the database
        SocialMediaAccount.objects.update_or_create(
            organization=organization,
            platform=SocialMediaAccount.TWITTER,
            defaults={
                'user': request.user,
                'access_token': access_token,
                'access_token_secret': access_token_secret,
            }
        )

        return JsonResponse({"message": "Twitter account connected successfully!"})
    except Exception as e:
        return JsonResponse({"error": "Error fetching access token", "details": str(e)}, status=500)

def post_tweet(tweet_text, organization):
    """
    Posts a tweet using the stored Twitter access tokens.
    """
    print(f"Attempting to post a tweet for organization: {organization}")

    # Retrieve the associated Twitter account for the organization
    twitter_oauth = SocialMediaAccount.objects.filter(organization=organization).first()

    if not twitter_oauth:
        print(f"No Twitter account connected for organization: {organization}")
        return JsonResponse({"error": "Twitter account not connected."}, status=400)

    print(f"Found Twitter account for organization: {organization}")
    print(f"Access token: {twitter_oauth.access_token}")

    # Prepare the payload to post the tweet
    payload = {"text": tweet_text}
    post_tweet_url = "https://api.twitter.com/2/tweets"

    # Set up OAuth1 session for authentication
    oauth = OAuth1Session(
        settings.TWITTER_API_KEY,
        client_secret=settings.TWITTER_API_SECRET,
        resource_owner_key=twitter_oauth.access_token,
        resource_owner_secret=twitter_oauth.access_token_secret,
    )

    print(f"Making a POST request to Twitter API: {post_tweet_url}")
    response = oauth.post(post_tweet_url, json=payload)

    # Check the response status code and handle accordingly
    if response.status_code == 201:
        print(f"Tweet posted successfully. Response: {response.json()}")
        return JsonResponse({"message": "Tweet posted successfully!"})

    # if response.status_code == 429:
    #     retry_after = 15 * 60  # Wait for 15 minutes (default)
    #     print("Rate limit exceeded. Retrying after 15 minutes...")
    #     time.sleep(retry_after)

    else:
        print(f"Error posting tweet. Status code: {response.status_code}, Response: {response.json()}")
        return JsonResponse(
            {"error": response.json(), "status_code": response.status_code}, status=500
        )


# LinkedIn API Credentials
LINKEDIN_CLIENT_ID = settings.LINKEDIN_CLIENT_ID
LINKEDIN_CLIENT_SECRET = settings.LINKEDIN_CLIENT_SECRET
LINKEDIN_REDIRECT_URI = settings.LINKEDIN_REDIRECT_URI
LINKEDIN_SCOPE = settings.LINKEDIN_SCOPE

# LinkedIn Function to post on user behalf
def linkedin_initiate_oauth(request):
    """
    Initiates the LinkedIn OAuth process and returns the authorization URL.
    """

    auth_url = "https://www.linkedin.com/oauth/v2/authorization?{}".format(
        urlencode({
            'response_type': 'code',
            'client_id': LINKEDIN_CLIENT_ID,
            'redirect_uri': LINKEDIN_REDIRECT_URI,
            'scope': LINKEDIN_SCOPE
        })
    )
    # print(f"LinkedIn Authorization URL: {auth_url}".format())
    return JsonResponse({"authorization_url": auth_url})


def linkedin_callback_oauth(request, organization):
    """
    Handles the callback and exchanges the authorization code for access tokens.
    """
    authorization_code = request.GET.get("code")  # From frontend input
    if not authorization_code:
        return JsonResponse({"error": "Missing authorization code."}, status=400)

    token_url = "https://www.linkedin.com/oauth/v2/accessToken"
    payload = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': LINKEDIN_REDIRECT_URI,
        'client_id': LINKEDIN_CLIENT_ID,
        'client_secret': LINKEDIN_CLIENT_SECRET,
    }

    try:
        # Step 1: Exchange authorization code for access token
        response = requests.post(token_url, data=payload)
        if response.status_code == 200:
            tokens = response.json()
            access_token = tokens.get('access_token')

            # Step 2: Fetch LinkedIn member ID (sub) using the access token
            member_id_url = "https://api.linkedin.com/v2/userinfo"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "X-Restli-Protocol-Version": "2.0.0"
            }

            member_response = requests.get(member_id_url, headers=headers)
            if member_response.status_code == 200:
                member_id = member_response.json().get("sub")
                print(f"LinkedIn member ID retrieved: {member_id}")

                # Step 3: Save tokens and member ID in the database
                SocialMediaAccount.objects.update_or_create(
                    organization=organization,
                    platform=SocialMediaAccount.LINKEDIN,
                    defaults={
                        'user': request.user,
                        'access_token': access_token,
                        'access_id_secret': member_id,  # Store member ID as 'access_id_secret' or another field
                    }
                )
                organization.has_linkedin = True
                organization.save()
                print(f"LinkedIn access token and member ID saved for organization: {organization}")
                return JsonResponse({"message": "LinkedIn account connected successfully!"})
            else:
                print(f"Error fetching LinkedIn member ID: {member_response.text}")
                return JsonResponse({"error": "Unable to fetch LinkedIn member ID."}, status=500)
        else:
            print(f"Error fetching LinkedIn access token: {response.text}")
            return JsonResponse({"error": response.json()}, status=response.status_code)
    except Exception as e:
        return JsonResponse({"error": "Error fetching access token or member ID", "details": str(e)}, status=500)

def post_linkedin_update(post_content, organization):
    """
    Posts an update on LinkedIn using the stored access tokens.
    """
    print(f"Attempting to post on LinkedIn for organization: {organization}")

    # Retrieve the associated LinkedIn account for the organization
    linkedin_oauth = SocialMediaAccount.objects.filter(organization=organization).first()

    if not linkedin_oauth:
        print(f"No LinkedIn account connected for organization: {organization}")
        return JsonResponse({"error": "LinkedIn account not connected."}, status=400)

    print(f"Found LinkedIn account for organization: {organization}")
    print(f"Access token: {linkedin_oauth.access_token}")

    # Use stored member ID or fetch it again if missing
    member_id = linkedin_oauth.access_id_secret

    # Create the post data
    post_data = {
        "author": f"urn:li:person:{member_id}",
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary": {"text": post_content},
                "shareMediaCategory": "NONE"
            }
        },
        "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"}
    }

    # Post the content to LinkedIn
    post_url = "https://api.linkedin.com/v2/ugcPosts"
    headers = {
        "Authorization": f"Bearer {linkedin_oauth.access_token}",
        "X-Restli-Protocol-Version": "2.0.0"
    }
    print(f"Posting content to LinkedIn: {post_content}")

    try:
        response = requests.post(post_url, json=post_data, headers=headers)
        if response.status_code == 201:
            print(f"LinkedIn post created successfully: {response.json()}")
            return JsonResponse({"message": "Post created successfully on LinkedIn!"})
        else:
            print(f"Error posting on LinkedIn. Status code: {response.status_code}, Response: {response.text}")
            return JsonResponse(
                {"error": response.json(), "status_code": response.status_code}, status=response.status_code
            )
    except Exception as e:
        return JsonResponse({"error": "Error posting on LinkedIn", "details": str(e)}, status=500)























