from requests_oauthlib import OAuth1Session
from django.http import JsonResponse
from core.models import SocialMediaAccount
from django.conf import settings
import time

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

    if response.status_code == 429:
        retry_after = 15 * 60  # Wait for 15 minutes (default)
        print("Rate limit exceeded. Retrying after 15 minutes...")
        time.sleep(retry_after)

    else:
        print(f"Error posting tweet. Status code: {response.status_code}, Response: {response.json()}")
        return JsonResponse(
            {"error": response.json(), "status_code": response.status_code}, status=500
        )








