from organizations.models import UserOrganizationRole
from django.core.exceptions import PermissionDenied
import os, json
from django.conf import settings
from openai import OpenAI
from django.shortcuts import get_object_or_404
from .models import Post, Webhook, PostGroup
import re, random
from notifications.utlis import create_and_notify
from django.utils import timezone
from datetime import timedelta



client = OpenAI(
  base_url = settings.AI_BASE_URL,
  api_key = settings.AI_API_KEY
)

def create_posts_from_formatted_data(secret_key, formatted_posts):
    """
    Create Post objects from the formatted posts data, associating them with the correct organization.
    Args:
        secret_key (str): The secret key to identify the organization via the Webhook model.
        formatted_posts (dict): The formatted posts data containing Twitter and LinkedIn posts.
    """
    print(f"🔑 Secret Key Received: {secret_key}")
    print(f"📩 Formatted Posts Data: {json.dumps(formatted_posts, indent=2)}")  # Pretty-print the JSON data

    # Get the Webhook and associated organization using the secret key
    webhook = get_object_or_404(Webhook, private_secret=secret_key)
    organization = webhook.organization
    print(f"🏢 Organization Retrieved: {organization.name} (ID: {organization.id})")

    # Extract Twitter and LinkedIn posts
    twitter_posts = formatted_posts.get('twitter_posts', [])
    linkedin_posts = formatted_posts.get('linkedin_posts', [])
    print(f"🐦 Twitter Posts Extracted: {twitter_posts}")
    print(f"🔗 LinkedIn Posts Extracted: {linkedin_posts}")

    # Helper function to extract individual posts from the grouped list
    def extract_posts(posts):
        extracted = []
        current_post = None

        for line in posts:
            # Detecting new post headers
            if "Twitter Post" in line or "LinkedIn Post" in line:
                if current_post:
                    extracted.append(current_post.strip())
                current_post = ""
            else:
                current_post = f"{current_post} {line}".strip() if current_post else line.strip()

        if current_post:
            extracted.append(current_post.strip())

        return extracted

    # Extract individual Twitter and LinkedIn posts
    twitter_posts_cleaned = extract_posts(twitter_posts)
    linkedin_posts_cleaned = extract_posts(linkedin_posts)
    print(f"✅ Cleaned Twitter Posts: {twitter_posts_cleaned}")
    print(f"✅ Cleaned LinkedIn Posts: {linkedin_posts_cleaned}")

    # Combine all posts with platform information
    all_posts = [
                    {"content": post, "platform": "twitter"} for post in twitter_posts_cleaned
                ] + [
                    {"content": post, "platform": "linkedin"} for post in linkedin_posts_cleaned
                ]

    print(f"📜 All Posts to Create: {json.dumps(all_posts, indent=2)}")

    # Create a PostGroup to group all the posts
    post_group = PostGroup.objects.create(
        organization=organization,
        name=f"Generated Posts Group for {organization.name}",  # Explicit name tied to the organization
        description="Group for AI-generated posts."
    )
    print(f"📌 Created PostGroup: {post_group.name} (ID: {post_group.id})")

    # Set default scheduling delay (e.g., 15 minutes) for all posts
    # scheduled_publish_time = timezone.now() + timedelta(minutes=15)
    # print(f"🕒 Scheduled Publish Time: {scheduled_publish_time}")
    scheduled_publish_time = timezone.now()
    print(f"🕒 Scheduled Publish Time (Test Default): {scheduled_publish_time}")

    # Create Post objects for each post and associate them with the PostGroup
    created_posts = []
    for post_data in all_posts:
        post = Post.objects.create(
            organization=organization,
            content=post_data["content"],
            platform=post_data["platform"],
            # post_group=post_group , # Associate the post with the group
            scheduled_publish_time=scheduled_publish_time,  # Set the scheduled time for publishing
            actual_publish_time=None,  # Set actual publish time to None initially
        )
        created_posts.append(post)
        print(f"📝 Created Post: {post.content[:50]}... (ID: {post.id}, Platform: {post.platform})")

    print(f"🎯 Total Posts Created: {len(created_posts)}")

    # Send notification with the relevant email template
    notification_result = create_and_notify(
        organization,
        title="New Post Created",
        message="A new post draft has been created and is ready for review.",
        triggered_by=None,
        template_path='emails/notification_email_draft.html'  # Or change to published template
    )

    print(f"📢 Notification Sent: {notification_result}")

    # # Get the Webhook and associated organization using the secret key
    # webhook = get_object_or_404(Webhook, private_secret=secret_key)
    # organization = webhook.organization
    #
    # # Extract Twitter and LinkedIn posts
    # twitter_posts = formatted_posts.get('twitter_posts', [])
    # linkedin_posts = formatted_posts.get('linkedin_posts', [])
    #
    # # Helper function to extract individual posts from the grouped list
    # def extract_posts(posts):
    #     extracted = []
    #     current_post = None
    #
    #     for line in posts:
    #         # Detecting new post headers
    #         if "Twitter Post" in line or "LinkedIn Post" in line:
    #             if current_post:
    #                 extracted.append(current_post.strip())
    #             current_post = ""
    #         else:
    #             current_post = f"{current_post} {line}".strip() if current_post else line.strip()
    #
    #     if current_post:
    #         extracted.append(current_post.strip())
    #
    #     return extracted
    #
    # # Extract individual Twitter and LinkedIn posts
    # twitter_posts_cleaned = extract_posts(twitter_posts)
    # linkedin_posts_cleaned = extract_posts(linkedin_posts)
    #
    # # Combine all posts with platform information
    # all_posts = [
    #     {"content": post, "platform": "twitter"} for post in twitter_posts_cleaned
    # ] + [
    #     {"content": post, "platform": "linkedin"} for post in linkedin_posts_cleaned
    # ]
    #
    # # Create a PostGroup to group all the posts
    # post_group = PostGroup.objects.create(
    #     organization=organization,
    #     name=f"Generated Posts Group for {organization.name}",  # Explicit name tied to the organization
    #     description="Group for AI-generated posts."
    # )
    #
    # # Set default scheduling delay (e.g., 15 minutes) for all posts
    # scheduled_publish_time = timezone.now() + timedelta(minutes=15)
    #
    # # Create Post objects for each post and associate them with the PostGroup
    # created_posts = []
    # for post_data in all_posts:
    #     post = Post.objects.create(
    #         organization=organization,
    #         content=post_data["content"],
    #         platform=post_data["platform"],
    #         post_group=post_group , # Associate the post with the group
    #         scheduled_publish_time=scheduled_publish_time,  # Set the scheduled time for publishing
    #         actual_publish_time=None,  # Set actual publish time to None initially
    #     )
    #     created_posts.append(post)
    #     print(f"Created Post: {post} with ID {post.id}")
    #
    # print(f"Total posts created: {len(created_posts)}")
    #
    # # Send notification with the relevant email template
    # create_and_notify(
    #     organization,
    #     title="New Post Created",
    #     message="A new post draft has been created and is ready for review.",
    #     triggered_by=None,
    #     template_path='emails/notification_email_draft.html'  # Or change to published template
    # )

    return created_posts, post_group

def is_organization_owner_or_admin(user, organization):
    """
    Helper function to check if the user is the owner or an admin of the organization.
    This function uses the UserOrganizationRole model to check the user's role in the organization.
    Raises PermissionDenied if the user is a member.
    """
    try:
        # Fetch the user's role for the given organization
        user_role = UserOrganizationRole.objects.get(user=user, organization=organization)

        # Check if the user is the owner or admin
        if user_role.role in ['owner', 'admin']:
            return True  # User is an owner or admin

    except UserOrganizationRole.DoesNotExist:
        pass

    # If the user is not the owner/admin, raise a PermissionDenied exception
    raise PermissionDenied("You are not authorized to perform this action.")

def load_base_prompt():
    """
    Load the base prompt from the external file.
    """
    prompt_file_path = os.path.join(os.path.dirname(__file__), 'ai_prompts', 'base_prompt.txt')
    with open(prompt_file_path, 'r') as file:
        return file.read()

def format_prompt(commits, tone):
    """
    Format the base prompt with the user commits and tone.
    """
    # Load the base prompt
    base_prompt = load_base_prompt()

    # Insert the commits and tone into the prompt
    formatted_prompt = base_prompt.format(commits=commits, tone=tone)

    return formatted_prompt

def generate_post_with_ai(commits, tone, secret_key):
    """
    Generate a post using AI based on commits and tone.
    """
    # Format the prompt before passing it to the AI
    prompt = format_prompt(commits, tone)

    try:
        # Call the AI function to generate the post with streaming enabled
        print("Sending request to the AI...")
        completion = client.chat.completions.create(
            model="meta/llama-3.3-70b-instruct",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            top_p=0.7,
            max_tokens=1024,
            stream=True
        )

        # Print the entire response object to check its structure
        # print("AI response object:", completion)

        # Iterate through each chunk in the stream response
        generated_content = ""
        for chunk in completion:
            if chunk.choices[0].delta.content is not None:
                content = chunk.choices[0].delta.content
                # print(f"Chunk content: {content}")  # Print the content of the chunk
                generated_content += content  # Append content to the final result

        # print("Final generated content:", generated_content)

        # Format the posts
        formatted_posts = format_ai_posts(generated_content)
        print(formatted_posts)

        # Create posts
        created_posts = create_posts_from_formatted_data(secret_key, formatted_posts)
        print(created_posts, "Created Posts")

        # Output the created posts for verification
        for post in created_posts:
            print(f"Post ID: {post.id}, Platform: {post.platform}, Content: {post.content}")

        # Return the final generated content
        return created_posts

    except Exception as e:
        # Print any errors that occur during the AI request
        print(f"Error generating post: {e}")
        return None

def format_ai_posts(ai_response):
    """
    Process and format the AI-generated posts into structured format for Twitter and LinkedIn.
    Removes unnecessary characters, and groups posts by platform (Twitter / LinkedIn).
    """
    # Remove unnecessary ** (bold) formatting, or any unwanted characters like extra quotes
    ai_response_cleaned = re.sub(r"\*\*(.*?)\*\*", r"\1", ai_response)  # Removing bold markers (**)
    ai_response_cleaned = ai_response_cleaned.replace('"', '')  # Removing quotes

    # Now, group the posts by platform (Twitter and LinkedIn)
    # Split the response by platform headers (assumes "Twitter" and "LinkedIn" headers are there)
    twitter_posts = []
    linkedin_posts = []

    # Split by `---` to separate Twitter from LinkedIn content
    groups = ai_response_cleaned.split('---')

    # Check if Twitter or LinkedIn posts are present and collect them
    for group in groups:
        if "Twitter" in group:
            # Split into separate posts and remove extra spaces
            twitter_posts = [post.strip() for post in group.split("\n") if post.strip()]
        elif "LinkedIn" in group:
            linkedin_posts = [post.strip() for post in group.split("\n") if post.strip()]

    # Prepare the final structured output
    result = {
        'twitter_posts': twitter_posts,
        'linkedin_posts': linkedin_posts
    }

    return result

def generate_webhook_details(organization):
    if not organization.can_generate_webhook():
        raise ValueError("Webhook details cannot be generated unless at least one platform is enabled.")

    # Continue with webhook generation
    return True
#
#
# def generate_code_verifier_and_challenge():
#     """
#     Generate code_verifier and code_challenge for OAuth2.
#     """
#     # Generate a random code_verifier
#     code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8").rstrip("=")
#     # Generate a SHA256 code_challenge
#     code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
#     code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8").rstrip("=")
#     return code_verifier, code_challenge
#
#
# def post_on_twitter_initiate(request):
#     """
#     Initiates the Twitter OAuth2 flow by generating an authorization URL.
#     """
#     # Generate code_verifier and code_challenge
#     code_verifier, code_challenge = generate_code_verifier_and_challenge()
#
#     # Save the code_verifier in the session for later use
#     request.session["twitter_code_verifier"] = code_verifier
#
#     # Create an OAuth2 session
#     twitter = OAuth2Session(
#         settings.TWITTER_CLIENT_ID,
#         redirect_uri=settings.TWITTER_REDIRECT_URI,
#         scope=settings.TWITTER_SCOPES,
#     )
#
#     # Generate the authorization URL
#     authorization_url, state = twitter.authorization_url(
#         settings.TWITTER_AUTH_URL,
#         code_challenge=code_challenge,
#         code_challenge_method="S256",
#     )
#
#     # Save the state in the session
#     request.session["oauth_state"] = state
#     print(state)
#
#     # Redirect the user to Twitter's authorization page
#     return HttpResponseRedirect(authorization_url)
#
#
# def post_on_twitter_callback(request):
#     """
#     Handles the callback from Twitter OAuth2 and retrieves the access token.
#     """
#     # Retrieve the state and code_verifier from the session
#     state = request.session.get("oauth_state")
#     code_verifier = request.session.get("twitter_code_verifier")
#
#     if not state or not code_verifier:
#         return JsonResponse({"error": "Invalid session state or code_verifier missing."}, status=400)
#
#     # Get the authorization code from the callback URL
#     authorization_code = request.GET.get("code")
#
#     if not authorization_code:
#         return JsonResponse({"error": "Authorization code is missing."}, status=400)
#
#     # Create an OAuth2 session
#     twitter = OAuth2Session(
#         settings.TWITTER_CLIENT_ID,
#         redirect_uri=settings.TWITTER_REDIRECT_URI,
#         state=state,
#     )
#
#     try:
#         # Exchange the authorization code for an access token
#         token = twitter.fetch_token(
#             settings.TWITTER_TOKEN_URL,
#             client_secret=settings.TWITTER_CLIENT_SECRET,
#             code=authorization_code,
#             code_verifier=code_verifier,
#         )
#         # Save the token for the user (e.g., in the database or session)
#         request.session["twitter_token"] = token
#
#         # Optionally, create a tweet
#         response = create_tweet(token)
#         return JsonResponse({"status": "success", "response": response}, status=200)
#     except Exception as e:
#         return JsonResponse({"error": str(e)}, status=500)
#
#
# def create_tweet(token):
#     """
#     Creates a tweet using the Twitter API.
#     """
#     headers = {
#         "Authorization": f"Bearer {token['access_token']}",
#         "Content-Type": "application/json",
#     }
#     payload = {"text": "Testing Twitter Post from Django!"}
#
#     response = requests.post("https://api.twitter.com/2/tweets", json=payload, headers=headers)
#
#     if response.status_code == 201:
#         return response.json()
#     else:
#         return {"error": response.json(), "status_code": response.status_code}
#
#
#
#

# Function to filter posts by platform and select based on priority
def select_post_to_publish(posts_to_publish):
    # Step 1: Filter the posts by platform (e.g., 'twitter')
    twitter_posts = [post for post in posts_to_publish if post.platform == 'twitter']

    if not twitter_posts:
        print("No posts available for Twitter.")
        return None

    # Step 2: Separate posts into priority and non-priority
    priority_posts = [post for post in twitter_posts if post.priority]
    non_priority_posts = [post for post in twitter_posts if not post.priority]

    # Step 3: Select the post based on priority
    if priority_posts:
        # If there are priority posts, select the first one (you can also choose random here if needed)
        selected_post = priority_posts[0]
        print(f"Priority post selected: {selected_post.id}")
    else:
        # If no priority posts, select one randomly from non-priority posts
        selected_post = random.choice(non_priority_posts)
        print(f"Random post selected: {selected_post.id}")

    return selected_post

# Function to filter posts by platform and select based on priority
def select_linkedin_post_to_publish(posts_to_publish):
    # Step 1: Filter the posts by platform (e.g., 'LinkedIn')
    linkedIn_posts = [post for post in posts_to_publish if post.platform == 'linkedin']

    if not linkedIn_posts:
        print("No posts available for LinkedIn.")
        return None

    # Step 2: Separate posts into priority and non-priority
    priority_posts = [post for post in linkedIn_posts if post.priority]
    non_priority_posts = [post for post in linkedIn_posts if not post.priority]

    # Step 3: Select the post based on priority
    if priority_posts:
        # If there are priority posts, select the first one (you can also choose random here if needed)
        selected_post = priority_posts[0]
        print(f"Priority post selected: {selected_post.id}")
    else:
        # If no priority posts, select one randomly from non-priority posts
        selected_post = random.choice(non_priority_posts)
        print(f"Random post selected: {selected_post.id}")

    return selected_post


# Function to delete the posts that were not selected for publishing
def delete_other_posts(selected_post, platform):
    # Filter out posts that are drafted or scheduled and not selected
    other_posts = Post.objects.filter(
        platform=platform,
        status__in=['drafted']
    ).exclude(id=selected_post.id)

    # Delete the posts that are not selected for publishing
    deleted_count, _ = other_posts.delete()
    print(f"{deleted_count} posts were deleted from the database.")
























