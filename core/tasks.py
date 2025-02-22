from django_tenants.utils import tenant_context
from django.utils import timezone
from core.models import Post
from accounts.social_service import post_tweet, post_linkedin_update
from notifications.utlis import create_and_notify
from organizations.models import Organization
from celery import shared_task
from background_task import background
from core.utlis import select_post_to_publish, delete_other_posts, select_linkedin_post_to_publish

# @shared_task
@background(schedule=60)  # Runs every 1 minute
def publish_pending_post():
    """
    This task checks for all posts that are in the 'draft' or 'scheduled' state,
    are not deleted or inactive, and are scheduled for publishing.
    It will publish the post if the scheduled time has passed.
    This will run for all tenants without passing a tenant_id explicitly.
    """
    print("Started checking for posts to publish...")

    try:
        # Get all tenants (replace 'Organization' with your actual tenant model)
        tenants = Organization.objects.all()

        # Loop through each tenant and switch to their schema using tenant_context
        for tenant in tenants:
            print(f"Switching to tenant: {tenant.schema_name}")
            try:
                # Switch to the current tenant's schema
                with tenant_context(tenant):
                    print(f"Switched to tenant schema: {tenant.schema_name}")

                    # Fetch all posts for this tenant
                    all_posts = Post.objects.all()

                    # Initialize a list to hold the posts that are ready to be published
                    posts_to_publish = []

                    # Iterate through all the posts and print relevant details
                    for post in all_posts:
                        print(f"Checking post {post.id}:")
                        print(f"  Status: {post.status}")
                        print(f"  Is Deleted: {post.is_deleted}")
                        print(f"  Is Inactive: {post.is_inactive}")
                        print(f"  Scheduled Publish Time: {post.scheduled_publish_time}")
                        print(f"  Current Time: {timezone.now()}")

                        # Apply the filtering conditions
                        if post.status in ["drafted", "scheduled"]:
                            print(f"  Status is either DRAFTED or SCHEDULED.")
                            if not post.is_deleted:
                                print(f"  Post is not deleted.")
                                if not post.is_inactive:
                                    print(f"  Post is not inactive.")
                                    # Check if scheduled_publish_time is not None before comparing
                                    if post.scheduled_publish_time and post.scheduled_publish_time <= timezone.now():
                                        print(f"  Post is scheduled to be published on time.")
                                        posts_to_publish.append(post)
                                    else:
                                        print(f"  Post's scheduled publish time is in the future or not set.")
                                else:
                                    print(f"  Post is inactive, skipping.")
                            else:
                                print(f"  Post is deleted, skipping.")
                        else:
                            print(f"  Status is neither DRAFTED nor SCHEDULED, skipping.")

                    # Print the number of posts found to be published
                    print(
                        f"Found {len(posts_to_publish)} posts to check for publishing in tenant {tenant.schema_name}.")

                    # Send the notification email if posts have been found to publish
                    if posts_to_publish:
                        # Prepare the email data
                        title = "Your Post Has Been Published on Social Media"
                        message = f"A total of {len(posts_to_publish)} posts have been successfully published."

                        # Send notification with the relevant email template
                        create_and_notify(
                            organization=tenant,
                            title=title,
                            message=message,
                            triggered_by=None,
                            template_path='emails/notification_email_published.html'
                            # You can change to a published template
                        )

                    # Process each post and check if it is ready to be published
                    for post in posts_to_publish:
                        print(f"Checking if post {post.id} is ready to be published...")
                        if post.is_ready_to_publish():
                            print(f"Post {post.id} is ready to be published.")

                            # Select the post for Twitter using the defined function
                            selected_post = select_post_to_publish(posts_to_publish)
                            selected_linkedin_post = select_linkedin_post_to_publish(posts_to_publish)

                            if selected_linkedin_post:
                                # Mark the selected post as published
                                post_linkedin_update(selected_linkedin_post.content, organization=tenant)
                                selected_linkedin_post.publish()

                                # Post the tweet
                                print(f"Post {selected_linkedin_post.id} has been published.")

                                # Step 4: Delete all other posts that are not the selected one
                                delete_other_posts(selected_linkedin_post, platform="linkedin")

                                # Exit the loop after publishing the selected post (no need to continue processing)
                                break


                            if selected_post:
                                # Mark the selected post as published
                                post_tweet(selected_post.content[:280], organization=tenant)
                                selected_post.publish()

                                # Post the tweet
                                print(f"Post {selected_post.id} has been published.")

                                # Step 4: Delete all other posts that are not the selected one
                                delete_other_posts(selected_post, platform="twitter")

                                # Exit the loop after publishing the selected post (no need to continue processing)
                                break
                        else:
                            print(f"Post {post.id} is not ready for publishing.")



            except Exception as e:
                print(f"Error while processing tenant {tenant.schema_name}: {e}")
        print("Finished checking for posts to publish.")
    except Exception as e:
        print(f"Error while accessing tenants or posts: {e}")
