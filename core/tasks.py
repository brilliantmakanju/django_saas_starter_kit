from django_tenants.utils import tenant_context
from django.utils import timezone

from accounts.models import UserAccount
from core.models import Post
from accounts.social_service import post_tweet, post_linkedin_update
from notifications.utlis import create_and_notify
from organizations.models import Organization, UserOrganizationRole
from datetime import timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from django.utils.timezone import now
from core.utlis import select_post_to_publish, delete_other_posts, select_linkedin_post_to_publish

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

                    # Get organization owner
                    owner_role = UserOrganizationRole.objects.filter(
                        organization=tenant, role="owner"
                    ).select_related("user").first()

                    if not owner_role or not owner_role.user:
                        print(f"No valid owner found for {tenant.schema_name}, skipping...")
                        continue

                    owner = owner_role.user

                    # Check if the owner is on the basic plan
                    if owner.plan == UserAccount.BASIC:
                        # Count posts published by the owner in the current month
                        start_of_month = now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                        monthly_post_count = Post.objects.filter(
                            created_by=owner,
                            created_at__gte=start_of_month
                        ).count()

                        if monthly_post_count >= 5:
                            print(
                                f"Owner {owner.email} has reached the 5-post limit for this month. Skipping publishing.")
                            continue

                    max_delay = timedelta(minutes=15)
                    current_time = timezone.now()

                    all_posts = Post.objects.filter(
                        platform="linkedin",
                        status__in=["drafted", "scheduled"],
                        is_deleted=False,
                        is_inactive=False,
                        scheduled_publish_time__isnull=False
                    )

                    posts_to_publish = []

                    # Iterate through filtered posts
                    for post in all_posts:
                        print(f"Checking post {post.id}:")
                        print(f"Scheduled Publish Time: {post.scheduled_publish_time}")
                        print(f"Current Time: {current_time}")

                        time_difference = current_time - post.scheduled_publish_time

                        # Publish if within the 5-minute window or exactly on time
                        if timedelta(0) <= time_difference <= max_delay:
                            print(f"Post is within the allowed delay window. Publishing now.")
                            posts_to_publish.append(post)

                        elif post.scheduled_publish_time > current_time:
                            print(f"Post's scheduled publish time is in the future. Not publishing yet.")

                        else:
                            print(f"Post's scheduled publish time exceeded the maximum delay. Skipping.")

                    print(f"Found {len(posts_to_publish)} posts to check for publishing on LinkedIn.")

                    # Process each post and check if it is ready to be published
                    for post in posts_to_publish:
                        print(f"Checking if post {post.id} is ready to be published...")
                        if post.is_ready_to_publish():
                            print(f"Post {post.id} is ready to be published.")

                            # Select the post for Twitter using the defined function
                            # selected_post = select_post_to_publish(posts_to_publish)
                            selected_linkedin_post = select_linkedin_post_to_publish(posts_to_publish)

                            if selected_linkedin_post:
                                # Mark the selected post as published
                                post_linkedin_update(selected_linkedin_post.content, organization=tenant)
                                selected_linkedin_post.publish()

                                # Post the tweet
                                print(f"Post {selected_linkedin_post.id} has been published.")

                                # Step 4: Delete all other posts that are not the selected one
                                delete_other_posts(selected_linkedin_post, platform="linkedin")

                                # Send the notification email **after successful publishing**
                                title = "Your Post Has Been Published on Social Media"
                                message = f"Your post with ID {selected_linkedin_post.id} has been successfully published."

                                create_and_notify(
                                    organization=tenant,
                                    title=title,
                                    message=message,
                                    triggered_by=None,
                                    template_path='emails/notification_email_published.html'
                                )

                                # Exit the loop after publishing the selected post (no need to continue processing)
                                break
                        else:
                            print(f"Post {post.id} is not ready for publishing.")



            except Exception as e:
                print(f"Error while processing tenant {tenant.schema_name}: {e}")
        print("Finished checking for posts to publish.")
    except Exception as e:
        print(f"Error while accessing tenants or posts: {e}")



def start_scheduler():
    from django.core.management import call_command  # Import here to prevent premature Django access

    scheduler = BackgroundScheduler()
    scheduler.add_job(publish_pending_post, 'interval', minutes=4)
    scheduler.start()