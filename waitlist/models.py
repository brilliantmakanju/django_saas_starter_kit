from django.db import models

class NewsletterPlatform(models.Model):
    name = models.CharField(max_length=100, unique=True)  # e.g. "Pet Progress", "Twitter Tracker"

    def __str__(self):
        return self.name


class NewsletterSubscriber(models.Model):
    email = models.EmailField()
    platform = models.ForeignKey(NewsletterPlatform, on_delete=models.CASCADE, related_name='subscribers')
    subscribed_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ('email', 'platform')  # avoid duplicates

    def __str__(self):
        return f"{self.email} ({self.platform.name})"










class ContactMessage(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    responded = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.name} - {self.email}"
