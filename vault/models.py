from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now


class UploadedFile(models.Model):
    VISIBILITY_CHOICES = [
        ('PUBLIC', 'Public'),
        ('PRIVATE', 'Private'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="uploaded_files")  # Associate file with user
    file = models.FileField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    visibility = models.CharField(max_length=10, choices=VISIBILITY_CHOICES, default='PRIVATE')
    shared_with = models.ManyToManyField(User, related_name="shared_files", blank=True)  # Users the file is shared with

    def __str__(self):
        return f"{self.file.name} (Uploaded by {self.user.username})"

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    bio = models.TextField(blank=True, null=True)
    profile_image = models.ImageField(upload_to='profile_images/', blank=True, null=True)
    location = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"{self.user.username}'s Profile"
    

class AuditLog(models.Model):
    ACTIONS = [
        ('UPLOAD', 'Upload'),
        ('DOWNLOAD', 'Download'),
        ('DELETE', 'Delete'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="audit_logs")
    action = models.CharField(max_length=10, choices=ACTIONS)
    file_name = models.CharField(max_length=255)
    timestamp = models.DateTimeField(default=now)
    details = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.file_name} - {self.timestamp}"
    


class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Message from {self.sender} to {self.receiver} at {self.timestamp}"






class SharedFile(models.Model):
    shared_by = models.ForeignKey(User, related_name='files_shared_by', on_delete=models.CASCADE)
    shared_with = models.ForeignKey(User, related_name='files_shared_with', on_delete=models.CASCADE)
    file = models.ForeignKey(UploadedFile, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        # Truncate file name for better readability in the admin interface
        return f"{self.file.file.name[:20]} shared by {self.shared_by.username} with {self.shared_with.username}"

    class Meta:
        verbose_name = "Shared File"
        verbose_name_plural = "Shared Files"
        # Prevent duplicate sharing of the same file with the same user
        constraints = [
            models.UniqueConstraint(fields=['shared_with', 'file'], name='unique_file_share')
        ]