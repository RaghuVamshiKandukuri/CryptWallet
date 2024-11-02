from django.db import models
from django.contrib.auth.models import User

class FileMetadata(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file_name = models.CharField(max_length=255)
    encrypted_file = models.FileField(upload_to='encrypted_files/')
    shared_with = models.ManyToManyField(User, related_name='shared_files', blank=True)

    def __str__(self):
        return self.file_name

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(blank=True, null=True)
    profile_image = models.ImageField(upload_to='profile_images/', blank=True, null=True)
    location = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"{self.user.username}'s Profile"
    

