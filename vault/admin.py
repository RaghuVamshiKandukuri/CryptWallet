from django.contrib import admin

# Register your models here.
from .models import FileMetadata

admin.site.register(FileMetadata)