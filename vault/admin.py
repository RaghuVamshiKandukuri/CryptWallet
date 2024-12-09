from django.contrib import admin
from .models import AuditLog, UploadedFile, UserProfile

admin.site.register(AuditLog)
admin.site.register(UploadedFile)
admin.site.register(UserProfile)