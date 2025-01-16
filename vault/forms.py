from django import forms
from django.contrib.auth.models import User
from .models import UploadedFile

class FileUploadForm(forms.ModelForm):
    class Meta:
        model = UploadedFile
        fields = ['file','visibility']

class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username','first_name', 'last_name', 'email']

class FileShareForm(forms.Form):
    username = forms.CharField(max_length=150, help_text="Enter the username of the recipient.")