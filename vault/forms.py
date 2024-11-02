from django import forms
from .models import FileMetadata

class FileUploadForm(forms.ModelForm):
    class Meta:
        model = FileMetadata
        fields = ['file_name']
        widgets = {
            'file_name': forms.FileInput(attrs={'accept': '*/*'}),
        }
