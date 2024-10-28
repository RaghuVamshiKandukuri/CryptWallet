from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as django_login
from django.urls import reverse
from django.conf import settings
from django.contrib.auth.models import User
from django import forms

from .models import FileMetadata
from .forms import FileUploadForm

# Cryptography imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

import os

# Create your views here.
def main(request):
    return render(request, 'vault/auth/main.html')

def index(request):
    if not request.user.is_authenticated:
        return login(request)
    return render(request, 'vault/index.html')


def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            django_login(request, user)
            return HttpResponseRedirect(reverse('index'))
        else:
            error_message = "Invalid credentials. Please try again."
            return render(request, 'vault/auth/login.html', {'error_message': error_message})
        

    if request.user.is_authenticated:
        return index(request)
    return render(request, 'vault/auth/login.html')


def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        
        if password == confirm_password:
            if User.objects.filter(username=username).exists():
                error_message = "Username already taken. Please choose another."
            elif User.objects.filter(email=email).exists():
                error_message = "Email is already in use. Please use a different email."
            else:
                user = User.objects.create_user(username=username, email=email, password=password)
                django_login(request, user)
                return redirect('index')
        else:
            error_message = "Passwords do not match."
        return render(request, 'vault/auth/register.html', {'error_message': error_message})
    
    return render(request, 'vault/auth/register.html')








from django.contrib.auth import logout
from django.shortcuts import redirect

def logout_view(request):
    logout(request)
    return redirect('login')  # Redirect to login page after logging out






def encrypt_file(file_data, password):
    salt = os.urandom(16)  # Unique salt for this file
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()
    return salt + iv + encrypted_data  # Include salt and iv in the stored file

# Usage:
# encrypted_content = encrypt_file(uploaded_file.read(), 'encryption_password')








def upload_file(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            file_data = request.FILES['file_data']
            privacy_setting = form.cleaned_data['privacy_setting']
            owner = request.user
            
            # Encrypt the file
            encrypted_data = encrypt_file(file_data.read(), 'secure_password')
            file_name = file_data.name
            file_path = f"{settings.MEDIA_ROOT}/{file_name}.enc"
            
            # Save the encrypted file to media folder
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Save file metadata
            FileMetadata.objects.create(
                file_name=file_name,
                file_path=file_path,
                owner=owner,
                privacy_setting=privacy_setting
            )
            return redirect('file_list')  # Or wherever you want to go post-upload
    else:
        form = FileUploadForm()
    return render(request, 'upload.html', {'form': form})




#new after 
@login_required
def file_upload_view(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            file_metadata = form.save(commit=False)
            file_metadata.user = request.user
            file_metadata.save()
            return redirect('file_list')
    else:
        form = FileUploadForm()
    return render(request, 'vault/file_upload.html', {'form': form})

@login_required
def file_list_view(request):
    files = FileMetadata.objects.filter(user=request.user)
    return render(request, 'vault/file_list.html', {'files': files})

@login_required
def file_detail_view(request, file_id):
    file = get_object_or_404(FileMetadata, id=file_id)
    if file.is_public or request.user == file.user or request.user in file.shared_with.all():
        return render(request, 'vault/file_detail.html', {'file': file})
    else:
        return HttpResponse("You do not have permission to view this file.", status=403)

@login_required
def request_file_access(request, file_id):
    file = get_object_or_404(FileMetadata, id=file_id)
    if request.user != file.user:
        # Here, send a notification or email to the owner requesting permission
        return HttpResponse("Access request sent to file owner.")
    return HttpResponse("You already have access.")


@login_required
def profile(request):
    return render(request, 'vault/profile.html', {})





def messages(request):
    # Sample context data for messages
    context = {
        'messages': [
            {'sender': 'Alice', 'content': 'Hey, how are you?', 'time': '2:00 PM'},
            {'sender': 'Bob', 'content': 'Don\'t forget our meeting!', 'time': '3:15 PM'},
        ]
    }
    return render(request, 'vault/messages.html', context)

def settings(request):
    # Sample context data for settings
    context = {
        'settings': {
            'email_notifications': True,
            'sms_alerts': False,
            'dark_mode': True,
        }
    }
    return render(request, 'vault/settings.html', context)