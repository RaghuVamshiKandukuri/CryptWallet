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

from django.contrib import messages
import os
from django.contrib.auth import logout

from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from .utils import decrypt_file




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







def logout_view(request):
    logout(request)
    return redirect('login')  # Redirect to login page after logging out






def encrypt_file(file_data, password):
    # Encrypt the file using AES encryption
    salt = os.urandom(16)
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
    return salt + iv + encrypted_data


def decrypt_file(encrypted_data, password):
    salt, iv, encrypted_data = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()











@login_required
def upload_file(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            file_data = uploaded_file.read()
            key = b'Sixteen byte key'  # Ensure this key matches AES-128 length

            encrypted_data = encrypt_file(file_data, key)

            file_metadata = FileMetadata.objects.create(
                user=request.user,
                file_name=uploaded_file.name,
                encrypted_file=encrypted_data
            )
            return redirect('success_page')
    else:
        form = FileUploadForm()
    
    return render(request, 'upload.html', {'form': form})


def download_file(request, file_id):
    file = get_object_or_404(FileMetadata, id=file_id, user=request.user)
    encrypted_data = file.encrypted_file

    # Decrypt the data
    password = "secure_password"  # Replace with correct key
    decrypted_data = decrypt_file(encrypted_data, password)

    response = HttpResponse(decrypted_data, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{file.file_name}"'
    return response



#new after 

@login_required
def file_upload_view(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file_name']  # File field in FileUploadForm
            file_data = uploaded_file.read()
            
            # Encrypt file data before storing it
            password = "secure_password"  # Replace with user-specific or generated key
            encrypted_data = encrypt_file(file_data, password)
            
            # Save encrypted file metadata to the database
            file_metadata = FileMetadata.objects.create(
                user=request.user,
                file_name=uploaded_file.name,
                encrypted_file=encrypted_data
            )
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
def share_file(request, file_id):
    file = get_object_or_404(FileMetadata, id=file_id, owner=request.user)
    if request.method == 'POST':
        username = request.POST.get('username')
        try:
            user_to_share = User.objects.get(username=username)
            file.shared_with.add(user_to_share)
            return HttpResponse("File shared successfully.")
        except User.DoesNotExist:
            return HttpResponse("User does not exist.", status=404)
    return render(request, 'vault/share_file.html', {'file': file})

# Request file access view
@login_required
def request_file_access(request, file_id):
    file = get_object_or_404(FileMetadata, id=file_id)
    if request.user != file.owner:
        # Notify the owner of the access request
        # Implement email/notification as needed
        return HttpResponse("Access request sent to file owner.")
    return HttpResponse("You already have access.")


@login_required
def download_file(request, file_id):
    file = get_object_or_404(FileMetadata, id=file_id, owner=request.user)
    if file.owner == request.user or request.user in file.shared_with.all():
        with open(file.file_path, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = decrypt_file(encrypted_data, 'secure_password')  # Update 'secure_password' as needed

        response = HttpResponse(decrypted_data, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{file.file_name}"'
        return response
    return HttpResponse("You do not have permission to download this file.", status=403)




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




class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']

@login_required
def profile(request):
    if request.method == 'POST':
        form = ProfileUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your profile has been updated!')
            return redirect('profile')  # Redirect to avoid form resubmission
    else:
        form = ProfileUpdateForm(instance=request.user)

    return render(request, 'vault/profile.html', {'form': form})





















