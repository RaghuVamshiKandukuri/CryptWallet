from fileinput import filename
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as django_login
from django.urls import reverse
from django.conf import settings
from django.contrib.auth.models import User
from django import forms

from .models import UploadedFile
from .forms import FileUploadForm, ProfileUpdateForm

from django.contrib import messages
import os
from django.contrib.auth import logout

from django.core.files.storage import default_storage
from django.core.files.base import ContentFile


from .forms import FileUploadForm

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import os


from .models import AuditLog

# Generate a secure encryption key using a password and salt
def generate_key(password: str, salt: bytes) -> bytes:
    if not password or not isinstance(password, str):
        raise ValueError("Password must be a non-empty string.")
    
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt a file with AES encryption
def encrypt_file(input_file, output_file, password: str):
    if not password:
        raise ValueError("A password is required for encryption.")
    
    # Generate a salt and an IV
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    key = generate_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Write salt and IV to the output file
    output_file.write(salt)
    output_file.write(iv)

    # Encrypt the file in chunks
    while chunk := input_file.read(64 * 1024):
        output_file.write(encryptor.update(chunk))
    output_file.write(encryptor.finalize())

# Decrypt a file with AES decryption
def decrypt_file(encrypted_file_path: str, password: str) -> bytes:
    if not password:
        raise ValueError("A password is required for decryption.")

    with open(encrypted_file_path, 'rb') as encrypted_file:
        # Read salt and IV from the file
        salt = encrypted_file.read(16)
        iv = encrypted_file.read(16)

        # Derive the encryption key
        key = generate_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the file content
        decrypted_data = decryptor.update(encrypted_file.read()) + decryptor.finalize()

    return decrypted_data




def file_upload(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            password = "secure_password"  # Replace with a secure password or user-provided input
            original_file_name = uploaded_file.name
            encrypted_file_path = os.path.join(settings.MEDIA_ROOT, 'uploads', original_file_name + '.enc')

            # Ensure the directory exists
            os.makedirs(os.path.dirname(encrypted_file_path), exist_ok=True)

            # Encrypt the file
            with uploaded_file.open('rb') as infile, open(encrypted_file_path, 'wb') as outfile:
                encrypt_file(infile, outfile, password)

            # Save file metadata
            UploadedFile.objects.create(file='uploads/' + original_file_name + '.enc')

            AuditLog.objects.create(
                user=request.user,
                action='UPLOAD',
                file_name=original_file_name,
                details="File uploaded and encrypted."
            )


            messages.success(request, "File uploaded and encrypted successfully.")
            return redirect('file_upload')
    else:
        form = FileUploadForm()

    files = UploadedFile.objects.all()
    return render(request, 'vault/file_upload.html', {'form': form, 'files': files})

# File download view
def download_file(request, file_id):
    file_obj = get_object_or_404(UploadedFile, id=file_id)
    encrypted_file_path = os.path.join(settings.MEDIA_ROOT, file_obj.file.name)
    original_file_name = os.path.basename(file_obj.file.name).replace('.enc', '')

    password = "secure_password"  # Replace with the same password used for encryption

    try:
        decrypted_data = decrypt_file(encrypted_file_path, password)

        AuditLog.objects.create(
            user=request.user,
            action='DOWNLOAD',
            file_name=original_file_name,
            details="File decrypted and downloaded."
        )

        # Serve the decrypted file for download
        response = HttpResponse(decrypted_data, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{original_file_name}"'
        return response

    except Exception as e:
        print(f"Decryption error: {e}")
        raise Http404("File could not be decrypted or found.")




def delete_file(request, file_id):
    file_obj = get_object_or_404(UploadedFile, id=file_id)
    original_file_name = os.path.basename(file_obj.file.name).replace('.enc', '')
    if request.method == "POST":
        file = get_object_or_404(UploadedFile, id=file_id)  # Change 'UploadedFile' to your model name
        file.file.delete()  # Deletes the file from storage
        file.delete()  # Deletes the database record

        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            file_name=original_file_name,
            details="File deleted from storage."
        )
        
        messages.success(request, "File deleted successfully.")
    return redirect('file_upload')  # Redirect to the file upload page




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
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        
        if password == confirm_password:
            if User.objects.filter(username=username).exists():
                error_message = "Username already taken. Please choose another."
            elif User.objects.filter(email=email).exists():
                error_message = "Email is already in use. Please use a different email."
            else:
                # Create user with first name and last name
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name
                )
                django_login(request, user)
                return redirect('index')
        else:
            error_message = "Passwords do not match."
        return render(request, 'vault/auth/register.html', {'error_message': error_message})
    
    return render(request, 'vault/auth/register.html')







def logout_view(request):
    logout(request)
    return redirect('login')  # Redirect to login page after logging out



def setting(request):
    # Sample context data for settings
    context = {
        'setting': {
            'email_notifications': True,
            'sms_alerts': False,
            'dark_mode': True,
        }
    }
    return render(request, 'vault/setting.html', context)



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






from django.contrib.auth.decorators import login_required

@login_required
def audit_logs(request):
    logs = AuditLog.objects.filter(user=request.user).order_by('-timestamp')
    return render(request, 'vault/audit_logs.html', {'logs': logs})



