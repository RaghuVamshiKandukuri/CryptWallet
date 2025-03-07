from fileinput import filename
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect, Http404, HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as django_login
from django.urls import reverse
from django.conf import settings
from django.contrib.auth.models import User
from django import forms
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
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




@login_required
def file_upload(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            password = "secure_password"  # Replace with a secure password or user-provided input
            original_file_name = uploaded_file.name
            encrypted_file_path = os.path.join(settings.MEDIA_ROOT, 'uploads', original_file_name + '.enc')

            os.makedirs(os.path.dirname(encrypted_file_path), exist_ok=True)

            with uploaded_file.open('rb') as infile, open(encrypted_file_path, 'wb') as outfile:
                encrypt_file(infile, outfile, password)

            UploadedFile.objects.create(
                user=request.user,
                file='uploads/' + original_file_name + '.enc'
            )

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

    files = UploadedFile.objects.filter(user=request.user)
    return render(request, 'vault/file_upload.html', {'form': form, 'files': files})



VALID_VISIBILITY_OPTIONS = {"public", "private"}

@login_required
def toggle_file_visibility(request, file_id):
    file_obj = get_object_or_404(UploadedFile, id=file_id)

    # Check user permissions
    if file_obj.user != request.user:
        return HttpResponseForbidden("You do not have permission to update this file.")

    if request.method == "POST":
        visibility = request.POST.get("visibility").upper()

        # Validate visibility parameter
        if visibility.lower() not in VALID_VISIBILITY_OPTIONS:
            messages.error(request, "Invalid visibility option.")
            return redirect('file_upload')

        # Update file visibility
        file_obj.visibility = visibility.strip()
        file_obj.save()

        # Log the update
        AuditLog.objects.create(
            user=request.user,
            action="UPDATE",
            file_name=file_obj.file.name,
            details=f"Visibility set to {visibility}."
        )

        messages.success(request, f"File is now {visibility}.")

    return redirect('file_upload')


@login_required
def share_file(request, file_id):
    file_obj = get_object_or_404(UploadedFile, id=file_id)

    if file_obj.user != request.user:
        return HttpResponseForbidden("You can only share your own files.")

    if request.method == "POST":
        username = request.POST.get("username")
        recipient = User.objects.filter(username=username).first()

        if recipient:
            # Prevent duplicate sharing
            if not SharedFile.objects.filter(shared_by=request.user, shared_with=recipient, file=file_obj).exists():
                SharedFile.objects.create(shared_by=request.user, shared_with=recipient, file=file_obj)
                messages.success(request, f"File successfully shared with {recipient.username}.")
            else:
                messages.warning(request, f"You have already shared this file with {recipient.username}.")
        else:
            messages.error(request, "User not found.")

    return redirect('file_upload')




@login_required
def view_shared_files(request):
    files = UploadedFile.objects.filter(shared_with=request.user)
    return render(request, 'vault/shared_files.html', {'files': files})





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




@login_required
def delete_file(request, file_id):
    file_obj = get_object_or_404(UploadedFile, id=file_id)

    # Ensure the file belongs to the logged-in user
    if file_obj.user != request.user:
        return HttpResponseForbidden("You do not have permission to delete this file.")

    original_file_name = os.path.basename(file_obj.file.name).replace('.enc', '')
    if request.method == "POST":
        file_obj.file.delete()  # Deletes the file from storage
        file_obj.delete()  # Deletes the database record

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



@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    AuditLog.objects.create(
        user=user,
        action='LOGIN',
        details=f"User {user.username} logged in."
    )

@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    AuditLog.objects.create(
        user=user,
        action='LOGOUT',
        details=f"User {user.username} logged out."
    )



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


def u(request, username):
    user = User.objects.get(username=username)
    print(username, user)
    return render(request, 'vault/user.html', {
        'u': user,
        'files': UploadedFile.objects.filter(user__username=username, visibility="PUBLIC")
    })



from django.contrib.auth.decorators import login_required

@login_required
def audit_logs(request):
    logs = AuditLog.objects.filter(user=request.user).order_by('-timestamp')
    return render(request, 'vault/audit_logs.html', {'logs': logs})





from .models import Message

@login_required
def message_list(request):
    messages = Message.objects.filter(receiver=request.user).order_by('-timestamp')
    return render(request, 'vault/message_list.html', {'messages': messages})


@login_required
def send_message(request, user_id=None):
    if request.method == 'POST':
        recipient_id = request.POST.get('recipient')
        content = request.POST.get('content')
        if not content:
            messages.error(request, "Message content cannot be empty.")
            return redirect('send_message')

        recipient = get_object_or_404(User, id=recipient_id)
        Message.objects.create(
            sender=request.user,
            receiver=recipient,
            content=content
        )
        messages.success(request, f"Message sent to {recipient.username}.")
        return redirect('search_user')

    users = User.objects.exclude(id=request.user.id)  # Exclude the logged-in user
    return render(request, 'vault/send_message.html', {'users': users})



from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.models import User  # Use your User model here

def search_user(request):
    query = request.GET.get('q', '').strip()  # Get and sanitize the search query
    user = None

    if query:  # If there's a query, try to find the user
        user = User.objects.filter(username__iexact=query).first()  # Case-insensitive match, returns None if not found

    return render(request, 'vault/search_user.html', {'query': query, 'user': user})

@login_required
def search_suggestions(request):
    """View to handle user search suggestions."""
    if request.method == "GET":
        query = request.GET.get("q", "").strip()

        # Return empty list for short queries
        if len(query) < 2:
            return JsonResponse([], safe=False)

        # Search for users excluding the current user
        users = User.objects.filter(username__icontains=query).exclude(id=request.user.id)
        suggestions = [{"username": user.username} for user in users]

        return JsonResponse(suggestions, safe=False)

    return JsonResponse([], safe=False)


from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.contrib import messages
from .models import UploadedFile, SharedFile
from django.contrib.auth.models import User

from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from django.http import HttpResponse

@login_required
def share_file(request, file_id):
    file = get_object_or_404(UploadedFile, id=file_id, user=request.user)
    if request.method == 'POST':
        username = request.POST.get('username')
        print("Username received:", username)  # Debugging
        recipient = get_object_or_404(User, username=username)
        SharedFile.objects.create(file=file, shared_by=request.user, shared_with=recipient)
        return HttpResponse(f"File shared with {recipient.username}")
    return HttpResponse("Invalid request.")



from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import SharedFile

@login_required
def shared_files(request):
    shared_files = SharedFile.objects.filter(shared_with=request.user).select_related('file', 'shared_by')
    return render(request, 'vault/shared_files.html', {'shared_files': shared_files})