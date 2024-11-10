from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect
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
from .models import UploadedFile

def file_upload(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('file_upload')
    else:
        form = FileUploadForm()
    files = UploadedFile.objects.all()
    return render(request, 'vault/file_upload.html', {'form': form, 'files': files})



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





















