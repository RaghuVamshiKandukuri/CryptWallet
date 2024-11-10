
from CryptWallet.settings import MEDIA_URL, MEDIA_ROOT

from django.conf.urls.static import static
from django.urls import path, include
from .views import * 
from django.contrib import admin

urlpatterns = [
    path("", main, name="main"),
    path('main/',main, name='main'),
    path("login/", login, name="login"),
    path("register/", register, name="register"),
    path('logout/', logout_view, name='logout'),
    path('index/',index,name='index'),
    path('profile/', profile, name='profile'),
    path('settings/', settings, name='settings'),
    path('file_upload/', file_upload, name='file_upload')
    
    
] 

urlpatterns += static(MEDIA_URL, document_root=MEDIA_ROOT)





    
    
    
    
