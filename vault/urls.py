
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
    path('upload/', file_upload_view, name='file_upload'),
    path('files/', file_list_view, name='file_list'),
    path('files/<int:file_id>/', file_detail_view, name='file_detail'),
    path('files/<int:file_id>/request_access/', request_file_access, name='request_file_access'),
    path('files/<int:file_id>/download/', download_file, name='download_file'),
    path('files/<int:file_id>/share/', share_file, name='share_file'),
    path('profile/', profile, name='profile'),
    path('messages/', messages, name='messages'),
    path('settings/', settings, name='settings'),
    
    
] 

urlpatterns += static(MEDIA_URL, document_root=MEDIA_ROOT)


    
    
    
    
