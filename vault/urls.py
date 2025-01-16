
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
    path('u/<str:username>/', u, name="u"),


    path('setting/', setting, name='setting'),
    path('file_upload/', file_upload, name='file_upload'),
    path('delete/<int:file_id>/', delete_file, name='delete_file'),
    path('download/<int:file_id>/', download_file, name='download_file'),
    path('audit-logs/', audit_logs, name='audit_logs'),
    path('messages/', message_list, name='message_list'),
    path('messages/send/<int:user_id>/', send_message, name='send_message'),
    path('users/search/', search_user, name='search_user'),
    path('search_suggestions', search_suggestions, name='search_suggestions'),
    path('files/upload/', file_upload, name='file_upload'),
    path('files/<int:file_id>/toggle-visibility/', toggle_file_visibility, name='toggle_visibility'),
    path('files/<int:file_id>/share/', share_file, name='share_files'),
    path('share_files/', share_file, name='share_files'),
    path('shared-files/',shared_files, name='shared_files'),
    path('files/<int:file_id>/share/', share_file, name='share_file'),
    path('shared-files/', shared_files, name='shared_files'),

    path('share_file/<int:file_id>/', share_file, name='share_file'),
    

    

] 

urlpatterns += static(MEDIA_URL, document_root=MEDIA_ROOT)
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)



    
    
    
    
