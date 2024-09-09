from django.urls import path
from . import views

app_name = 'weak_cipher_detector'

urlpatterns = [
    path('', views.analyze_certificate, name='analyze_certificate'),
]