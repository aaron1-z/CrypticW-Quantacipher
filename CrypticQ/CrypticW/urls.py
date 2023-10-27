from django.urls import path
from . import views

urlpatterns = [
    path('create_user/', views.create_user, name='create_user'),
    path('store_information/', views.store_information, name='store_information'),
    path('retrieve_information/', views.retrieve_information, name='retrieve_information'),
    # Add more URL patterns as needed
]
