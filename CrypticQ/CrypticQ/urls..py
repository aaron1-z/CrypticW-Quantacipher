from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('crypticw/', include('CrypticW.urls')),  # Include your app's URLs here
    # Add more URL patterns as needed
]
