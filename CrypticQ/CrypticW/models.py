from django.db import models

class UserProfile(models.Model):
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    email = models.EmailField(max_length=255, blank=True, null=True)
    full_name = models.CharField(max_length=255, blank=True, null=True)
    birthdate = models.DateField(blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    # Add more fields as needed

    def __str__(self):
        return self.username
