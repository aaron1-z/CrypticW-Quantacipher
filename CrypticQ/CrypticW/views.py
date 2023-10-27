# CrypticW/views.py
from django.shortcuts import render
from django.http import HttpResponse
from .utils import create_user_credentials, store_information, retrieve_information

# View to handle user registration
def create_user(request):
    if request.method == 'POST':
        # Get username and password from the form data
        username = request.POST['username']
        password = request.POST['password']
        
        # Call the create_user_credentials function from utils.py
        user_credentials = create_user_credentials(username, password)
        
        # You can save user_credentials in your database if needed
        
        # Render the registration success template and pass the username to display
        return render(request, 'registration_success.html', {'username': username})
    
    # If the request method is GET, render the create user form template
    return render(request, 'create_user.html')

# View to handle storing user information
def store_information(request):
    if request.method == 'POST':
        # Get username, password, and data from the form data
        username = request.POST['username']
        password = request.POST['password']
        data = request.POST['data']
        
        # Authenticate user (you might want to implement authentication logic here)
        
        # Call the store_information function from utils.py
        store_information(username, data)
        
        # Render the information stored template
        return render(request, 'information_stored.html')
    
    # If the request method is GET, render the store information form template
    return render(request, 'store_information.html')

# View to handle retrieving user information
def retrieve_information(request):
    if request.method == 'POST':
        # Get username, password, and info_id from the form data
        username = request.POST['username']
        password = request.POST['password']
        info_id = request.POST['info_id']
        
        # Authenticate user (you might want to implement authentication logic here)
        
        # Call the retrieve_information function from utils.py
        information = retrieve_information(username, info_id)
        
        # Render the information template and pass the retrieved information to display
        return render(request, 'information.html', {'information': information})
    
    # If the request method is GET, render the retrieve information form template
    return render(request, 'retrieve_information.html')
