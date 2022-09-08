from django.contrib import admin
from django.shortcuts import render
from django.urls import path, include
from django.views import View


class Home(View):
    def get(self, request):
        return render(request, 'accounts/base.html')


urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),

    path('', Home.as_view(), name='home'),
]
