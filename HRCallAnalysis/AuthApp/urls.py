from django.urls import path
from .views import (
    RegisterView, LoginView, TokenRefreshView,
    UserListView, UserDetailView,
    RoleListView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('users/', UserListView.as_view(), name='user-list'),
    # path('users/<int:pk>/', UserDetailView.as_view(), name='user-detail'),
    # path('roles/', RoleListView.as_view(), name='role-list'),
]