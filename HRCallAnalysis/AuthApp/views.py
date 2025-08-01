import logging
from rest_framework import status, permissions

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from django.contrib.auth import authenticate, get_user_model
from .serializers import (
    UserSerializer, UserRegisterSerializer,
    UserLoginSerializer, TokenSerializer, RoleSerializer
)
from .models import CustomUser, Role
from django.utils import timezone

# Set up logging
logger = logging.getLogger(__name__)

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        # Pass the request in the context to the serializer
        serializer = UserRegisterSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                'user': UserSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        from django.contrib.auth import authenticate
        from django.conf import settings
        
        username = request.data.get('username')
        password = request.data.get('password')
        
        if not username or not password:
            return Response(
                {'error': 'Please provide both username and password'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Try to authenticate using the custom backend
        user = authenticate(
            request=request,
            username=username,
            password=password
        )
        
        if user is None:
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        # Check if user is active and not deleted
        if not user.is_active:
            return Response(
                {'error': 'Your account is inactive. Please contact the administrator.'},
                status=status.HTTP_403_FORBIDDEN
            )
            
        if user.is_deleted:
            return Response(
                {'error': 'Your account has been deleted. Please contact the administrator.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Update last_login field
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'status': True,
            'message': 'Login successful',
            'user': UserSerializer(user).data,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            # 'expires_in': int(settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()),
            # 'token_type': 'Bearer'
        })

class TokenRefreshView(APIView):
    """
    Takes a refresh token and returns a new access token.
    If ROTATE_REFRESH_TOKENS is True, also returns a new refresh token.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request, *args, **kwargs):
        from rest_framework_simplejwt.tokens import RefreshToken
        from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
        from django.conf import settings
        
        refresh_token = request.data.get('refresh')
        
        if not refresh_token:
            return Response(
                {'error': 'Refresh token is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Get the old refresh token
            old_refresh = RefreshToken(refresh_token)
            
            # Verify the token type is refresh
            if old_refresh.get('token_type') != 'refresh':
                raise InvalidToken('Token has wrong type')
            
            # Get the user ID from the token
            user_id = old_refresh.get('user_id')
            if not user_id:
                raise InvalidToken('Token contains no user identification')
            
            # Create response data with new access token
            response_data = {
                'access': str(old_refresh.access_token),
                'user_id': user_id
            }
            
            rotate_tokens = getattr(settings, 'SIMPLE_JWT', {}).get('ROTATE_REFRESH_TOKENS', False)
            blacklist_after_rotation = getattr(settings, 'SIMPLE_JWT', {}).get('BLACKLIST_AFTER_ROTATION', True)
            
            if rotate_tokens:
                logger.debug('Token rotation enabled')
                try:
                    # Blacklist the old refresh token
                    if blacklist_after_rotation:
                        old_refresh.blacklist()
                        logger.debug('Old token blacklisted')
                    
                    # Create a new refresh token
                    User = get_user_model()
                    try:
                        user = User.objects.get(id=user_id)
                        new_refresh = RefreshToken.for_user(user)
                        # Set token type in the payload
                        new_refresh['token_type'] = 'refresh'
                        # Add user_id to the payload
                        new_refresh['user_id'] = str(user.id)
                        response_data['refresh'] = str(new_refresh)
                        logger.debug('New refresh token generated')
                    except User.DoesNotExist:
                        logger.error(f'User {user_id} not found')
                        raise InvalidToken('User not found')
                except Exception as e:
                    logger.error(f'Error generating new refresh token: {str(e)}')
                    raise InvalidToken('Error generating new refresh token')
            
            return Response(response_data)
            
        except Exception as e:
            error_msg = str(e)
            error_type = type(e).__name__
            
            # Handle specific JWT errors
            if 'Token is blacklisted' in error_msg:
                return Response(
                    {'error': 'Token has been blacklisted. Please log in again.'}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
            elif 'Token is invalid or expired' in error_msg:
                return Response(
                    {'error': 'Refresh token is invalid or has expired. Please log in again.'}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # For debugging - return detailed error in development
            import sys, traceback
            exc_type, exc_value, exc_traceback = sys.exc_info()
            error_details = {
                'error': 'Could not refresh token',
                'type': error_type,
                'message': error_msg,
                'traceback': traceback.format_exc() if settings.DEBUG else None
            }
            
            return Response(
                error_details,
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

from django.db import connection
from django.db.utils import DatabaseError

class UserListView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT id, last_login, is_superuser, first_name, last_name, 
                           email, opo_id, mobile_no, role_id, designation, is_active, 
                           is_staff, is_deleted, created_by_id, created_at, updated_at
                    FROM AuthApp_customuser 
                    WHERE is_deleted = 0
                """)
                columns = [col[0] for col in cursor.description]
                users = [dict(zip(columns, row)) for row in cursor.fetchall()]
                
                # Convert datetime fields to string for JSON serialization
                for user in users:
                    if user['last_login']:
                        user['last_login'] = user['last_login'].isoformat()
                    if user['created_at']:
                        user['created_at'] = user['created_at'].isoformat()
                    if user['updated_at']:
                        user['updated_at'] = user['updated_at'].isoformat()
                
                return Response(users)
                
        except DatabaseError as e:
            logger.error(f"Database error in UserListView: {str(e)}")
            return Response(
                {'error': 'An error occurred while fetching users'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class UserDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get_user_by_id(self, user_id):
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id, password, last_login, is_superuser, first_name, last_name, 
                       email, opo_id, mobile_no, role_id, designation, is_active, 
                       is_staff, is_deleted, created_by_id, created_at, updated_at
                FROM AuthApp_customuser 
                WHERE id = %s AND is_deleted = 0
            """, [user_id])
            
            columns = [col[0] for col in cursor.description]
            row = cursor.fetchone()
            if not row:
                return None
                
            user = dict(zip(columns, row))
            # Convert datetime fields to string for JSON serialization
            if user['last_login']:
                user['last_login'] = user['last_login'].isoformat()
            if user['created_at']:
                user['created_at'] = user['created_at'].isoformat()
            if user['updated_at']:
                user['updated_at'] = user['updated_at'].isoformat()
            return user
    
    def get(self, request, pk):
        try:
            user = self.get_user_by_id(pk)
            if not user:
                return Response(
                    {'error': 'User not found'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            return Response(user)
            
        except DatabaseError as e:
            logger.error(f"Database error in UserDetailView get: {str(e)}")
            return Response(
                {'error': 'An error occurred while fetching user'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def put(self, request, pk):
        try:
            # First check if user exists and is not deleted
            if not self.get_user_by_id(pk):
                return Response(
                    {'error': 'User not found'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Prepare the update query
            update_fields = []
            params = []
            
            # Add all fields that can be updated
            for field in ['first_name', 'last_name', 'email', 'opo_id', 'mobile_no', 
                         'role_id', 'designation', 'is_active', 'is_staff']:
                if field in request.data:
                    update_fields.append(f"{field} = %s")
                    params.append(request.data[field])
            
            if not update_fields:
                return Response(
                    {'error': 'No valid fields to update'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Add updated_at
            update_fields.append("updated_at = NOW()")
            
            # Add user_id for WHERE clause
            params.append(pk)
            
            # Build and execute the update query
            update_query = f"""
                UPDATE authapp_customuser 
                SET {', '.join(update_fields)}
                WHERE id = %s AND is_deleted = 0
            """
            
            with connection.cursor() as cursor:
                cursor.execute(update_query, params)
                if cursor.rowcount == 0:
                    return Response(
                        {'error': 'User not found or no changes made'}, 
                        status=status.HTTP_404_NOT_FOUND
                    )
            
            # Return the updated user
            updated_user = self.get_user_by_id(pk)
            return Response(updated_user)
            
        except DatabaseError as e:
            logger.error(f"Database error in UserDetailView put: {str(e)}")
            return Response(
                {'error': 'An error occurred while updating user'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def delete(self, request, pk):
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE AuthApp_customuser 
                    SET is_deleted = 1, updated_at = NOW()
                    WHERE id = %s AND is_deleted = 0
                """, [pk])
                
                if cursor.rowcount == 0:
                    return Response(
                        {'error': 'User not found or already deleted'}, 
                        status=status.HTTP_404_NOT_FOUND
                    )
                    
            return Response(status=status.HTTP_204_NO_CONTENT)
            
        except DatabaseError as e:
            logger.error(f"Database error in UserDetailView delete: {str(e)}")
            return Response(
                {'error': 'An error occurred while deleting user'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class RoleListView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT id, name
                    FROM AuthApp_role
                    ORDER BY id
                """)
                
                columns = [col[0] for col in cursor.description]
                roles = [dict(zip(columns, row)) for row in cursor.fetchall()]
                return Response(roles)
                
        except DatabaseError as e:
            logger.error(f"Database error in RoleListView: {str(e)}")
            return Response(
                {'error': 'An error occurred while fetching roles'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )