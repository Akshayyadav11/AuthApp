from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from .models import CustomUser

class MultiFieldModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = CustomUser.objects.get(
                Q(email=username) |
                Q(opo_id=username) |
                Q(mobile_no=username)
            )
            if user.check_password(password):
                return user
        except CustomUser.DoesNotExist:
            return None
        except CustomUser.MultipleObjectsReturned:
            # Log this incident as it indicates a data integrity issue
            return None
        return None

    def get_user(self, user_id):
        try:
            return CustomUser.objects.get(pk=user_id)
        except CustomUser.DoesNotExist:
            return None