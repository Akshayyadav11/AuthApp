from django.core.exceptions import ValidationError
import re

def validate_mobile_no(value):
    if value is None:
        return
    if not re.match(r'^\+?1?\d{9,15}$', value):
        raise ValidationError("Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")

def validate_opo_id(value):
    if value is None:
        return
    if not re.match(r'^[A-Za-z0-9]{6,20}$', value):
        raise ValidationError("OPO ID must be 6-20 alphanumeric characters.")