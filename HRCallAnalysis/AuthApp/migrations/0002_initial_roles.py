from django.db import migrations

def create_initial_roles(apps, schema_editor):
    Role = apps.get_model('AuthApp', 'Role')
    Role.objects.create(name='Admin')
    Role.objects.create(name='SuperAdmin')
    Role.objects.create(name='User')

class Migration(migrations.Migration):
    dependencies = [
        ('AuthApp', '0001_initial'),
    ]
    operations = [
        migrations.RunPython(create_initial_roles),
    ]