import os
import sys
from pathlib import Path

# Add the project root directory to Python path
project_root = str(Path(__file__).resolve().parent.parent)
sys.path.append(project_root)

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'HRCallAnalysis.settings')
import django
django.setup()

# Now import Django models
from AuthApp.models import CustomUser, Role
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = 'Creates a super admin user with all required fields'

    def handle(self, *args, **options):
        # Get or create the SuperAdmin role
        role, created = Role.objects.get_or_create(name='SuperAdmin')
        
        # Check if super admin already exists
        if CustomUser.objects.filter(is_superuser=True).exists():
            self.stdout.write(self.style.WARNING('Super admin already exists!'))
            return
        
        # Create super admin
        superadmin = CustomUser.objects.create_superuser(
            email='superadmin@example.com',
            password='admin123',  # Change this in production!
            first_name='Super',
            last_name='Admin',
            opo_id='SUPER001',
            mobile_no='1234567890',
            role=role,
            designation='System Administrator'
        )
        
        self.stdout.write(self.style.SUCCESS('Successfully created super admin!'))

if __name__ == '__main__':
    command = Command()
    command.handle()