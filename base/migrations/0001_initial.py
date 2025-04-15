# Generated by Django 5.2 on 2025-04-15 21:52

import django.contrib.gis.db.models.fields
import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Benefit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='CompanyProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('logo', models.ImageField(upload_to='company/')),
                ('address', models.TextField()),
                ('contact_email', models.EmailField(max_length=254)),
                ('contact_phone', models.CharField(max_length=20)),
            ],
        ),
        migrations.CreateModel(
            name='Organization',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('location', django.contrib.gis.db.models.fields.PointField(blank=True, null=True, srid=4326)),
                ('geofence_radius', models.PositiveIntegerField(default=100, help_text='Radius in meters')),
                ('address', models.TextField(blank=True)),
                ('location_source', models.CharField(choices=[('manual', 'Manual Entry'), ('geocode', 'Geocode from Address'), ('first_checkin', 'Derive from First Intern Check-in'), ('pending', 'Pending Automatic Detection')], default='pending', max_length=20)),
            ],
            options={
                'verbose_name': 'Organization',
                'verbose_name_plural': 'Organizations',
            },
        ),
        migrations.CreateModel(
            name='University',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('location', models.CharField(max_length=200)),
                ('website', models.URLField(blank=True)),
                ('partnership_since', models.DateField(blank=True, null=True)),
            ],
            options={
                'verbose_name': 'University',
                'verbose_name_plural': 'Universities',
            },
        ),
        migrations.CreateModel(
            name='Department',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, null=True, unique=True)),
                ('code', models.CharField(help_text='Short department code (e.g., HR-001)', max_length=10, null=True, unique=True)),
                ('location', models.CharField(blank=True, max_length=100)),
                ('floor', models.CharField(blank=True, max_length=20)),
                ('budget', models.DecimalField(blank=True, decimal_places=2, help_text='Annual department budget', max_digits=12, null=True)),
                ('headcount', models.PositiveIntegerField(default=0)),
                ('active', models.BooleanField(default=True)),
                ('established_date', models.DateField(blank=True, null=True)),
                ('phone_extension', models.CharField(blank=True, max_length=10)),
                ('internal_email', models.EmailField(blank=True, max_length=254)),
                ('description', models.TextField(blank=True)),
                ('mission_statement', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('parent_department', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='sub_departments', to='base.department')),
            ],
            options={
                'verbose_name': 'Department',
                'verbose_name_plural': 'Departments',
                'ordering': ['name'],
                'permissions': [('can_manage_department', 'Can manage department settings')],
            },
        ),
        migrations.CreateModel(
            name='Employee',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=20, null=True)),
                ('employee_id', models.CharField(max_length=20, unique=True)),
                ('phone', models.CharField(max_length=15)),
                ('address', models.TextField()),
                ('hire_date', models.DateField()),
                ('salary', models.DecimalField(decimal_places=2, max_digits=10)),
                ('position', models.CharField(max_length=100)),
                ('is_active', models.BooleanField(default=True)),
                ('department', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='base.department')),
                ('user', models.OneToOneField(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Attendance',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date', models.DateField()),
                ('check_in', models.TimeField()),
                ('check_out', models.TimeField(blank=True, null=True)),
                ('status', models.CharField(choices=[('present', 'Present'), ('absent', 'Absent'), ('late', 'Late')], max_length=20)),
                ('employee', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='base.employee')),
            ],
        ),
        migrations.CreateModel(
            name='EmployeeBenefit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('enrollment_date', models.DateField()),
                ('benefit', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='base.benefit')),
                ('employee', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='base.employee')),
            ],
        ),
        migrations.AddField(
            model_name='benefit',
            name='employees',
            field=models.ManyToManyField(through='base.EmployeeBenefit', to='base.employee'),
        ),
        migrations.CreateModel(
            name='EmployeeSkill',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('proficiency', models.CharField(choices=[('beginner', 'Beginner'), ('intermediate', 'Intermediate'), ('expert', 'Expert')], max_length=20)),
                ('employee', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='base.employee')),
            ],
        ),
        migrations.CreateModel(
            name='Intern',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(max_length=50, null=True)),
                ('last_name', models.CharField(max_length=50, null=True)),
                ('date_of_birth', models.DateField(blank=True, null=True)),
                ('gender', models.CharField(blank=True, choices=[('M', 'Male'), ('F', 'Female'), ('O', 'Other'), ('U', 'Prefer not to say')], max_length=1, null=True)),
                ('image', models.ImageField(blank=True, null=True, upload_to='interns/images/')),
                ('personal_email', models.EmailField(max_length=254, null=True, unique=True)),
                ('phone_number', models.CharField(max_length=20, null=True)),
                ('emergency_contact_name', models.CharField(blank=True, max_length=100, null=True)),
                ('emergency_contact_phone', models.CharField(blank=True, max_length=20, null=True)),
                ('address', models.TextField(blank=True, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('degree_program', models.CharField(blank=True, max_length=100, null=True)),
                ('current_year', models.PositiveSmallIntegerField(blank=True, null=True)),
                ('expected_graduation', models.DateField(blank=True, null=True)),
                ('transcript', models.FileField(blank=True, null=True, upload_to='interns/transcripts/')),
                ('internship_start_date', models.DateField(null=True)),
                ('internship_end_date', models.DateField(null=True)),
                ('status', models.CharField(choices=[('active', 'Active'), ('completed', 'Completed'), ('terminated', 'Terminated'), ('extended', 'Extended')], default='active', max_length=20)),
                ('stipend_amount', models.DecimalField(blank=True, decimal_places=2, max_digits=8, null=True)),
                ('bank_account_number', models.CharField(blank=True, max_length=50, null=True)),
                ('bank_name', models.CharField(blank=True, max_length=100, null=True)),
                ('resume', models.FileField(blank=True, null=True, upload_to='interns/resumes/')),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('department', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='base.department')),
                ('mentor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='mentored_interns', to='base.employee')),
                ('user', models.OneToOneField(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='intern', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='base.organization')),
                ('university', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='base.university')),
            ],
            options={
                'verbose_name': 'Intern',
                'verbose_name_plural': 'Interns',
                'ordering': ['first_name'],
                'permissions': [('manage_interns', 'Can manage all intern records')],
            },
        ),
        migrations.CreateModel(
            name='JobOpening',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('requirements', models.TextField()),
                ('posted_date', models.DateField(auto_now_add=True)),
                ('is_active', models.BooleanField(default=True)),
                ('department', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='base.department')),
            ],
        ),
        migrations.CreateModel(
            name='Application',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('applicant_name', models.CharField(max_length=100)),
                ('applicant_email', models.EmailField(max_length=254)),
                ('resume', models.FileField(upload_to='resumes/')),
                ('status', models.CharField(choices=[('submitted', 'Submitted'), ('reviewed', 'Reviewed'), ('rejected', 'Rejected'), ('hired', 'Hired')], default='submitted', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('job', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='base.jobopening')),
            ],
        ),
        migrations.CreateModel(
            name='LeaveRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('start_date', models.DateField()),
                ('end_date', models.DateField()),
                ('reason', models.TextField()),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected')], default='pending', max_length=20)),
                ('employee', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='base.employee')),
            ],
        ),
        migrations.CreateModel(
            name='LocationLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('point', django.contrib.gis.db.models.fields.PointField(srid=4326)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('accuracy', models.FloatField(blank=True, null=True)),
                ('address', models.TextField(blank=True, null=True)),
                ('is_inside_geofence', models.BooleanField(default=False)),
                ('intern', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='base.intern')),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.TextField()),
                ('is_read', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='OTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('otp', models.CharField(max_length=6)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField()),
                ('is_verified', models.BooleanField(default=False)),
                ('token', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Payroll',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('month', models.DateField()),
                ('basic_salary', models.DecimalField(decimal_places=2, max_digits=10)),
                ('bonuses', models.DecimalField(decimal_places=2, default=0, max_digits=10)),
                ('deductions', models.DecimalField(decimal_places=2, default=0, max_digits=10)),
                ('tax', models.DecimalField(decimal_places=2, max_digits=10)),
                ('net_salary', models.DecimalField(decimal_places=2, max_digits=10)),
                ('employee', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='base.employee')),
            ],
        ),
        migrations.CreateModel(
            name='PerformanceReview',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date', models.DateField()),
                ('rating', models.IntegerField(choices=[(1, 'Poor'), (5, 'Excellent')])),
                ('comments', models.TextField()),
                ('employee', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='base.employee')),
                ('reviewer', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Skill',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('employees', models.ManyToManyField(through='base.EmployeeSkill', to='base.employee')),
            ],
        ),
        migrations.AddField(
            model_name='employeeskill',
            name='skill',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='base.skill'),
        ),
        migrations.CreateModel(
            name='WebAuthnCredential',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('credential_id', models.TextField()),
                ('public_key', models.TextField()),
                ('counter', models.IntegerField()),
                ('device_type', models.CharField(max_length=100)),
                ('backed_up', models.BooleanField()),
                ('transports', models.JSONField(default=list)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('user', 'credential_id')},
            },
        ),
    ]
