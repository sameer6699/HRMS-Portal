from django.db import models
from django.contrib.auth.models import User


class Ticket(models.Model):
    ticket_id = models.CharField(max_length=100)
    subject = models.CharField(max_length=255)
    description = models.TextField()
    ticket_received_date = models.DateTimeField()
    department = models.CharField(max_length=100)
    status = models.CharField(max_length=50)

    def __str__(self):
        return self.ticket_id
    
class UserRole(models.Model):
    ROLE_CHOICES = [
        ('Admin', 'Admin'),
        ('Support Agent', 'Support Agent'),
        ('Supervisor', 'Supervisor'),
        ('User', 'User'),
        ('Quality Assurance', 'Quality Assurance'),
        ('Accounts', 'Accounts'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=50, choices=ROLE_CHOICES)

    def __str__(self):
        return f"{self.user.username} - {self.role}"