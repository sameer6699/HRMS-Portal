from django.db import models


class Ticket(models.Model):
    ticket_id = models.CharField(max_length=100)
    subject = models.CharField(max_length=255)
    description = models.TextField()
    ticket_received_date = models.DateTimeField()
    department = models.CharField(max_length=100)
    status = models.CharField(max_length=50)

    def __str__(self):
        return self.ticket_id