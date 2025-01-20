from django.db import models

# Create your models here.

class Threat(models.Model):
    '''
    threat_name = models.CharField(max_length=255, null=True, blank=True)  # Nullable
    description = models.TextField(null=True, blank=True)  # Nullable
    threat_level = models.CharField(max_length=50, null=True, blank=True)
    category = models.CharField(max_length=100, null=True, blank=True)
    reported = models.DateTimeField(auto_now_add=True)  # No need for null here, since it's auto-generated
    origin = models.CharField(max_length=100, null=True, blank=True)
    status = models.CharField(max_length=50, null=True, blank=True)
    attack_destination = models.CharField(max_length=255, null=True, blank=True)'''
    
    
    origin_country_alpha2 = models.CharField(max_length=2, blank=True, null=True)  # Can be blank or null
    origin_country_name = models.CharField(max_length=100, blank=True, null=True)  # Can be blank or null
    value = models.DecimalField(max_digits=10, decimal_places=6, blank=True, null=True)  # Optional field
    rank = models.IntegerField(blank=True, null=True)  # Can be null
    
    class Meta:
        unique_together = ('origin_country_alpha2', 'rank')
        indexes = [
            models.Index(fields=['origin_country_alpha2']),
        ]
    

    
    
    def __str__(self):
        return self.threat_name

