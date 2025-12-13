from django.conf import settings
from django.db import models

class PortScan(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="port_scans")
    target = models.CharField(max_length=255)
    ports = models.CharField(max_length=255, blank=True)
    profile = models.CharField(max_length=32, default="quick")
    notes = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

class PortScanResult(models.Model):
    scan = models.ForeignKey(PortScan, on_delete=models.CASCADE, related_name="results")
    port = models.IntegerField()
    protocol = models.CharField(max_length=8, default="TCP")
    state = models.CharField(max_length=16)
    service = models.CharField(max_length=64, blank=True)
    latency_ms = models.IntegerField(default=0)

class NetworkDiagram(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="diagrams")
    name = models.CharField(max_length=120, default="My Diagram")
    data = models.JSONField(default=dict)  # {"nodes":[...], "edges":[...]}
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)