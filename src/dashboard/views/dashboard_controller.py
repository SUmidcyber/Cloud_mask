from flask import Blueprint, render_template
from flask_socketio import emit
from src.dashboard.services import realtime_metrics
import json

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
def security_dashboard():
    """Güvenlik dashboard ana sayfasını render eder"""
    return render_template('dashboard/security.html')

@dashboard_bp.route('/api/metrics')
def get_metrics():
    """JSON formatında metrikleri döner"""
    return json.dumps(realtime_metrics.get_current_metrics())

def register_socketio_events(socketio):
    @socketio.on('connect')
    def handle_connect():
        emit('connection_established', {'status': 'connected'})
    
    @socketio.on('request_metrics')
    def handle_metrics_request(data):
        emit('metrics_update', realtime_metrics.get_latest())