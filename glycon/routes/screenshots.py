from flask_login import current_user
from flask_socketio import emit
from glycon.config import CONFIG
import sqlite3
import os

def init_screenshot_handlers(socketio):
    @socketio.on('delete_screenshot')
    def handle_delete_screenshot(data):
        if not current_user.is_authenticated:
            emit('screenshots_error', {'error': 'Unauthorized'})
            return
            
        screenshot_id = data.get('screenshot_id')
        if not screenshot_id:
            emit('screenshots_error', {'error': 'screenshot_id required'})
            return
            
        try:
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            # Get screenshot info first
            c.execute("SELECT id, agent_id, file_path FROM screenshots WHERE id = ?", (screenshot_id,))
            screenshot = c.fetchone()
            
            if not screenshot:
                emit('screenshots_error', {'error': 'Screenshot not found'})
                return
                
            # Delete from database
            c.execute("DELETE FROM screenshots WHERE id = ?", (screenshot_id,))
            
            # Delete the file
            file_path = screenshot[2]
            if os.path.exists(file_path):
                os.remove(file_path)
                
            conn.commit()
            
            # Notify all clients
            emit('screenshot_deleted', {
                'screenshot_id': screenshot_id,
                'agent_id': screenshot[1],
                'message': 'Screenshot deleted successfully'
            }, broadcast=True)
            
        except Exception as e:
            conn.rollback()
            emit('screenshots_error', {
                'error': f"Failed to delete screenshot: {str(e)}"
            })
        finally:
            conn.close()