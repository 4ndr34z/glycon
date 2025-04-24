from flask_login import current_user
from flask_socketio import emit
from glycon.config import CONFIG
import sqlite3
import os

def init_screenshot_handlers(socketio):
    @socketio.on('delete_screenshot')
    def handle_delete_screenshot(data):
        try:
            if not current_user.is_authenticated:
                raise PermissionError('Unauthorized')
                
            screenshot_id = data.get('screenshot_id')
            if not screenshot_id:
                raise ValueError('Missing screenshot_id')
                
            conn = sqlite3.connect(CONFIG.database)
            c = conn.cursor()
            
            c.execute("SELECT id, agent_id, file_path FROM screenshots WHERE id = ?", (screenshot_id,))
            screenshot = c.fetchone()
            
            if not screenshot:
                raise ValueError('Screenshot not found')
                
            # Delete from database
            c.execute("DELETE FROM screenshots WHERE id = ?", (screenshot_id,))
            
            # Delete file
            file_path = screenshot[2]
            if os.path.exists(file_path):
                os.remove(file_path)
                
            conn.commit()
            
            emit('screenshot_deleted', {
                'screenshot_id': screenshot_id,
                'agent_id': screenshot[1]
            }, broadcast=True)
            
        except Exception as e:
            conn.rollback()
            emit('screenshots_error', {
                'error': str(e),
                'screenshot_id': data.get('screenshot_id')
            })
        finally:
            conn.close()