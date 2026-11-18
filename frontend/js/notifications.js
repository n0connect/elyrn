// ========================================
// NOTIFICATION SYSTEM
// ========================================

// How long a notification stays, how soon after it is added it slides in, and how long its
// slide-out runs before it is removed (the stylesheet's .notification transition)
const NOTIFICATION_SHOWN_MS = 4000;
const NOTIFICATION_ENTER_DELAY_MS = 10;
const NOTIFICATION_EXIT_MS = 300;
const NOTIFICATION_CLOSE_LABEL = '×';
const NOTIFICATION_CLOSE_ARIA_LABEL = 'Close notification';

function showNotification(message, type = 'info', duration = NOTIFICATION_SHOWN_MS) {
    const container = document.getElementById('notificationContainer');
    
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    const closeBtn = document.createElement('button');
    closeBtn.className = 'close-btn';
    closeBtn.textContent = NOTIFICATION_CLOSE_LABEL;
    closeBtn.setAttribute('aria-label', NOTIFICATION_CLOSE_ARIA_LABEL);
    closeBtn.addEventListener('click', function() {
        closeNotification(this);
    });
    
    const msgDiv = document.createElement('div');
    msgDiv.textContent = message;
    
    notification.appendChild(closeBtn);
    notification.appendChild(msgDiv);
    
    // Add to container
    container.appendChild(notification);
    
    // Show animation
    setTimeout(() => {
        notification.classList.add('show');
    }, NOTIFICATION_ENTER_DELAY_MS);
    
    // Auto remove after duration
    if (duration > 0) {
        setTimeout(() => {
            closeNotification(notification.querySelector('.close-btn'));
        }, duration);
    }
}

function closeNotification(closeBtn) {
    const notification = closeBtn.parentElement;
    notification.classList.remove('show');
    
    // Remove from DOM after animation
    setTimeout(() => {
        if (notification.parentElement) {
            notification.parentElement.removeChild(notification);
        }
    }, NOTIFICATION_EXIT_MS);
}

function showSuccess(message) {
    showNotification(message, 'success');
}

function showError(message) {
    showNotification(message, 'error');
}

function showWarning(message) {
    showNotification(message, 'warning');
}