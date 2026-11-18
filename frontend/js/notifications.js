// ========================================
// NOTIFICATION SYSTEM
// ========================================

// How long a notification stays, how soon after it is added it slides in, and how long its
// slide-out runs before it is removed (the stylesheet's .notification transition)
const NOTIFICATION_SHOWN_MS = 4000;
// A duration that never ends: the notification goes only when its close control is pressed
const NOTIFICATION_STAYS = 0;
const NOTIFICATION_ENTER_DELAY_MS = 10;
const NOTIFICATION_EXIT_MS = 300;
// The close control is the pixel close icon in a tile (pixels.js); its name stays here because a
// toast can be shown before ui.js (UI_TEXT) has loaded
const NOTIFICATION_CLOSE_ICON = 'close';
const NOTIFICATION_CLOSE_ARIA_LABEL = 'close notification';

function showNotification(message, type = 'info', duration = NOTIFICATION_SHOWN_MS) {
    const container = document.getElementById('notificationContainer');
    
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'close-btn icon-btn';
    const closeTile = document.createElement('span');
    closeTile.className = 'icon-tile';
    Pixels.setIcons(closeTile, NOTIFICATION_CLOSE_ICON);
    closeBtn.appendChild(closeTile);
    closeBtn.setAttribute('aria-label', NOTIFICATION_CLOSE_ARIA_LABEL);
    closeBtn.title = NOTIFICATION_CLOSE_ARIA_LABEL;
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

// standing (errors.js): the notification stays until the user closes it
function shownFor(standing) {
    return standing === true ? NOTIFICATION_STAYS : NOTIFICATION_SHOWN_MS;
}

function showError(message, standing = false) {
    showNotification(message, 'error', shownFor(standing));
}

function showWarning(message, standing = false) {
    showNotification(message, 'warning', shownFor(standing));
}