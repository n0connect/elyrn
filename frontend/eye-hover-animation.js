/* ========================================
   EYE HOVER PROGRESSIVE ACCOUNT NUMBER REVEAL SYSTEM
   5cm radius zone-based animation controller
   ======================================== */

// Zone radii around the eye's centre, in pixels: compact zones for precise control
const EYE_ZONE_RADII_PX = Object.freeze({
    inner: 18,    // smooth reveal
    middle: 51,   // fast scramble (2x)
    outer: 87     // responsive scramble
});
// Per animation frame, by zone: the share of hidden characters redrawn at rest
// (scramble), how much each unit of mouse speed adds to it (perSpeed), and how far the
// reveal moves (reveal). In the inner zone the scramble fades as the reveal grows (perReveal).
const EYE_ZONE_MOTION = Object.freeze({
    outer: Object.freeze({ scramble: 0.15, perSpeed: 0.1, reveal: -0.02 }),
    middle: Object.freeze({ scramble: 0.4, perSpeed: 0.15, reveal: 0.01 }),
    inner: Object.freeze({ scramble: 0.2, perReveal: 0.3, reveal: 0.03 })
});
// Mouse speed is pixels per millisecond times this, capped at EYE_MAX_MOUSE_SPEED
const EYE_MOUSE_SPEED_SCALE = 10;
const EYE_MAX_MOUSE_SPEED = 5;

class EyeHoverAnimation {
    constructor() {
        this.eyeIcon = null;
        this.accountNumberInput = null;
        this.isInitialized = false;
        this.currentZone = 'none';
        this.originalValue = '';
        this.displayValue = '';
        this.animationFrame = null;
        this.mouseSpeed = 0;
        this.lastMousePos = { x: 0, y: 0 };
        this.lastMouseTime = Date.now();
        this.revealProgress = 0; // 0 to 1
        // A login is reading the number (holdMasked): nothing is drawn until release()
        this.held = false;

        // Zone configurations (in pixels)
        this.zones = { ...EYE_ZONE_RADII_PX };

        // The account number's alphabet, as the scramble in ui.js draws it
        this.characters = SCRAMBLE_CHARS;

        // Deterministic reveal order (seeded random)
        this.revealOrder = [];

        this.init();
    }

    init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setupAnimation());
        } else {
            this.setupAnimation();
        }
    }

    setupAnimation() {
        this.eyeIcon = document.getElementById('eyeIcon');
        this.accountNumberInput = document.getElementById('accountNumberInput');
        
        if (!this.eyeIcon || !this.accountNumberInput) return;

        // Store original value when input changes
        this.accountNumberInput.addEventListener('input', (e) => {
            if (this.currentZone === 'none') {
                this.originalValue = e.target.value;
                this.generateRevealOrder();
            }
        });

        // Typing always wins over the hover effect: restore the real value before the edit lands,
        // otherwise keystrokes made near the eye are overwritten by the next animation frame
        const yieldToUser = () => {
            if (this.currentZone !== 'none') {
                this.stopAnimation();
                this.resetToMasked();
                this.currentZone = 'none';
                this.updateEyeStyle();
            }
        };
        this.accountNumberInput.addEventListener('keydown', yieldToUser);
        this.accountNumberInput.addEventListener('paste', yieldToUser);

        // Initialize
        this.originalValue = this.accountNumberInput.value;
        this.generateRevealOrder();

        // Track mouse on ENTIRE document (not just wrapper)
        // Bind handleMouseMove to preserve 'this' context and store reference for cleanup
        this.boundHandleMouseMove = this.handleMouseMove.bind(this);
        document.addEventListener('mousemove', this.boundHandleMouseMove);
        
        this.isInitialized = true;
    }

    generateRevealOrder() {
        // Create a shuffled order for character reveal
        const len = this.originalValue.length;
        this.revealOrder = [];
        for (let i = 0; i < len; i++) {
            this.revealOrder.push(i);
        }
        // Fisher-Yates shuffle with seed based on length (the 7 and 3 are that fixed seed)
        for (let i = len - 1; i > 0; i--) {
            const j = (i * 7 + 3) % (i + 1);
            [this.revealOrder[i], this.revealOrder[j]] = [this.revealOrder[j], this.revealOrder[i]];
        }
    }

    handleMouseMove(e) {
        if (!this.eyeIcon || !this.accountNumberInput || this.held) return;
        
        // Only activate when login container is visible
        const loginContainer = document.getElementById('loginContainer');
        if (!loginContainer || loginContainer.style.display === 'none') return;
        
        // Calculate mouse speed
        const now = Date.now();
        const timeDelta = now - this.lastMouseTime;
        if (timeDelta > 0) {
            const dx = e.clientX - this.lastMousePos.x;
            const dy = e.clientY - this.lastMousePos.y;
            const distance = Math.sqrt(dx * dx + dy * dy);
            this.mouseSpeed = Math.min(distance / timeDelta * EYE_MOUSE_SPEED_SCALE, EYE_MAX_MOUSE_SPEED);
        }
        this.lastMousePos = { x: e.clientX, y: e.clientY };
        this.lastMouseTime = now;
        
        // Get eye icon center
        const rect = this.eyeIcon.getBoundingClientRect();
        const eyeCenterX = rect.left + rect.width / 2;
        const eyeCenterY = rect.top + rect.height / 2;
        
        // Calculate distance from mouse to eye center
        const distX = e.clientX - eyeCenterX;
        const distY = e.clientY - eyeCenterY;
        const distanceToEye = Math.sqrt(distX * distX + distY * distY);
        
        // Determine zone
        let newZone = 'none';
        if (distanceToEye <= this.zones.inner) {
            newZone = 'inner';
        } else if (distanceToEye <= this.zones.middle) {
            newZone = 'middle';
        } else if (distanceToEye <= this.zones.outer) {
            newZone = 'outer';
        }
        
        // Update zone
        if (newZone !== this.currentZone) {
            this.currentZone = newZone;
            this.updateEyeStyle();
            
            if (newZone === 'none') {
                this.stopAnimation();
                this.resetToMasked();
            } else {
                this.startAnimation();
            }
        }
    }

    updateEyeStyle() {
        this.eyeIcon.className = 'eye-icon';
        if (this.currentZone !== 'none') {
            this.eyeIcon.classList.add(`zone-${this.currentZone}`);
        }
    }

    startAnimation() {
        if (this.animationFrame || this.held) return;
        this.originalValue = this.accountNumberInput.value;
        if (!this.originalValue) return;
        this.generateRevealOrder();
        this.animate();
    }

    stopAnimation() {
        if (this.animationFrame) {
            cancelAnimationFrame(this.animationFrame);
            this.animationFrame = null;
        }
    }

    animate() {
        if (!this.originalValue || this.currentZone === 'none') {
            this.resetToMasked();
            return;
        }
        
        // Calculate animation parameters based on zone
        let scrambleIntensity = 0;
        let revealDelta = 0;
        
        const motion = EYE_ZONE_MOTION[this.currentZone];
        switch (this.currentZone) {
            case 'outer':
                // Slow scramble, mouse speed responsive
                scrambleIntensity = motion.scramble + this.mouseSpeed * motion.perSpeed;
                revealDelta = motion.reveal; // Move away from reveal
                break;
                
            case 'middle':
                // Fast scramble (2x), more intense
                scrambleIntensity = motion.scramble + this.mouseSpeed * motion.perSpeed;
                revealDelta = motion.reveal; // Slight progress
                break;
                
            case 'inner':
                // Slow down and reveal smoothly
                scrambleIntensity = Math.max(0, motion.scramble - this.revealProgress * motion.perReveal);
                revealDelta = motion.reveal; // Move toward full reveal
                break;
        }
        
        // Update reveal progress
        this.revealProgress = Math.max(0, Math.min(1, this.revealProgress + revealDelta));
        
        // Generate display value
        this.displayValue = this.generateDisplayValue(scrambleIntensity);
        
        // Show as text and update display
        this.accountNumberInput.type = 'text';
        this.accountNumberInput.value = this.displayValue;
        
        // Continue animation
        this.animationFrame = requestAnimationFrame(() => this.animate());
    }

    generateDisplayValue(scrambleIntensity) {
        const len = this.originalValue.length;
        let result = new Array(len);
        
        // Calculate how many characters should be revealed based on progress
        const revealCount = Math.floor(this.revealProgress * len);
        
        for (let i = 0; i < len; i++) {
            // Check if this character position is in the revealed set
            const revealIndex = this.revealOrder.indexOf(i);
            const isRevealed = revealIndex < revealCount;
            
            if (isRevealed) {
                // Show real character
                result[i] = this.originalValue[i];
            } else if (Math.random() < scrambleIntensity) {
                // Scramble with random character
                result[i] = this.characters[Math.floor(Math.random() * this.characters.length)];
            } else {
                // Keep previous display value or show random
                result[i] = this.displayValue?.[i] || 
                           this.characters[Math.floor(Math.random() * this.characters.length)];
            }
        }
        
        return result.join('');
    }

    resetToMasked() {
        this.revealProgress = 0;
        this.accountNumberInput.type = 'password';
        this.accountNumberInput.value = this.originalValue;
        this.displayValue = '';
    }

    // A login reads the number (auth.js takeLoginNumber): the effect stops and draws nothing more
    // until release(); the field goes back to type=password before its value is set, in this same
    // task, so no frame ever shows a character of the number in clear. Returns the number as typed
    // (this animation's copy while it was drawing, else the field's own value).
    holdMasked() {
        this.held = true;
        this.stopAnimation();
        const typed = this.currentZone !== 'none' ? this.originalValue : this.accountNumberInput.value;
        this.currentZone = 'none';
        if (this.eyeIcon) this.updateEyeStyle();
        this.originalValue = typed;
        this.resetToMasked();
        return typed;
    }

    // The login has ended: hovering may draw again
    release() {
        this.held = false;
    }

    // Drops what was typed: the field and this animation's copy of it (leaving login, logging
    // in or out). The field stays masked.
    forget() {
        this.stopAnimation();
        this.currentZone = 'none';
        this.originalValue = '';
        this.resetToMasked();
    }

    destroy() {
        this.stopAnimation();
        if (this.boundHandleMouseMove) {
            document.removeEventListener('mousemove', this.boundHandleMouseMove);
            this.boundHandleMouseMove = null;
        }
    }
}

// Initialize
let eyeAnimation = null;

function initEyeAnimation() {
    const accountNumberInput = document.getElementById('accountNumberInput');
    const eyeIcon = document.getElementById('eyeIcon');
    
    // Destroy existing animation if it exists
    if (eyeAnimation) {
        eyeAnimation.destroy();
        eyeAnimation = null;
    }
    
    if (accountNumberInput && eyeIcon) {
        eyeAnimation = new EyeHoverAnimation();
        // Make eyeAnimation globally accessible for login function
        window.eyeAnimation = eyeAnimation;
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initEyeAnimation);
} else {
    initEyeAnimation();
}

window.addEventListener('beforeunload', () => {
    if (eyeAnimation) eyeAnimation.destroy();
});

// Make initEyeAnimation globally accessible
window.initEyeAnimation = initEyeAnimation;
