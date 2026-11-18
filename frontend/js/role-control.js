// ========================================
// ROLE CONTROL (members panel and message bubbles)
// ========================================
// How a room member's role is shown and changed in the page (docs/architecture/rooms.md, Member
// roles). A role is other members' data: always inserted as text, always after a '#', and drawn
// unlike the built-in `you` and `owner` badges (those are framed; a role is plain italic text),
// so a role never passes for one; the words themselves are reserved (validation.js). A role
// proves nothing: only the built-in badge marks the owner.
//
// The control is offered only where it can be used (Rooms.mayEditRole): the owner for everyone,
// every member for itself. Typed text is checked as it is typed, with the reason shown inline;
// the request and its refusals live in save().

const RoleControl = (() => {
    'use strict';

    const ROLE_MARK = '#';
    const OPEN_LABEL = 'role';
    const SET_LABEL = 'set';
    const CLEAR_LABEL = 'clear';
    const CANCEL_LABEL = 'cancel';
    const OPEN_HINT = 'a short label shown beside this member to everyone in the room';
    const INPUT_LABEL = 'role';
    const ACTION = 'role';

    // The editor left open: { card, draft } (memory only), so a roster refresh while typing
    // keeps the editor and what was typed
    let editing = null;

    // '#role' as a plain text span, or null for no role
    function tag(role) {
        if (typeof role !== 'string' || role === '') return null;
        const span = document.createElement('span');
        span.className = 'member-role';
        span.textContent = ROLE_MARK + role;
        return span;
    }

    // Puts each bubble's role in line with the roster: roleByKey maps a sender's public key to
    // its role ('' or absent: none, a member who left has none)
    function markBubbles(roleByKey) {
        document.querySelectorAll('#messageList .msg-sender').forEach(sender => {
            const old = sender.querySelector('.member-role');
            if (old) old.remove();
            const fresh = tag(roleByKey.get(sender.dataset.sender));
            if (fresh) sender.querySelector('.aura-code').after(fresh);
        });
    }

    function button(text, onClick) {
        const element = document.createElement('button');
        element.className = 'menu-opt';
        element.textContent = text;
        element.addEventListener('click', onClick);
        return element;
    }

    // The control for one roster entry: null when this account may not change its role.
    // save(text) stores text ('' clears) and resolves once done; rerender redraws the panel.
    function control({ room, entry, save, rerender }) {
        if (!Rooms.mayEditRole(room, entry)) return null;
        if (editing && editing.card === entry.card) return editor({ entry, save, rerender });
        const open = button(OPEN_LABEL, () => {
            editing = { card: entry.card, draft: entry.role || '' };
            rerender();
            const field = document.querySelector('#memberList .role-input');
            if (field) field.focus();
        });
        open.title = OPEN_HINT;
        return open;
    }

    function editor({ entry, save, rerender }) {
        const box = document.createElement('div');
        box.className = 'role-editor';
        const mark = document.createElement('span');
        mark.className = 'member-role';
        mark.textContent = ROLE_MARK;
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'role-input';
        input.setAttribute('aria-label', INPUT_LABEL);
        input.autocomplete = 'off';
        input.spellcheck = false;
        input.value = editing.draft;
        const reason = document.createElement('span');
        reason.className = 'role-reason';
        reason.setAttribute('role', 'status');
        const set = button(SET_LABEL, () => submit(input.value));
        const judge = () => {
            editing.draft = input.value;
            const checked = validateRoleText(input.value);
            // Nothing typed yet is no fault to point at; set stays off until the text passes
            reason.textContent = checked.valid || input.value === '' ? '' : Errors.message(checked.error, checked.params);
            set.disabled = !checked.valid;
        };
        const submit = async (text) => {
            const checked = validateRoleText(text);
            if (text !== '' && !checked.valid) {
                Errors.inline(reason, checked.error, checked.params);
                return;
            }
            if (await save(checked.valid ? checked.value : '')) {
                editing = null;
                rerender();
            }
        };
        input.addEventListener('input', judge);
        input.addEventListener('keydown', event => {
            if (event.key === 'Enter' && !set.disabled) submit(input.value);
        });
        box.append(mark, input, set);
        if (entry.role) box.appendChild(button(CLEAR_LABEL, () => submit('')));
        box.append(button(CANCEL_LABEL, () => {
            editing = null;
            rerender();
        }), reason);
        judge();
        return box;
    }

    // Seals and stores text ('' clears) as entry's role; reports any refusal by its own code.
    // Resolves to whether the server stored it. One change at a time.
    async function save({ api, conv, entry, text }) {
        return (await once(ACTION, () => saveNow({ api, conv, entry, text }))) === true;
    }

    async function saveNow({ api, conv, entry, text }) {
        let result;
        try {
            result = await Rooms.setRole({ api, conv, entry, text });
        } catch (error) {
            Errors.report(Errors.CODES.E_ROLE_NOT_SET, null, error);
            return false;
        }
        if (result.ok) return true;
        if (result.status === HTTP_STATUS.FORBIDDEN) {
            Errors.report(Errors.CODES.E_ROLE_NOT_ALLOWED, null, result);
        } else if (result.status === HTTP_STATUS.NOT_FOUND) {
            Errors.report(Errors.CODES.W_ROLE_MEMBER_GONE, null, result);
        } else if (result.status === HTTP_STATUS.TOO_MANY_REQUESTS) {
            Errors.report(Errors.CODES.W_ROLE_RATE_LIMITED, null, result);
        } else if (result.status !== HTTP_STATUS.UNAUTHORIZED) {
            Errors.report(Errors.CODES.E_ROLE_NOT_SET, null, result);
        }
        return false;
    }

    // The session ended: no editor survives it
    function reset() {
        editing = null;
    }

    return Object.freeze({ tag, markBubbles, control, save, reset });
})();
