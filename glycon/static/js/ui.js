/**
 * Glycon C2 - Tactical UI Engine (100% Local Vanilla ES6+, Zero CDN)
 * Provides Modals, Promise-based Confirm/Prompt Dialogs, Toasts, Tabs, and Image Lightbox.
 */
(function () {
    'use strict';

    function escapeHtml(unsafe) {
        if (unsafe === null || unsafe === undefined) return '';
        return String(unsafe)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // SVG Icons for JS components
    const ICONS = {
        success: '<svg class="w-5 h-5 text-emerald-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>',
        danger: '<svg class="w-5 h-5 text-rose-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z"/></svg>',
        warning: '<svg class="w-5 h-5 text-amber-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/></svg>',
        info: '<svg class="w-5 h-5 text-cyan-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z"/></svg>',
        close: '<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>'
    };

    // -------------------------------------------------------------------------
    // 1. Toast Notification System
    // -------------------------------------------------------------------------
    function ensureToastContainer() {
        let container = document.getElementById('glycon-toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'glycon-toast-container';
            container.className = 'fixed bottom-5 right-5 z-[100] flex flex-col gap-2.5 max-w-sm w-full pointer-events-none';
            document.body.appendChild(container);
        }
        return container;
    }

    function toast(title, message = '', type = 'info', duration = 4500) {
        // Normalize arguments if called as toast(message, type)
        if (!message && ['success', 'danger', 'error', 'warning', 'info'].includes(type)) {
            message = title;
            title = type === 'danger' || type === 'error' ? 'Error' : type.charAt(0).toUpperCase() + type.slice(1);
        }

        const normType = (type === 'error' || type === 'danger') ? 'danger'
            : (type === 'success') ? 'success'
            : (type === 'warning') ? 'warning'
            : 'info';

        const borderColors = {
            success: 'border-emerald-500/50 bg-slate-900/95 shadow-emerald-950/30',
            danger: 'border-rose-500/50 bg-slate-900/95 shadow-rose-950/30',
            warning: 'border-amber-500/50 bg-slate-900/95 shadow-amber-950/30',
            info: 'border-cyan-500/50 bg-slate-900/95 shadow-cyan-950/30'
        };

        const container = ensureToastContainer();
        const el = document.createElement('div');
        el.className = `pointer-events-auto flex items-start gap-3 p-4 rounded-xl border ${borderColors[normType]} backdrop-blur-md shadow-xl text-slate-100 transition-all duration-200 opacity-0 translate-y-2`;
        el.setAttribute('role', 'alert');

        el.innerHTML = `
            ${ICONS[normType]}
            <div class="flex-1 min-w-0">
                <p class="text-xs font-semibold uppercase tracking-wider text-slate-200">${escapeHtml(title)}</p>
                ${message ? `<p class="text-sm text-slate-300 mt-0.5 break-words">${escapeHtml(message)}</p>` : ''}
            </div>
            <button type="button" class="text-slate-400 hover:text-slate-100 p-1 rounded-lg hover:bg-slate-800/80 transition-colors" aria-label="Close">
                ${ICONS.close}
            </button>
        `;

        const closeBtn = el.querySelector('button');
        const removeToast = () => {
            el.classList.add('opacity-0', 'translate-y-2');
            setTimeout(() => el.remove(), 200);
        };
        closeBtn.addEventListener('click', removeToast);

        container.appendChild(el);
        requestAnimationFrame(() => {
            el.classList.remove('opacity-0', 'translate-y-2');
        });

        if (duration > 0) {
            setTimeout(removeToast, duration);
        }
    }

    // -------------------------------------------------------------------------
    // 2. Modal System
    // -------------------------------------------------------------------------
    function resolveModal(modalIdOrEl) {
        if (!modalIdOrEl) return null;
        if (typeof modalIdOrEl === 'string') {
            const cleanId = modalIdOrEl.startsWith('#') ? modalIdOrEl.slice(1) : modalIdOrEl;
            return document.getElementById(cleanId);
        }
        return modalIdOrEl;
    }

    function openModal(modalIdOrEl, triggerEl = null) {
        const modal = resolveModal(modalIdOrEl);
        if (!modal) return;

        modal.classList.remove('hidden');
        modal.classList.add('flex');
        modal.setAttribute('aria-hidden', 'false');

        // Dispatch custom events for dynamic modal listeners (e.g. shellcode outputs & system info)
        const showEvent = new CustomEvent('glycon:modal-show', {
            bubbles: true,
            detail: { relatedTarget: triggerEl }
        });
        showEvent.relatedTarget = triggerEl;
        modal.dispatchEvent(showEvent);

        const bsCompatEvent = new CustomEvent('show.bs.modal', { bubbles: true });
        bsCompatEvent.relatedTarget = triggerEl;
        modal.dispatchEvent(bsCompatEvent);

        // Focus first input if present
        setTimeout(() => {
            const firstInput = modal.querySelector('input:not([type="hidden"]):not([readonly]), select, textarea');
            if (firstInput) firstInput.focus();
        }, 50);
    }

    function closeModal(modalIdOrEl) {
        const modal = resolveModal(modalIdOrEl);
        if (!modal) return;

        modal.classList.add('hidden');
        modal.classList.remove('flex');
        modal.setAttribute('aria-hidden', 'true');

        const hideEvent = new CustomEvent('hidden.bs.modal', { bubbles: true });
        modal.dispatchEvent(hideEvent);
    }

    // -------------------------------------------------------------------------
    // 3. Promise-based Confirm & Prompt Dialogs (Replaces native confirm/prompt)
    // -------------------------------------------------------------------------
    let activeDialogResolver = null;

    function ensureDialogModal() {
        let modal = document.getElementById('glycon-dialog-modal');
        if (modal) return modal;

        modal = document.createElement('div');
        modal.id = 'glycon-dialog-modal';
        modal.className = 'fixed inset-0 z-[95] hidden items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm';
        modal.innerHTML = `
            <div class="bg-slate-900 border border-slate-800 rounded-xl shadow-2xl max-w-md w-full overflow-hidden animate-in fade-in zoom-in-95 duration-150">
                <div class="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
                    <h3 id="glycon-dialog-title" class="text-base font-semibold text-slate-100">Confirm Action</h3>
                    <button type="button" id="glycon-dialog-x" class="text-slate-400 hover:text-slate-200 p-1 rounded-lg hover:bg-slate-800">
                        ${ICONS.close}
                    </button>
                </div>
                <form id="glycon-dialog-form">
                    <div class="p-5 space-y-4">
                        <p id="glycon-dialog-message" class="text-sm text-slate-300 whitespace-pre-line leading-relaxed"></p>
                        <div id="glycon-dialog-input-wrap" class="hidden space-y-1.5">
                            <label id="glycon-dialog-label" for="glycon-dialog-input" class="block text-xs font-medium uppercase tracking-wider text-slate-400"></label>
                            <input id="glycon-dialog-input" type="text" class="tactical-input font-mono" autocomplete="off">
                        </div>
                    </div>
                    <div class="px-5 py-3.5 bg-slate-950/60 border-t border-slate-800 flex items-center justify-end gap-2.5">
                        <button type="button" id="glycon-dialog-cancel" class="tactical-btn-secondary">Cancel</button>
                        <button type="submit" id="glycon-dialog-confirm" class="tactical-btn-primary">Confirm</button>
                    </div>
                </form>
            </div>
        `;
        document.body.appendChild(modal);
        return modal;
    }

    function confirmDialog(options = {}) {
        if (typeof options === 'string') {
            options = { message: options };
        }
        const {
            title = 'Confirm Operation',
            message = 'Are you sure you want to proceed?',
            confirmText = 'Confirm',
            cancelText = 'Cancel',
            variant = 'danger'
        } = options;

        return new Promise((resolve) => {
            const modal = ensureDialogModal();
            const titleEl = document.getElementById('glycon-dialog-title');
            const msgEl = document.getElementById('glycon-dialog-message');
            const inputWrap = document.getElementById('glycon-dialog-input-wrap');
            const confirmBtn = document.getElementById('glycon-dialog-confirm');
            const cancelBtn = document.getElementById('glycon-dialog-cancel');
            const closeX = document.getElementById('glycon-dialog-x');
            const form = document.getElementById('glycon-dialog-form');

            titleEl.textContent = title;
            msgEl.textContent = message;
            msgEl.classList.toggle('hidden', !message);
            inputWrap.classList.add('hidden');
            confirmBtn.textContent = confirmText;
            cancelBtn.textContent = cancelText;

            confirmBtn.className = variant === 'danger'
                ? 'tactical-btn-danger'
                : variant === 'warning'
                ? 'tactical-btn-warning'
                : 'tactical-btn-primary';

            const cleanup = (result) => {
                modal.classList.add('hidden');
                modal.classList.remove('flex');
                form.onsubmit = null;
                cancelBtn.onclick = null;
                closeX.onclick = null;
                activeDialogResolver = null;
                resolve(result);
            };

            activeDialogResolver = () => cleanup(false);
            form.onsubmit = (e) => {
                e.preventDefault();
                cleanup(true);
            };
            cancelBtn.onclick = () => cleanup(false);
            closeX.onclick = () => cleanup(false);

            modal.classList.remove('hidden');
            modal.classList.add('flex');
            setTimeout(() => confirmBtn.focus(), 30);
        });
    }

    function promptDialog(options = {}) {
        if (typeof options === 'string') {
            options = { title: options };
        }
        const {
            title = 'Input Required',
            message = '',
            label = 'Value',
            placeholder = '',
            defaultValue = '',
            confirmText = 'Execute',
            cancelText = 'Cancel',
            inputType = 'text'
        } = options;

        return new Promise((resolve) => {
            const modal = ensureDialogModal();
            const titleEl = document.getElementById('glycon-dialog-title');
            const msgEl = document.getElementById('glycon-dialog-message');
            const inputWrap = document.getElementById('glycon-dialog-input-wrap');
            const labelEl = document.getElementById('glycon-dialog-label');
            const inputEl = document.getElementById('glycon-dialog-input');
            const confirmBtn = document.getElementById('glycon-dialog-confirm');
            const cancelBtn = document.getElementById('glycon-dialog-cancel');
            const closeX = document.getElementById('glycon-dialog-x');
            const form = document.getElementById('glycon-dialog-form');

            titleEl.textContent = title;
            msgEl.textContent = message;
            msgEl.classList.toggle('hidden', !message);

            inputWrap.classList.remove('hidden');
            labelEl.textContent = label;
            inputEl.type = inputType;
            inputEl.placeholder = placeholder;
            inputEl.value = defaultValue;

            confirmBtn.textContent = confirmText;
            confirmBtn.className = 'tactical-btn-primary';
            cancelBtn.textContent = cancelText;

            const cleanup = (value) => {
                modal.classList.add('hidden');
                modal.classList.remove('flex');
                form.onsubmit = null;
                cancelBtn.onclick = null;
                closeX.onclick = null;
                activeDialogResolver = null;
                resolve(value);
            };

            activeDialogResolver = () => cleanup(null);
            form.onsubmit = (e) => {
                e.preventDefault();
                cleanup(inputEl.value);
            };
            cancelBtn.onclick = () => cleanup(null);
            closeX.onclick = () => cleanup(null);

            modal.classList.remove('hidden');
            modal.classList.add('flex');
            setTimeout(() => {
                inputEl.focus();
                inputEl.select();
            }, 30);
        });
    }

    // -------------------------------------------------------------------------
    // 4. Built-in Image Lightbox (Zero jQuery / Zero CDN)
    // -------------------------------------------------------------------------
    let lightboxItems = [];
    let lightboxIndex = 0;

    function ensureLightbox() {
        let lb = document.getElementById('glycon-lightbox');
        if (lb) return lb;

        lb = document.createElement('div');
        lb.id = 'glycon-lightbox';
        lb.className = 'fixed inset-0 z-[98] hidden items-center justify-center bg-slate-950/90 backdrop-blur-md p-4 select-none';
        lb.innerHTML = `
            <button type="button" id="glycon-lb-close" class="absolute top-4 right-4 z-10 p-2.5 rounded-full bg-slate-900/90 text-slate-300 hover:text-white border border-slate-700/80 hover:bg-slate-800 transition-colors" aria-label="Close preview">
                <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
            <button type="button" id="glycon-lb-prev" class="absolute left-4 top-1/2 -translate-y-1/2 z-10 p-3 rounded-full bg-slate-900/90 text-slate-300 hover:text-white border border-slate-700/80 hover:bg-slate-800 transition-colors" aria-label="Previous image">
                <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 19.5L8.25 12l7.5-7.5"/></svg>
            </button>
            <button type="button" id="glycon-lb-next" class="absolute right-4 top-1/2 -translate-y-1/2 z-10 p-3 rounded-full bg-slate-900/90 text-slate-300 hover:text-white border border-slate-700/80 hover:bg-slate-800 transition-colors" aria-label="Next image">
                <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5"/></svg>
            </button>
            <div class="max-w-6xl max-h-[90vh] flex flex-col items-center gap-3">
                <img id="glycon-lb-img" src="" alt="Preview" class="max-h-[82vh] max-w-full object-contain rounded-xl border border-slate-800 shadow-2xl bg-slate-900">
                <div id="glycon-lb-caption" class="text-xs font-mono text-slate-300 bg-slate-900/90 px-3.5 py-1.5 rounded-full border border-slate-800"></div>
            </div>
        `;
        document.body.appendChild(lb);

        document.getElementById('glycon-lb-close').addEventListener('click', closeLightbox);
        document.getElementById('glycon-lb-prev').addEventListener('click', (e) => {
            e.stopPropagation();
            stepLightbox(-1);
        });
        document.getElementById('glycon-lb-next').addEventListener('click', (e) => {
            e.stopPropagation();
            stepLightbox(1);
        });
        lb.addEventListener('click', (e) => {
            if (e.target === lb) closeLightbox();
        });

        return lb;
    }

    function updateLightboxView() {
        const item = lightboxItems[lightboxIndex];
        if (!item) return;
        const img = document.getElementById('glycon-lb-img');
        const cap = document.getElementById('glycon-lb-caption');
        const prevBtn = document.getElementById('glycon-lb-prev');
        const nextBtn = document.getElementById('glycon-lb-next');

        img.src = item.src;
        const countLabel = lightboxItems.length > 1 ? ` (${lightboxIndex + 1} / ${lightboxItems.length})` : '';
        cap.textContent = (item.caption || 'Capture Preview') + countLabel;

        prevBtn.classList.toggle('hidden', lightboxItems.length <= 1);
        nextBtn.classList.toggle('hidden', lightboxItems.length <= 1);
    }

    function openLightbox(src, caption = '', group = null) {
        const lb = ensureLightbox();
        if (group) {
            const links = Array.from(document.querySelectorAll(`a[data-lightbox="${group}"]`));
            lightboxItems = links.map(a => ({
                src: a.getAttribute('href'),
                caption: a.getAttribute('data-title') || a.closest('.screenshot-card, .webcam-card, div')?.querySelector('p, .caption')?.textContent?.trim() || ''
            }));
            lightboxIndex = Math.max(0, lightboxItems.findIndex(i => i.src === src));
        } else {
            lightboxItems = [{ src, caption }];
            lightboxIndex = 0;
        }
        updateLightboxView();
        lb.classList.remove('hidden');
        lb.classList.add('flex');
    }

    function stepLightbox(delta) {
        if (lightboxItems.length <= 1) return;
        lightboxIndex = (lightboxIndex + delta + lightboxItems.length) % lightboxItems.length;
        updateLightboxView();
    }

    function closeLightbox() {
        const lb = document.getElementById('glycon-lightbox');
        if (lb) {
            lb.classList.add('hidden');
            lb.classList.remove('flex');
        }
    }

    // -------------------------------------------------------------------------
    // 5. Global Event Delegation (Modals, Tabs, Lightbox, Escape key)
    // -------------------------------------------------------------------------
    document.addEventListener('click', function (e) {
        // Lightbox trigger
        const lbLink = e.target.closest('a[data-lightbox]');
        if (lbLink) {
            e.preventDefault();
            openLightbox(
                lbLink.getAttribute('href'),
                lbLink.getAttribute('data-title') || '',
                lbLink.getAttribute('data-lightbox')
            );
            return;
        }

        // Open modal trigger
        const modalTrigger = e.target.closest('[data-modal-target], [data-bs-toggle="modal"]');
        if (modalTrigger) {
            e.preventDefault();
            const targetId = modalTrigger.getAttribute('data-modal-target') || modalTrigger.getAttribute('data-bs-target');
            openModal(targetId, modalTrigger);
            return;
        }

        // Close modal trigger
        const modalClose = e.target.closest('[data-modal-close], [data-bs-dismiss="modal"]');
        if (modalClose) {
            e.preventDefault();
            const parentModal = modalClose.closest('.glycon-modal, .modal');
            if (parentModal) closeModal(parentModal);
            return;
        }

        // Click on modal backdrop
        if (e.target.classList.contains('glycon-modal')) {
            closeModal(e.target);
            return;
        }

        // Tab trigger
        const tabBtn = e.target.closest('[data-tab-target], [data-bs-toggle="tab"]');
        if (tabBtn) {
            e.preventDefault();
            const targetSelector = tabBtn.getAttribute('data-tab-target') || tabBtn.getAttribute('data-bs-target');
            const tabList = tabBtn.closest('[role="tablist"]');
            if (tabList) {
                tabList.querySelectorAll('[role="tab"]').forEach(btn => {
                    const isActive = btn === tabBtn;
                    btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
                    btn.classList.toggle('bg-emerald-500/15', isActive);
                    btn.classList.toggle('text-emerald-400', isActive);
                    btn.classList.toggle('border-emerald-500/50', isActive);
                    btn.classList.toggle('text-slate-400', !isActive);
                    btn.classList.toggle('border-transparent', !isActive);
                });
            }
            const targetPane = resolveModal(targetSelector);
            if (targetPane && targetPane.parentElement) {
                Array.from(targetPane.parentElement.children).forEach(pane => {
                    if (pane === targetPane) {
                        pane.classList.remove('hidden');
                        pane.classList.add('block');
                    } else if (pane.getAttribute('role') === 'tabpanel' || pane.classList.contains('tab-pane')) {
                        pane.classList.add('hidden');
                        pane.classList.remove('block');
                    }
                });
            }
            return;
        }
    });

    document.addEventListener('keydown', function (e) {
        const lb = document.getElementById('glycon-lightbox');
        const lbOpen = lb && !lb.classList.contains('hidden');
        if (lbOpen) {
            if (e.key === 'Escape') closeLightbox();
            if (e.key === 'ArrowLeft') stepLightbox(-1);
            if (e.key === 'ArrowRight') stepLightbox(1);
            return;
        }

        if (e.key === 'Escape') {
            if (activeDialogResolver) {
                activeDialogResolver();
                return;
            }
            const openModals = document.querySelectorAll('.glycon-modal:not(.hidden)');
            if (openModals.length > 0) {
                closeModal(openModals[openModals.length - 1]);
            }
        }
    });

    // Expose GlyconUI globally
    window.GlyconUI = {
        escapeHtml,
        toast,
        confirm: confirmDialog,
        prompt: promptDialog,
        openModal,
        closeModal,
        openLightbox,
        closeLightbox
    };

    // Backward-compatible shims for existing scripts
    window.showToast = function (title, message, type) {
        GlyconUI.toast(title, message, type);
    };
    window.showNotification = function (message, type) {
        GlyconUI.toast('Notification', message, type);
    };
    window.bootstrap = {
        Modal: class {
            constructor(el) { this.el = el; }
            show() { GlyconUI.openModal(this.el); }
            hide() { GlyconUI.closeModal(this.el); }
            static getInstance(el) { return new window.bootstrap.Modal(el); }
        },
        Toast: class {
            constructor(el) { this.el = el; }
            show() {}
        },
        Tooltip: class {
            constructor() {}
        }
    };
})();
