(function () {
    'use strict';

    const initializedForms = new WeakSet();

    function text(root, key, fallback) {
        return root.dataset[key] || fallback;
    }

    function setState(root, state, message) {
        const status = root.querySelector('[data-altcha-status]');
        const messageNode = root.querySelector('[data-altcha-message]');
        if (!status || !messageNode) {
            return;
        }

        root.dataset.state = state;
        status.hidden = state === 'idle';
        messageNode.textContent = message || '';
    }

    function encodeBase64Json(value) {
        const json = JSON.stringify(value);
        const bytes = new TextEncoder().encode(json);
        let binary = '';
        const chunkSize = 0x8000;
        for (let offset = 0; offset < bytes.length; offset += chunkSize) {
            binary += String.fromCharCode.apply(null, bytes.subarray(offset, offset + chunkSize));
        }
        return btoa(binary);
    }

    async function fetchChallenge(root) {
        const response = await fetch(root.dataset.challengeUrl, {
            method: 'GET',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: {
                Accept: 'application/json',
            },
        });

        if (response.status === 429) {
            const error = new Error('rate-limited');
            error.code = 'rate-limited';
            throw error;
        }

        if (!response.ok) {
            throw new Error('Unable to load ALTCHA challenge.');
        }

        const challenge = await response.json();
        if (!challenge || !challenge.parameters || !challenge.signature) {
            throw new Error('Invalid ALTCHA challenge response.');
        }

        return challenge;
    }

    function solveChallenge(root, challenge) {
        return new Promise((resolve, reject) => {
            if (!window.crypto || !window.crypto.subtle || typeof Worker === 'undefined') {
                reject(new Error('This browser does not support the required cryptography.'));
                return;
            }

            const workerUrl = root.dataset.workerUrl;
            if (!workerUrl) {
                reject(new Error('ALTCHA worker URL is missing.'));
                return;
            }

            // ALTCHA's official PBKDF2 worker supports splitting the deterministic
            // counter search between workers with counterStart/counterStep.
            const concurrency = Math.max(
                1,
                Math.min(4, Number(navigator.hardwareConcurrency) || 2)
            );
            const workers = [];
            let settled = false;
            let completedWithoutSolution = 0;

            function cleanup() {
                for (const worker of workers) {
                    try {
                        worker.postMessage({type: 'abort'});
                    } catch (error) {
                        // Ignore abort failures; terminate below is authoritative.
                    }
                    worker.terminate();
                }
            }

            function fail(error) {
                if (settled) {
                    return;
                }
                settled = true;
                cleanup();
                reject(error instanceof Error ? error : new Error(String(error)));
            }

            for (let index = 0; index < concurrency; index += 1) {
                let worker;
                try {
                    worker = new Worker(workerUrl);
                } catch (error) {
                    fail(error);
                    return;
                }

                workers.push(worker);
                worker.addEventListener('message', (event) => {
                    if (settled) {
                        return;
                    }

                    const data = event.data;
                    if (data && data.error) {
                        const message = data.error.message || data.error || 'ALTCHA solver failed.';
                        fail(new Error(String(message)));
                        return;
                    }

                    if (data && Number.isInteger(data.counter) && typeof data.derivedKey === 'string') {
                        settled = true;
                        cleanup();
                        resolve(data);
                        return;
                    }

                    // The official worker returns null when it reaches its timeout.
                    if (data === null) {
                        completedWithoutSolution += 1;
                        if (completedWithoutSolution >= concurrency) {
                            fail(new Error('ALTCHA solving timed out.'));
                        }
                    }
                });
                worker.addEventListener('error', (event) => {
                    fail(new Error(event.message || 'ALTCHA worker failed.'));
                });

                worker.postMessage({
                    type: 'work',
                    challenge,
                    counterMode: 'uint32',
                    counterStart: index,
                    counterStep: concurrency,
                    timeout: 20000,
                });
            }

            window.setTimeout(() => {
                fail(new Error('ALTCHA solving timed out.'));
            }, 22000);
        });
    }

    function requestOriginalSubmit(form, submitter) {
        if (typeof form.requestSubmit === 'function') {
            if (submitter && submitter.form === form && !submitter.disabled) {
                form.requestSubmit(submitter);
            } else {
                form.requestSubmit();
            }
            return;
        }

        // Legacy fallback. Modern browsers with Web Crypto have requestSubmit,
        // but keep this for defensive compatibility.
        HTMLFormElement.prototype.submit.call(form);
    }

    function initialize(root) {
        if (!(root instanceof HTMLElement) || root.dataset.altchaInitialized === '1') {
            return;
        }
        root.dataset.altchaInitialized = '1';

        const form = root.closest('form');
        const payloadInput = root.querySelector('[data-altcha-payload]');
        if (!form || !payloadInput || initializedForms.has(form)) {
            return;
        }
        initializedForms.add(form);

        let solutionPromise = null;
        let solutionExpiresAt = 0;
        let verified = false;

        function hasFreshSolution() {
            const now = Math.floor(Date.now() / 1000);
            return verified
                && Boolean(payloadInput.value)
                && solutionExpiresAt > now + 10;
        }

        function resetSolution() {
            payloadInput.value = '';
            solutionExpiresAt = 0;
            verified = false;
        }

        async function prepareSolution() {
            if (hasFreshSolution()) {
                return true;
            }

            if (solutionPromise) {
                return solutionPromise;
            }

            resetSolution();
            solutionPromise = (async () => {
                const challenge = await fetchChallenge(root);
                const solution = await solveChallenge(root, challenge);
                const expiresAt = Number(challenge?.parameters?.expiresAt || 0);
                if (!Number.isFinite(expiresAt) || expiresAt <= Math.floor(Date.now() / 1000)) {
                    throw new Error('ALTCHA challenge expired before it was solved.');
                }

                payloadInput.value = encodeBase64Json({challenge, solution});
                solutionExpiresAt = expiresAt;
                verified = true;
                return true;
            })();

            try {
                return await solutionPromise;
            } finally {
                solutionPromise = null;
            }
        }

        // Start the CPU work after the visitor actually interacts with the form.
        // This keeps page load quiet, but hides most proof-of-work latency behind
        // the time a human naturally spends filling out the form.
        const prewarm = () => {
            if (hasFreshSolution() || solutionPromise) {
                return;
            }
            prepareSolution().catch(() => {
                // Background preparation is best-effort. A visible retry happens
                // on submit, where errors can be communicated to the visitor.
                resetSolution();
            });
        };
        form.addEventListener('focusin', prewarm, {passive: true});
        form.addEventListener('input', prewarm, {passive: true});

        form.addEventListener('submit', async (event) => {
            if (hasFreshSolution()) {
                return;
            }

            event.preventDefault();
            event.stopImmediatePropagation();

            const submitter = event.submitter || null;
            if (submitter) {
                submitter.disabled = true;
            }

            setState(root, 'verifying', text(root, 'textVerifying', 'Security check…'));

            try {
                await prepareSolution();
                setState(root, 'verified', text(root, 'textVerified', 'Verified'));

                if (submitter) {
                    submitter.disabled = false;
                }

                // Let the success state paint once, then continue the original
                // form submission without requiring another click.
                window.requestAnimationFrame(() => requestOriginalSubmit(form, submitter));
            } catch (error) {
                resetSolution();
                if (submitter) {
                    submitter.disabled = false;
                }

                const isRateLimited = error && error.code === 'rate-limited';
                setState(
                    root,
                    'error',
                    isRateLimited
                        ? text(root, 'textRateLimited', 'Too many verification attempts. Please try again later.')
                        : text(root, 'textError', 'Verification failed. Please try again.')
                );
            }
        }, true);
    }

    function scan(scope) {
        if (scope instanceof Element && scope.matches('[data-altcha-captcha]')) {
            initialize(scope);
        }
        const nodes = scope.querySelectorAll ? scope.querySelectorAll('[data-altcha-captcha]') : [];
        nodes.forEach(initialize);
    }

    function start() {
        scan(document);

        if (typeof MutationObserver !== 'undefined') {
            const observer = new MutationObserver((mutations) => {
                for (const mutation of mutations) {
                    for (const node of mutation.addedNodes) {
                        if (node instanceof Element) {
                            scan(node);
                        }
                    }
                }
            });
            observer.observe(document.documentElement, {childList: true, subtree: true});
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start, {once: true});
    } else {
        start();
    }
})();
