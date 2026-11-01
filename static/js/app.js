/**
 * app.js - UI Controller & REST API Integration
 * =============================================
 * Author: Password Security Internship Project
 * 
 * Handles DOM events, real-time input analysis, clipboard actions,
 * and asynchronous communication with the Flask/SQLite backend.
 */

document.addEventListener("DOMContentLoaded", () => {
    // Instantiate core analyzer engine
    const analyzer = new PasswordAnalyzer();

    // DOM Elements
    const passwordInput     = document.getElementById("passwordInput");
    const toggleVisibility  = document.getElementById("toggleVisibility");
    const clearInputBtn     = document.getElementById("clearInputBtn");
    const strengthBar       = document.getElementById("strengthBar");
    const strengthLabel     = document.getElementById("strengthLabel");
    const scoreBadge        = document.getElementById("scoreBadge");
    const entropyValue      = document.getElementById("entropyValue");
    const crackTimeValue    = document.getElementById("crackTimeValue");
    const combinationsValue = document.getElementById("combinationsValue");
    const charsetPoolValue  = document.getElementById("charsetPoolValue");
    const checklistContainer= document.getElementById("checklistContainer");
    const warningsContainer = document.getElementById("warningsContainer");
    const alternativesContainer = document.getElementById("alternativesContainer");
    const generateBtn       = document.getElementById("generateBtn");
    const generatedBox      = document.getElementById("generatedBox");
    const generatedPassword = document.getElementById("generatedPassword");
    const copyGeneratedBtn  = document.getElementById("copyGeneratedBtn");
    const fillGeneratedBtn  = document.getElementById("fillGeneratedBtn");
    
    // Database Feature DOM Elements
    const dbWarningBanner   = document.getElementById("dbWarningBanner");
    const saveToDbBtn       = document.getElementById("saveToDbBtn");
    const dbStatusMessage   = document.getElementById("dbStatusMessage");
    const refreshVaultBtn   = document.getElementById("refreshVaultBtn");
    const clearVaultBtn     = document.getElementById("clearVaultBtn");
    const vaultTableBody    = document.getElementById("vaultTableBody");
    const vaultCountBadge   = document.getElementById("vaultCountBadge");

    // Debounce timer for backend database check
    let dbCheckTimer = null;

    // ==========================================
    // 1. Password Visibility Toggle (Show / Hide)
    // ==========================================
    toggleVisibility.addEventListener("click", () => {
        const isPassword = passwordInput.type === "password";
        passwordInput.type = isPassword ? "text" : "password";
        
        // Update SVG icon and aria label
        const eyeIcon = toggleVisibility.querySelector(".eye-icon");
        const eyeSlashIcon = toggleVisibility.querySelector(".eye-slash-icon");
        const toggleText = toggleVisibility.querySelector(".toggle-text");

        if (isPassword) {
            eyeIcon.classList.add("hidden");
            eyeSlashIcon.classList.remove("hidden");
            toggleText.textContent = "Hide";
            toggleVisibility.setAttribute("title", "Hide password");
        } else {
            eyeIcon.classList.remove("hidden");
            eyeSlashIcon.classList.add("hidden");
            toggleText.textContent = "Show";
            toggleVisibility.setAttribute("title", "Show password");
        }
    });

    // Clear input button
    clearInputBtn.addEventListener("click", () => {
        passwordInput.value = "";
        passwordInput.focus();
        runAnalysis("");
    });

    // ==========================================
    // 2. Real-Time Typing Listener
    // ==========================================
    passwordInput.addEventListener("input", (e) => {
        const val = e.target.value;
        runAnalysis(val);

        // Debounce database duplicate check (350ms pause after typing)
        clearTimeout(dbCheckTimer);
        if (val.trim().length > 0) {
            dbCheckTimer = setTimeout(() => {
                checkPasswordInDatabase(val);
            }, 350);
        } else {
            hideDbWarning();
        }
    });

    /**
     * Executes the strength analysis and updates all UI elements in real time.
     */
    function runAnalysis(password) {
        const report = analyzer.analyze(password);

        // Update Clear button visibility
        if (password.length > 0) {
            clearInputBtn.classList.remove("hidden");
        } else {
            clearInputBtn.classList.add("hidden");
        }

        // 1. Update Strength Meter & Score
        updateStrengthMeter(report);

        // 2. Update Checklist
        renderChecklist(report.checklist);

        // 3. Update Warnings
        renderWarnings(report.warnings);

        // 4. Update Entropy & Crack Time Stats
        updateEntropyStats(report);

        // 5. Update Alternatives
        renderAlternatives(report.suggestions);
    }

    /**
     * Updates the color-coded strength bar and score badge.
     */
    function updateStrengthMeter(report) {
        const { score, strength } = report;
        
        // Update Meter Bar
        strengthBar.style.width = `${strength.percent}%`;
        strengthBar.style.backgroundColor = strength.color;
        
        // Update Label
        strengthLabel.textContent = strength.label;
        strengthLabel.style.color = strength.color;
        
        // Update Score Badge
        scoreBadge.textContent = `${score} / 100`;
        scoreBadge.style.borderColor = strength.color;
        scoreBadge.style.color = strength.color;

        // Dynamic 5-segment indicators
        const segments = document.querySelectorAll(".meter-segment");
        segments.forEach((seg, idx) => {
            if (idx < strength.step) {
                seg.style.backgroundColor = strength.color;
                seg.classList.add("active");
            } else {
                seg.style.backgroundColor = "#e2e8f0";
                seg.classList.remove("active");
            }
        });
    }

    /**
     * Renders the interactive checklist of passed / failed criteria.
     */
    function renderChecklist(checklist) {
        checklistContainer.innerHTML = "";

        checklist.forEach(item => {
            const li = document.createElement("div");
            li.className = `checklist-item ${item.passed ? "passed" : "failed"}`;

            const iconSpan = document.createElement("span");
            iconSpan.className = "check-icon";
            iconSpan.innerHTML = item.passed
                ? `<svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>`
                : `<svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>`;

            const labelSpan = document.createElement("span");
            labelSpan.className = "check-label";
            labelSpan.textContent = item.label;

            li.appendChild(iconSpan);
            li.appendChild(labelSpan);

            if (item.detail && !item.passed) {
                const detailBadge = document.createElement("span");
                detailBadge.className = "check-detail-tag";
                detailBadge.textContent = item.detail;
                li.appendChild(detailBadge);
            }

            checklistContainer.appendChild(li);
        });
    }

    /**
     * Renders warning alerts for detected patterns.
     */
    function renderWarnings(warnings) {
        warningsContainer.innerHTML = "";
        if (!warnings || warnings.length === 0) {
            warningsContainer.classList.add("hidden");
            return;
        }

        warningsContainer.classList.remove("hidden");
        warnings.forEach(w => {
            const warnEl = document.createElement("div");
            warnEl.className = "warning-chip";
            warnEl.textContent = w;
            warningsContainer.appendChild(warnEl);
        });
    }

    /**
     * Updates information entropy statistics and crack time calculations.
     */
    function updateEntropyStats(report) {
        entropyValue.textContent = `${report.entropy} bits`;
        crackTimeValue.textContent = report.crackTimeOffline;
        combinationsValue.textContent = report.combinations;
        charsetPoolValue.textContent = `${report.charsetPool} chars`;
    }

    /**
     * Renders the 3 dynamic improved password suggestions.
     */
    function renderAlternatives(suggestions) {
        alternativesContainer.innerHTML = "";

        if (!suggestions || suggestions.length === 0) {
            alternativesContainer.innerHTML = `
                <div class="empty-suggestions-state">
                    <p>Type a password above to see 3 tailored, stronger alternative mutations.</p>
                </div>
            `;
            return;
        }

        suggestions.forEach(alt => {
            const card = document.createElement("div");
            card.className = "suggestion-card";

            card.innerHTML = `
                <div class="suggestion-header">
                    <span class="suggestion-title">${alt.title}</span>
                    <span class="suggestion-desc">${alt.description}</span>
                </div>
                <div class="suggestion-body">
                    <code class="suggestion-code">${escapeHtml(alt.password)}</code>
                    <div class="suggestion-actions">
                        <button class="btn btn-sm btn-outline use-alt-btn" title="Use this password in analyzer">
                            Use This
                        </button>
                        <button class="btn btn-sm btn-primary copy-alt-btn" title="Copy to clipboard">
                            Copy
                        </button>
                    </div>
                </div>
            `;

            // Action: Use This
            const useBtn = card.querySelector(".use-alt-btn");
            useBtn.addEventListener("click", () => {
                passwordInput.value = alt.password;
                passwordInput.type = "text"; // show it so user sees the improvement
                toggleVisibility.querySelector(".eye-icon").classList.add("hidden");
                toggleVisibility.querySelector(".eye-slash-icon").classList.remove("hidden");
                toggleVisibility.querySelector(".toggle-text").textContent = "Hide";
                runAnalysis(alt.password);
                showToast("Applied alternative to input!");
            });

            // Action: Copy
            const copyBtn = card.querySelector(".copy-alt-btn");
            copyBtn.addEventListener("click", () => {
                copyToClipboard(alt.password, copyBtn);
            });

            alternativesContainer.appendChild(card);
        });
    }

    // ==========================================
    // 3. Cryptographically Secure Password Generator
    // ==========================================
    generateBtn.addEventListener("click", () => {
        const strongPass = analyzer.generateSecurePassword(16);
        generatedPassword.value = strongPass;
        generatedBox.classList.remove("hidden");
        showToast("Generated new 16-character secure password!");
    });

    copyGeneratedBtn.addEventListener("click", () => {
        if (generatedPassword.value) {
            copyToClipboard(generatedPassword.value, copyGeneratedBtn);
        }
    });

    fillGeneratedBtn.addEventListener("click", () => {
        if (generatedPassword.value) {
            passwordInput.value = generatedPassword.value;
            passwordInput.type = "text";
            toggleVisibility.querySelector(".eye-icon").classList.add("hidden");
            toggleVisibility.querySelector(".eye-slash-icon").classList.remove("hidden");
            toggleVisibility.querySelector(".toggle-text").textContent = "Hide";
            runAnalysis(generatedPassword.value);
            showToast("Secure password filled into input!");
        }
    });

    // ==========================================
    // 4. SQLite Database Integration (Optional Feature)
    // ==========================================

    /**
     * Queries backend to check if the candidate password was previously saved.
     */
    async function checkPasswordInDatabase(pwd) {
        if (!pwd || pwd.length === 0) return;

        try {
            const resp = await fetch("/api/check-db", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password: pwd })
            });

            if (!resp.ok) return;

            const data = await resp.json();
            if (data.is_used) {
                showDbWarning("🚨 This password was used before, choose a new one.");
            } else {
                hideDbWarning();
            }
        } catch (err) {
            // Backend offline or running purely frontend
            console.debug("Backend database endpoint not reachable:", err.message);
        }
    }

    function showDbWarning(msg) {
        dbWarningBanner.textContent = msg;
        dbWarningBanner.classList.remove("hidden");
    }

    function hideDbWarning() {
        dbWarningBanner.textContent = "";
        dbWarningBanner.classList.add("hidden");
    }

    /**
     * Handles saving the current password into the SQLite database.
     */
    saveToDbBtn.addEventListener("click", async () => {
        const val = passwordInput.value;
        if (!val || val.trim().length === 0) {
            showToast("Please enter a password before saving.", "error");
            return;
        }

        saveToDbBtn.disabled = true;
        saveToDbBtn.textContent = "Checking & Hashing...";

        try {
            const resp = await fetch("/api/save-password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    password: val,
                    label: "Internship Candidate Demo"
                })
            });

            const data = await resp.json();

            if (data.success) {
                showDbStatus(data.message, "success");
                showToast("Password hashed and saved in SQLite!", "success");
                hideDbWarning();
                // Refresh vault history table
                loadVaultHistory();
            } else {
                // Show clear required message
                showDbStatus(data.message, "error");
                showDbWarning(`🚨 ${data.message}`);
                showToast(data.message, "error");
            }
        } catch (err) {
            showDbStatus("Could not connect to Flask backend. Make sure app.py is running.", "error");
        } finally {
            saveToDbBtn.disabled = false;
            saveToDbBtn.textContent = "Save / Register Password to SQLite";
        }
    });

    function showDbStatus(msg, type) {
        dbStatusMessage.textContent = msg;
        dbStatusMessage.className = `status-msg ${type}`;
        dbStatusMessage.classList.remove("hidden");
        setTimeout(() => {
            dbStatusMessage.classList.add("hidden");
        }, 6000);
    }

    /**
     * Loads stored salts and hashes from the database to show in the UI inspector.
     */
    async function loadVaultHistory() {
        try {
            const resp = await fetch("/api/history");
            if (!resp.ok) return;

            const history = await resp.json();
            vaultCountBadge.textContent = `${history.length} stored`;

            vaultTableBody.innerHTML = "";
            if (history.length === 0) {
                vaultTableBody.innerHTML = `
                    <tr>
                        <td colspan="5" class="empty-table-msg">
                            No passwords stored in SQLite yet. Enter a password above and click "Save / Register Password".
                        </td>
                    </tr>
                `;
                return;
            }

            history.forEach(item => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td><strong>#${item.id}</strong></td>
                    <td><span class="crypto-tag salt-tag" title="${item.salt_full}">${item.salt_preview}</span></td>
                    <td><span class="crypto-tag hash-tag" title="${item.hash_full}">${item.hash_preview}</span></td>
                    <td><span class="badge-algo">${item.algorithm}</span></td>
                    <td class="text-muted">${item.created_at || 'Just now'}</td>
                `;
                vaultTableBody.appendChild(tr);
            });
        } catch (err) {
            console.debug("Could not load vault history:", err.message);
        }
    }

    refreshVaultBtn.addEventListener("click", loadVaultHistory);

    clearVaultBtn.addEventListener("click", async () => {
        if (!confirm("Are you sure you want to clear all stored hashes from the SQLite database?")) {
            return;
        }

        try {
            const resp = await fetch("/api/clear-db", { method: "POST" });
            const data = await resp.json();
            if (data.success) {
                showToast("SQLite vault cleared!", "info");
                hideDbWarning();
                loadVaultHistory();
            }
        } catch (err) {
            showToast("Failed to clear vault.", "error");
        }
    });

    // ==========================================
    // 5. Utilities (Clipboard & Toast Notifications)
    // ==========================================
    function copyToClipboard(text, buttonEl) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => {
                triggerButtonSuccess(buttonEl);
                showToast("Copied to clipboard!");
            }).catch(() => fallbackCopy(text, buttonEl));
        } else {
            fallbackCopy(text, buttonEl);
        }
    }

    function fallbackCopy(text, buttonEl) {
        const temp = document.createElement("textarea");
        temp.value = text;
        document.body.appendChild(temp);
        temp.select();
        document.execCommand("copy");
        document.body.removeChild(temp);
        triggerButtonSuccess(buttonEl);
        showToast("Copied to clipboard!");
    }

    function triggerButtonSuccess(btn) {
        if (!btn) return;
        const originalText = btn.textContent;
        btn.textContent = "Copied!";
        btn.classList.add("btn-copied");
        setTimeout(() => {
            btn.textContent = originalText;
            btn.classList.remove("btn-copied");
        }, 1800);
    }

    function showToast(message, type = "info") {
        let toastContainer = document.getElementById("toastContainer");
        if (!toastContainer) {
            toastContainer = document.createElement("div");
            toastContainer.id = "toastContainer";
            toastContainer.className = "toast-container";
            document.body.appendChild(toastContainer);
        }

        const toast = document.createElement("div");
        toast.className = `toast-item toast-${type}`;
        toast.textContent = message;

        toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.classList.add("toast-fade-out");
            setTimeout(() => {
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            }, 300);
        }, 2500);
    }

    function escapeHtml(str) {
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Initialize initial state & load database history
    runAnalysis("");
    loadVaultHistory();
});

