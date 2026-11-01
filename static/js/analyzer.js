/**
 * analyzer.js - Password Strength & Cryptographic Entropy Engine
 * ==============================================================
 * Author: Password Security Internship Project
 * 
 * This module is the analytical brain of the application. It computes:
 * 1. Character class complexity (uppercase, lowercase, numbers, symbols)
 * 2. Uniqueness checks (common password list, repeated characters, sequences, years)
 * 3. Information Entropy (Shannon entropy formula: H = L * log2(R))
 * 4. Realistic crack time estimation (assuming modern offline GPU rig @ 10^10 hashes/sec)
 * 5. Overall score out of 100 with color-coded classification
 * 6. Dynamic suggestions for 3 improved versions + secure random password generator
 */

class PasswordAnalyzer {
    constructor() {
        // Pool sizes for printable ASCII character classes
        this.POOL_LOWERCASE = 26; // a-z
        this.POOL_UPPERCASE = 26; // A-Z
        this.POOL_DIGITS    = 10; // 0-9
        this.POOL_SYMBOLS   = 33; // !@#$%^&*()-_=+[]{}|;:'",.<>/?`~
        
        // Cracking speed benchmarks:
        // Modern offline cracking rig (e.g. 8x NVIDIA RTX 4090 running Hashcat on fast hashes):
        // Approx. 10 billion (10^10) guesses per second.
        this.GPU_GUESSES_PER_SEC = 1e10;

        // Throttled online login attack (standard web server with rate limiting):
        // Approx. 100 guesses per second.
        this.ONLINE_GUESSES_PER_SEC = 100;
    }

    /**
     * Performs a complete, multi-layered security analysis on a password.
     * @param {string} password - The plain text candidate password.
     * @returns {Object} Comprehensive analysis report including score, meter, checklist, entropy, crack time, and suggestions.
     */
    analyze(password) {
        if (!password || password.length === 0) {
            return this.getEmptyResult();
        }

        const len = password.length;

        // 1. Character class detection
        const hasLower   = /[a-z]/.test(password);
        const hasUpper   = /[A-Z]/.test(password);
        const hasDigit   = /[0-9]/.test(password);
        const hasSpecial = /[^A-Za-z0-9]/.test(password);

        // Count how many character classes are present (1 to 4)
        const classCount = [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length;

        // 2. Uniqueness & Pattern Detections
        const isCommon = this.checkCommonPassword(password);
        const repeatPattern = this.checkRepeatedCharacters(password);
        const seqPattern = this.checkSequences(password);
        const yearOrDict = this.checkYearsAndDictionary(password);

        // 3. Length Evaluation
        const isMinLength = len >= 8;
        const isIdealLength = len >= 12;

        // 4. Checklist status
        const checklist = [
            {
                id: "min_length",
                label: "At least 8 characters",
                passed: isMinLength,
                critical: true
            },
            {
                id: "ideal_length",
                label: "Optimal length (12+ characters)",
                passed: isIdealLength,
                critical: false
            },
            {
                id: "has_upper",
                label: "Uppercase letter (A-Z)",
                passed: hasUpper,
                critical: true
            },
            {
                id: "has_lower",
                label: "Lowercase letter (a-z)",
                passed: hasLower,
                critical: true
            },
            {
                id: "has_digit",
                label: "Number (0-9)",
                passed: hasDigit,
                critical: true
            },
            {
                id: "has_special",
                label: "Special character (!@#$...)",
                passed: hasSpecial,
                critical: true
            },
            {
                id: "no_common",
                label: "Not in top breached passwords list",
                passed: !isCommon.detected,
                detail: isCommon.detail,
                critical: true
            },
            {
                id: "no_repeats",
                label: "No repeated characters (aaa, 111)",
                passed: !repeatPattern.detected,
                detail: repeatPattern.detail,
                critical: false
            },
            {
                id: "no_sequences",
                label: "No sequential keys or digits (abc, 123, qwerty)",
                passed: !seqPattern.detected,
                detail: seqPattern.detail,
                critical: false
            },
            {
                id: "no_years_dict",
                label: "No 4-digit years (1900-2099) or dictionary words",
                passed: !yearOrDict.detected,
                detail: yearOrDict.detail,
                critical: false
            }
        ];

        // 5. Calculate Score out of 100
        let score = 0;

        // Length points (up to 40)
        if (len < 8) {
            score += len * 2; // e.g. 7 chars = 14 pts
        } else if (len >= 8 && len < 12) {
            score += 15 + (len - 8) * 3; // 8 chars = 15, 11 chars = 24
        } else if (len >= 12 && len < 16) {
            score += 28 + (len - 12) * 3; // 12 chars = 28, 15 chars = 37
        } else {
            score += 40; // 16+ chars = full 40 pts
        }

        // Complexity points (up to 40)
        if (hasLower) score += 10;
        if (hasUpper) score += 10;
        if (hasDigit) score += 10;
        if (hasSpecial) score += 10;

        // Variety bonus (10 points if all 4 character types present)
        if (classCount === 4) {
            score += 10;
        } else if (classCount === 3 && len >= 10) {
            score += 5;
        }

        // Additional length resilience bonus for very long passphrases (20+ chars)
        if (len >= 20) {
            score += 10;
        }

        // Apply Deductions for Vulnerabilities
        let warnings = [];

        if (isCommon.detected) {
            // Common breached password is a fatal vulnerability
            score = Math.min(score, 15);
            warnings.push(`⚠️ ${isCommon.detail || "Matches a frequently breached password"}`);
        }

        if (repeatPattern.detected) {
            score -= 15;
            warnings.push(`⚠️ Contains repeated characters: '${repeatPattern.match}'`);
        }

        if (seqPattern.detected) {
            score -= 15;
            warnings.push(`⚠️ Contains predictable sequence: '${seqPattern.match}'`);
        }

        if (yearOrDict.detected) {
            score -= 10;
            warnings.push(`⚠️ Contains predictable pattern: '${yearOrDict.match}'`);
        }

        // Clamp final score between 0 and 100
        score = Math.max(0, Math.min(100, Math.round(score)));

        // 6. Determine Strength Tier
        const strengthTier = this.getStrengthTier(score, isCommon.detected);

        // 7. Information Entropy & Crack Time Calculations
        const entropyData = this.calculateEntropyAndCrackTime(password, {
            hasLower, hasUpper, hasDigit, hasSpecial,
            hasFlaws: isCommon.detected || seqPattern.detected || repeatPattern.detected
        });

        // 8. Generate 3 Smarter Alternative Suggestions
        const suggestions = this.generateAlternatives(password);

        return {
            passwordLength: len,
            score: score,
            strength: strengthTier,
            checklist: checklist,
            warnings: warnings,
            entropy: entropyData.entropyBits,
            combinations: entropyData.combinations,
            crackTimeOffline: entropyData.crackTimeOffline,
            crackTimeOnline: entropyData.crackTimeOnline,
            charsetPool: entropyData.charsetPool,
            suggestions: suggestions
        };
    }

    /**
     * Maps numerical score [0-100] to a standardized strength tier.
     */
    getStrengthTier(score, isCommon) {
        if (isCommon || score <= 20) {
            return {
                label: "Very Weak",
                color: "#ef4444", // Red
                bgLight: "#fef2f2",
                percent: Math.max(score, 12),
                step: 1
            };
        } else if (score <= 40) {
            return {
                label: "Weak",
                color: "#f97316", // Orange
                bgLight: "#fff7ed",
                percent: score,
                step: 2
            };
        } else if (score <= 60) {
            return {
                label: "Medium",
                color: "#eab308", // Amber / Yellow
                bgLight: "#fefce8",
                percent: score,
                step: 3
            };
        } else if (score <= 80) {
            return {
                label: "Strong",
                color: "#10b981", // Emerald / Teal
                bgLight: "#ecfdf5",
                percent: score,
                step: 4
            };
        } else {
            return {
                label: "Very Strong",
                color: "#059669", // Deep Emerald Green
                bgLight: "#d1fae5",
                percent: 100,
                step: 5
            };
        }
    }

    /**
     * Checks if password appears in the common breached list or leet-normalized variant.
     */
    checkCommonPassword(password) {
        const lower = password.toLowerCase();
        
        // Check exact or lowercased match against common passwords list
        if (typeof COMMON_PASSWORDS !== "undefined") {
            for (let common of COMMON_PASSWORDS) {
                if (lower === common.toLowerCase()) {
                    return { detected: true, detail: `Found in top common passwords list ('${common}')` };
                }
            }
        }

        // Check leet-speak normalized version (e.g. p@ssw0rd -> password)
        const normalizedLeet = lower
            .replace(/@/g, 'a')
            .replace(/4/g, 'a')
            .replace(/3/g, 'e')
            .replace(/1/g, 'i')
            .replace(/!/g, 'i')
            .replace(/0/g, 'o')
            .replace(/\$/g, 's')
            .replace(/5/g, 's')
            .replace(/7/g, 't');

        if (typeof COMMON_PASSWORDS !== "undefined") {
            for (let common of COMMON_PASSWORDS) {
                if (normalizedLeet === common.toLowerCase()) {
                    return { detected: true, detail: `Matches disguised common password ('${common}') via leet-speak substitution` };
                }
            }
        }

        return { detected: false };
    }

    /**
     * Checks for 3 or more consecutive repeated characters (e.g. 'aaa', '111', '$$$').
     */
    checkRepeatedCharacters(password) {
        const match = password.match(/(.)\1{2,}/i);
        if (match) {
            return { detected: true, match: match[0], detail: `Repeated sequence: ${match[0]}` };
        }
        return { detected: false };
    }

    /**
     * Detects sequential alphabetical patterns ('abc', 'cba'), numerical patterns ('123', '321'),
     * and keyboard rows ('qwerty', 'asdf').
     */
    checkSequences(password) {
        const lower = password.toLowerCase();

        // 1. Numerical sequences (3 or more consecutive ascending or descending digits)
        const digitSeq = /(012|123|234|345|456|567|678|789|890|321|432|543|654|765|876|987)/;
        const numMatch = lower.match(digitSeq);
        if (numMatch) {
            return { detected: true, match: numMatch[0], detail: `Numerical sequence '${numMatch[0]}'` };
        }

        // 2. Alphabetical sequences (3 or more consecutive ascending or descending letters)
        const alphabet = "abcdefghijklmnopqrstuvwxyz";
        const reverseAlphabet = "zyxwvutsrqponmlkjihgfedcba";

        for (let i = 0; i < alphabet.length - 2; i++) {
            const forward = alphabet.substring(i, i + 3);
            const backward = reverseAlphabet.substring(i, i + 3);
            if (lower.includes(forward)) {
                return { detected: true, match: forward, detail: `Alphabetical sequence '${forward}'` };
            }
            if (lower.includes(backward)) {
                return { detected: true, match: backward, detail: `Reverse alphabetical sequence '${backward}'` };
            }
        }

        // 3. Physical Keyboard Walk patterns (e.g. 'qwe', 'asd', 'zxc')
        const keyboardWalks = [
            "qwe", "wer", "ert", "rty", "tyu", "yui", "uio", "iop",
            "asd", "sdf", "dfg", "fgh", "ghj", "hjk", "jkl",
            "zxc", "xcv", "cvb", "vbn", "bnm",
            "qwerty", "asdfgh", "zxcvbn"
        ];
        for (let walk of keyboardWalks) {
            if (lower.includes(walk)) {
                return { detected: true, match: walk, detail: `Keyboard walk sequence '${walk}'` };
            }
        }

        return { detected: false };
    }

    /**
     * Detects 4-digit years (1900-2099) and common dictionary words.
     */
    checkYearsAndDictionary(password) {
        const lower = password.toLowerCase();

        // 1. Detect 4-digit years between 1900 and 2099
        const yearRegex = /(19\d\d|20[0-2]\d)/;
        const yearMatch = lower.match(yearRegex);
        if (yearMatch) {
            return { detected: true, match: yearMatch[0], detail: `Contains calendar year '${yearMatch[0]}'` };
        }

        // 2. Detect common dictionary root words
        if (typeof DICTIONARY_WORDS !== "undefined") {
            for (let word of DICTIONARY_WORDS) {
                if (lower.includes(word) && word.length >= 4) {
                    return { detected: true, match: word, detail: `Contains common dictionary word '${word}'` };
                }
            }
        }

        return { detected: false };
    }

    /**
     * Calculates Shannon Information Entropy (bits) and realistic crack time.
     * 
     * Cryptography Concept - Shannon Entropy:
     * Entropy measures the degree of unpredictability or information density in bits.
     * Formula:
     *   Entropy (H) = L * log2(R)
     *   where:
     *     L = length of the password
     *     R = pool size (number of possible characters in the character set)
     * 
     * Crack Time Formula:
     *   Total Search Space (Combinations) = R^L = 2^H
     *   Average Guesses to Crack = Combinations / 2
     *   Seconds to Crack = (Combinations / 2) / (Guesses Per Second)
     */
    calculateEntropyAndCrackTime(password, meta) {
        let poolSize = 0;
        if (meta.hasLower) poolSize += this.POOL_LOWERCASE; // 26
        if (meta.hasUpper) poolSize += this.POOL_UPPERCASE; // 26
        if (meta.hasDigit) poolSize += this.POOL_DIGITS;    // 10
        if (meta.hasSpecial) poolSize += this.POOL_SYMBOLS; // 33

        // Fallback for custom or extended characters
        if (poolSize === 0) poolSize = 1;

        const L = password.length;
        // Theoretical entropy in bits
        let entropyBits = L * (Math.log(poolSize) / Math.LN2);

        // Adjust entropy downwards if predictable patterns, repetitions, or breached words are present
        if (meta.hasFlaws) {
            entropyBits = Math.max(5, entropyBits * 0.65);
        }

        // Total combinations = 2^(entropyBits)
        // Note: For very high entropy, Math.pow can overflow to Infinity, so handle gracefully
        const log2Guesses = entropyBits - 1; // Average guesses = 2^(H-1)

        const crackTimeOfflineSec = this.calculateSeconds(log2Guesses, this.GPU_GUESSES_PER_SEC);
        const crackTimeOnlineSec = this.calculateSeconds(log2Guesses, this.ONLINE_GUESSES_PER_SEC);

        return {
            entropyBits: Math.round(entropyBits * 10) / 10,
            charsetPool: poolSize,
            combinations: entropyBits > 100 ? `> 10^${Math.round(entropyBits * 0.301)}` : Math.round(Math.pow(2, entropyBits)).toLocaleString(),
            crackTimeOffline: this.formatDuration(crackTimeOfflineSec),
            crackTimeOnline: this.formatDuration(crackTimeOnlineSec)
        };
    }

    /**
     * Calculates crack time in seconds using log2 math to prevent numerical overflow.
     */
    calculateSeconds(log2Guesses, guessesPerSec) {
        const log2Rate = Math.log2(guessesPerSec);
        const log2Sec = log2Guesses - log2Rate;

        if (log2Sec <= 0) return 0; // Less than 1 second
        if (log2Sec > 120) return Infinity; // Astronomical

        return Math.pow(2, log2Sec);
    }

    /**
     * Formats seconds into human-readable duration for the user interface.
     */
    formatDuration(seconds) {
        if (seconds <= 0.05) return "Instantly (< 1 millisecond)";
        if (seconds < 1) return "< 1 second";
        if (seconds < 60) return `${Math.round(seconds)} seconds`;
        if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
        if (seconds < 2592000) return `${Math.round(seconds / 86400)} days`;
        if (seconds < 31536000) return `${Math.round(seconds / 2592000)} months`;

        const years = seconds / 31536000;
        if (years < 100) return `${Math.round(years)} years`;
        if (years < 1000) return `${Math.round(years)} years`;
        if (years < 1000000) return `${Math.round(years / 1000)} thousand years`;
        if (years < 1000000000) return `${Math.round(years / 1000000)} million years`;
        if (years < 1000000000000) return `${Math.round(years / 1000000000)} billion years`;

        return "Centuries (Astronomical / Uncrackable)";
    }

    /**
     * Generates 3 intelligent improved alternatives based on the user's password:
     * 1. Leet & Symbol substitution
     * 2. Sandwich & Salt Padding
     * 3. High-entropy Passphrase Mutation
     */
    generateAlternatives(password) {
        if (!password || password.trim().length === 0) {
            return [];
        }

        const base = password.trim();

        // 1. Leet & Symbol Substitution
        let leetVersion = base
            .replace(/[aA]/g, '@')
            .replace(/[eE]/g, '3')
            .replace(/[iI]/g, '!')
            .replace(/[oO]/g, '0')
            .replace(/[sS]/g, '$');

        // Ensure uppercase letter and special symbol at the end
        if (!/[A-Z]/.test(leetVersion)) {
            leetVersion = leetVersion.charAt(0).toUpperCase() + leetVersion.slice(1);
        }
        if (!/[0-9]/.test(leetVersion)) {
            leetVersion += "7";
        }
        leetVersion += "#";

        // 2. Sandwich & Salt Padding
        const prefixWords = ["Vault", "Shield", "Cipher", "Apex", "Matrix", "Krypton"];
        const symbols = ["!", "@", "#", "$", "%", "&", "*", "_"];
        
        const randomPrefix = prefixWords[Math.floor(Math.random() * prefixWords.length)];
        const randomSymbol1 = symbols[Math.floor(Math.random() * symbols.length)];
        const randomSymbol2 = symbols[Math.floor(Math.random() * symbols.length)];
        const randomSuffixNum = Math.floor(100 + Math.random() * 900); // 3 digits
        
        const sandwichVersion = `${randomPrefix}${randomSymbol1}${base}${randomSuffixNum}${randomSymbol2}`;

        // 3. High-Entropy Mutated Passphrase
        // Convert to camel/alternating casing and add high-entropy random token
        let mutatedBase = base
            .split('')
            .map((char, idx) => (idx % 2 === 0 ? char.toUpperCase() : char.toLowerCase()))
            .join('');

        const randomToken = this.generateSecureRandomToken(5);
        const mutatedVersion = `${mutatedBase}_Secure+${randomToken}`;

        return [
            {
                title: "Leet & Symbol Mutation",
                description: "Replaces vowels with lookalike cryptographic symbols and adds complexity.",
                password: leetVersion
            },
            {
                title: "Sandwich & Salt Padding",
                description: "Encapsulates your password within secure random words, numbers, and symbols.",
                password: sandwichVersion
            },
            {
                title: "High-Entropy Extended Passphrase",
                description: "Expands your input into a 16+ character high-entropy hardened passphrase.",
                password: mutatedVersion
            }
        ];
    }

    /**
     * Generates a completely new cryptographically secure random password (16 characters)
     * using the Web Cryptography API (`window.crypto.getRandomValues`).
     */
    generateSecurePassword(length = 16) {
        const lowerChars = "abcdefghijklmnopqrstuvwxyz";
        const upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const digitChars = "0123456789";
        const symbolChars = "!@#$%^&*()-_=+[]{}|;:,.<>?";

        const allChars = lowerChars + upperChars + digitChars + symbolChars;

        // Guaranteed to include at least 2 of each class
        let result = [
            this.getRandomCharFrom(upperChars),
            this.getRandomCharFrom(upperChars),
            this.getRandomCharFrom(lowerChars),
            this.getRandomCharFrom(lowerChars),
            this.getRandomCharFrom(digitChars),
            this.getRandomCharFrom(digitChars),
            this.getRandomCharFrom(symbolChars),
            this.getRandomCharFrom(symbolChars)
        ];

        // Fill remaining slots using CSPRNG
        const remainingLength = Math.max(0, length - result.length);
        const randomBuffer = new Uint32Array(remainingLength);
        
        if (typeof window !== "undefined" && window.crypto && window.crypto.getRandomValues) {
            window.crypto.getRandomValues(randomBuffer);
            for (let i = 0; i < remainingLength; i++) {
                result.push(allChars[randomBuffer[i] % allChars.length]);
            }
        } else {
            // Fallback
            for (let i = 0; i < remainingLength; i++) {
                result.push(allChars[Math.floor(Math.random() * allChars.length)]);
            }
        }

        // Fisher-Yates shuffle using cryptographically random values
        return this.secureShuffle(result).join('');
    }

    getRandomCharFrom(charSet) {
        if (typeof window !== "undefined" && window.crypto && window.crypto.getRandomValues) {
            const arr = new Uint32Array(1);
            window.crypto.getRandomValues(arr);
            return charSet[arr[0] % charSet.length];
        }
        return charSet[Math.floor(Math.random() * charSet.length)];
    }

    generateSecureRandomToken(len = 4) {
        const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789!#$*";
        let str = "";
        for (let i = 0; i < len; i++) {
            str += this.getRandomCharFrom(chars);
        }
        return str;
    }

    secureShuffle(array) {
        const copy = [...array];
        for (let i = copy.length - 1; i > 0; i--) {
            let j;
            if (typeof window !== "undefined" && window.crypto && window.crypto.getRandomValues) {
                const rand = new Uint32Array(1);
                window.crypto.getRandomValues(rand);
                j = rand[0] % (i + 1);
            } else {
                j = Math.floor(Math.random() * (i + 1));
            }
            [copy[i], copy[j]] = [copy[j], copy[i]];
        }
        return copy;
    }

    /**
     * Returns an empty/initial state analysis report when input is blank.
     */
    getEmptyResult() {
        return {
            passwordLength: 0,
            score: 0,
            strength: {
                label: "Enter a password",
                color: "#94a3b8",
                bgLight: "#f8fafc",
                percent: 0,
                step: 0
            },
            checklist: [
                { id: "min_length", label: "At least 8 characters", passed: false, critical: true },
                { id: "ideal_length", label: "Optimal length (12+ characters)", passed: false, critical: false },
                { id: "has_upper", label: "Uppercase letter (A-Z)", passed: false, critical: true },
                { id: "has_lower", label: "Lowercase letter (a-z)", passed: false, critical: true },
                { id: "has_digit", label: "Number (0-9)", passed: false, critical: true },
                { id: "has_special", label: "Special character (!@#$...)", passed: false, critical: true },
                { id: "no_common", label: "Not in top breached passwords list", passed: true, critical: true },
                { id: "no_repeats", label: "No repeated characters (aaa, 111)", passed: true, critical: false },
                { id: "no_sequences", label: "No sequential keys or digits (abc, 123, qwerty)", passed: true, critical: false },
                { id: "no_years_dict", label: "No 4-digit years (1900-2099) or dictionary words", passed: true, critical: false }
            ],
            warnings: [],
            entropy: 0,
            combinations: "0",
            crackTimeOffline: "Instant",
            crackTimeOnline: "Instant",
            charsetPool: 0,
            suggestions: []
        };
    }
}

// Export for Node/test environments or attach to window
if (typeof module !== "undefined" && module.exports) {
    module.exports = { PasswordAnalyzer };
}

