/**
 * common_passwords.js - Built-in Top Common Passwords & Dictionary Words
 * ====================================================================
 * Contains a compiled list of 160+ of the most frequently breached passwords
 * sourced from real-world breach analyses (NordPass, SecLists, SplashData).
 * 
 * Also contains common dictionary terms and keyboard walk patterns for instant detection.
 */

const COMMON_PASSWORDS = [
    // Top numerical patterns
    "123456", "123456789", "12345", "12345678", "111111", "1234567", "123123",
    "1234", "1111", "000000", "0000", "654321", "666666", "7777777", "123321",
    "112233", "987654321", "888888", "999999", "121212", "1234567890", "555555",
    "444444", "333333", "222222", "101010", "12340", "012345", "13579",

    // Classic word-based passwords
    "password", "password1", "password123", "p@ssword", "p@ssw0rd", "pass1234",
    "admin", "administrator", "admin123", "root", "default", "guest", "master",
    "welcome", "welcome1", "welcome123", "iloveyou", "love", "loveyou",
    "dragon", "monkey", "sunshine", "princess", "football", "baseball",
    "basketball", "soccer", "superman", "batman", "letmein", "letmeout",
    "trustno1", "secret", "shadow", "solo", "starwars", "pokemon",
    "michael", "jessica", "jordan", "charlie", "donald", "daniel",
    "thomas", "robert", "william", "matthew", "anthony", "andrew",
    "hannah", "nicole", "ashley", "jennifer", "rebecca", "melissa",
    "qwerty", "qwertyuiop", "asdfghjkl", "zxcvbnm", "qwerty123", "qwertz", "azerty",
    "1q2w3e", "1q2w3e4r", "1a2b3c", "abc123", "abc1234", "abcdef", "xyz123",

    // Corporate & tech defaults
    "login", "user", "access", "account", "system", "service", "support",
    "testing", "tester", "test1234", "dev", "developer", "server", "database",
    "computer", "network", "internet", "security", "protect", "changeit",
    "changeme", "oracle", "cisco", "cisco123", "router", "switch",

    // Seasonal & inspirational terms
    "summer", "winter", "spring", "autumn", "summer123", "winter2024", "summer2024",
    "november", "december", "january", "february", "october", "monday", "friday",
    "holiday", "christmas", "happy", "freedom", "cookie", "coffee", "chocolate",
    "monster", "killer", "matrix", "spiderman", "ironman", "avengers", "naruto",
    "harley", "hunter", "ranger", "patriot", "bullet", "mustang", "corvette",
    "harley23", "yellow", "orange", "purple", "silver", "golden", "diamond",
    "beautiful", "whatever", "nothing", "everything", "forever", "together",
    "hellothere", "goodmorning", "goodbye", "goodnight", "success", "winner"
];

// Common dictionary root words used for partial substring pattern matching
const DICTIONARY_WORDS = [
    "admin", "password", "secret", "access", "login", "welcome", "system",
    "account", "default", "master", "monkey", "dragon", "safety", "secure",
    "online", "computer", "student", "teacher", "school", "office", "summer",
    "winter", "spring", "autumn", "family", "friend", "player", "gaming"
];

// Common keyboard physical sequences (QWERTY layout)
const KEYBOARD_SEQUENCES = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "poiuytrewq", "lkjhgfdsa", "mnbvcxz",
    "1234567890", "0987654321",
    "qazwsx", "edcrfv", "tgbyhn", "yhnujm", "ujmik,ol."
];

// Export for module systems (if used in Node) or attach to window for browser
if (typeof module !== "undefined" && module.exports) {
    module.exports = { COMMON_PASSWORDS, DICTIONARY_WORDS, KEYBOARD_SEQUENCES };
}

