function isAllowedMicrosoftEmail(email, allowedDomains) {
    if (typeof email !== 'string') return false;
    const normalizedEmail = email.trim().toLowerCase();
    const separator = normalizedEmail.lastIndexOf('@');
    if (separator <= 0 || separator !== normalizedEmail.indexOf('@') || separator === normalizedEmail.length - 1) return false;
    return allowedDomains.includes(normalizedEmail.slice(separator + 1));
}

function getTokenExchangeAuthError(providerError) {
    return providerError === 'invalid_client' ? 'invalid_client' : 'token_exchange';
}

module.exports = { getTokenExchangeAuthError, isAllowedMicrosoftEmail };
