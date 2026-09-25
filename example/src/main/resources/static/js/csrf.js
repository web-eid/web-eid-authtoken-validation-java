"use strict";

const CSRF_COOKIE_NAME = "XSRF-TOKEN";
const CSRF_COOKIE_HEADER_NAME = "X-XSRF-TOKEN";

export function csrfHeader() {
    const cookieToken = getCookie(CSRF_COOKIE_NAME);
    if (cookieToken) {
        return {[CSRF_COOKIE_HEADER_NAME]: cookieToken};
    }

    const metaToken = document.querySelector("#csrftoken")?.content;
    const metaHeaderName = document.querySelector("#csrfheadername")?.content;
    if (metaToken && metaHeaderName) {
        return {[metaHeaderName]: metaToken};
    }

    return {};
}

function getCookie(name) {
    const encodedName = encodeURIComponent(name) + "=";
    return document.cookie
            .split(";")
            .map(cookie => cookie.trim())
            .filter(cookie => cookie.startsWith(encodedName))
            .map(cookie => decodeCookieValue(cookie.substring(encodedName.length)))
            .shift();
}

function decodeCookieValue(value) {
    try {
        return decodeURIComponent(value);
    } catch {
        return value;
    }
}
