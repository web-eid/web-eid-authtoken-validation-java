/*
 * Copyright (c) 2020-2025 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

"use strict";

const NO_LANGUAGE_SELECTED = { lang: "auto", display: "AUTO", name: "Auto" };

const SUPPORTED_LANGUAGES = [
  { lang: "et", display: "ET", name: "Eesti" },
  { lang: "en", display: "EN", name: "English" },
  { lang: "ru", display: "RU", name: "Русский" },
  { lang: "fi", display: "FI", name: "Suomi" },
  { lang: "hr", display: "HR", name: "Hrvatska" },
  { lang: "de", display: "DE", name: "Deutsch" },
  { lang: "fr", display: "FR", name: "Française" },
  { lang: "nl", display: "NL", name: "Nederlands" },
  { lang: "cs", display: "CS", name: "Čeština" },
  { lang: "sk", display: "SK", name: "Slovenština" },
  NO_LANGUAGE_SELECTED
];

const languageComponent = {
  selectedLang: document.querySelector("#selected-lang"),
  languageButton: document.querySelector("#language-button"),
  languageMenu: document.querySelector("#language-menu"),
  languageGrid: document.querySelector(".language-grid"),
  languageOptions: () => document.querySelectorAll(".language-option")
};

/**
 * Reads the `lang` query parameter from the current URL and validates it.
 *
 * - Returns the language code (e.g. "en", "et") if present and included in SUPPORTED_LANGUAGES.
 * - Returns `null` if the parameter is missing, empty, or not in the supported list.
 *
 * This ensures that only recognized languages are passed to the app. If `null`
 * is returned, the Web eID application will fall back to the OS default locale.
 */
export function getValidatedLangFromUrl() {
  const lang = new URLSearchParams(window.location.search).get("lang");
  if (!lang) {
    return null;
  }
  const normalizedLang = lang.trim().toLowerCase();
  const language = SUPPORTED_LANGUAGES.find(lang => lang.lang === normalizedLang);
  return language ? language.lang : null;
}

/**
 * Creates a language selections in UI component
 *
 * @param lang Language to be selected in component, example en
 * @param onLangChange Action to be executed when language is changed
 */
export function setupLanguageSelection(lang, onLangChange) {
  const language = SUPPORTED_LANGUAGES.find(supportedLanguage => supportedLanguage.lang === lang) ?? NO_LANGUAGE_SELECTED;

  SUPPORTED_LANGUAGES.forEach(supportedLanguage => {
    if (supportedLanguage === NO_LANGUAGE_SELECTED) {
      return;
    }

    const button = document.createElement("button");
    button.className = "language-option";
    button.textContent = supportedLanguage.name;

    if (supportedLanguage === language) {
      button.classList.add("selected");
      setSelectedLanguage(supportedLanguage);
    }

    button.addEventListener("click", () => {
      languageComponent.languageOptions().forEach(o => o.classList.remove("selected"));
      button.classList.add("selected");

      setSelectedLanguage(supportedLanguage);
      hideLanguageSelectionMenu();

      onLangChange(supportedLanguage.lang);
    });

    languageComponent.languageGrid.appendChild(button);
  });

  setSelectedLanguage(language);

  languageComponent.languageButton.onclick = e => {
    e.stopPropagation();
    showLanguageSelectionMenu();
  };

  document.onclick = () => {
    hideLanguageSelectionMenu();
  };

  languageComponent.languageMenu.onclick = e => e.stopPropagation();
}

function setSelectedLanguage(supportedLanguage) {
  languageComponent.selectedLang.textContent = supportedLanguage.display;
}

function showLanguageSelectionMenu() {
  languageComponent.languageMenu.classList.toggle("show");
  languageComponent.languageButton.classList.toggle("active");
}

function hideLanguageSelectionMenu() {
  languageComponent.languageMenu.classList.remove("show");
  languageComponent.languageButton.classList.remove("active");
}
