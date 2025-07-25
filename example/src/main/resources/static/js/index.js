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

const languageUi = {
  selectedLang: document.querySelector("#selected-lang"),
  languageButton: document.querySelector("#language-button"),
  languageMenu: document.querySelector("#language-menu"),
  languageOptions: document.querySelectorAll(".language-option")
};

export function setupLanguageSelection(currentLang, onLangChange) {
  const selectedOption = Array.from(languageUi.languageOptions)
    .find(option => option.dataset.lang === currentLang);

  languageUi.selectedLang.textContent = selectedOption ? selectedOption.dataset.display : "EN";

  languageUi.languageOptions.forEach(option =>
    option.classList.toggle('selected', option.dataset.lang === currentLang)
  );

  languageUi.languageButton.onclick = e => {
    e.stopPropagation();
    languageUi.languageMenu.classList.toggle('show');
    e.target.classList.toggle('active');
  };

  document.onclick = () => {
    languageUi.languageMenu.classList.remove('show');
    languageUi.languageButton.classList.remove('active');
  };

  languageUi.languageMenu.onclick = e => e.stopPropagation();

  languageUi.languageOptions.forEach(option => {
    option.onclick = () => {
      onLangChange(option.dataset.lang);
      languageUi.selectedLang.textContent = option.dataset.display;
      languageUi.languageOptions.forEach(o => o.classList.remove('selected'));
      option.classList.add('selected');
      languageUi.languageMenu.classList.remove('show');
      languageUi.languageButton.classList.remove('active');
    };
  });
}
