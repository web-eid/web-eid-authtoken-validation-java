// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;
import java.util.Objects;

import static eu.webeid.example.security.AuthTokenDTOAuthenticationProvider.ROLE_USER;

@Controller
@Secured(ROLE_USER)
public class WelcomeController {
    private static final Logger LOG = LoggerFactory.getLogger(WelcomeController.class);

    @GetMapping("welcome")
    public String welcome(Model model, Principal principal) {
        Objects.requireNonNull(principal);
        LOG.info("Showing welcome page, logged in as principal={}", principal.getName());
        model.addAttribute("principalName", principal.getName());
        return "welcome";
    }
}
