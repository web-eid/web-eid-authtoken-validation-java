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

package eu.webeid.example.config;

import eu.webeid.example.security.WebEidAjaxLoginProcessingFilter;
import eu.webeid.example.security.WebEidAuthenticationProvider;
import eu.webeid.example.security.WebEidChallengeNonceFilter;
import eu.webeid.example.security.WebEidMobileAuthInitFilter;
import eu.webeid.example.security.ui.WebEidLoginPageGeneratingFilter;
import eu.webeid.security.challenge.ChallengeNonceGenerator;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.thymeleaf.ITemplateEngine;

@Configuration
@ConfigurationPropertiesScan
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
public class ApplicationConfiguration {

    @Bean
    public SecurityFilterChain filterChain(
        HttpSecurity http,
        WebEidAuthenticationProvider webEidAuthenticationProvider,
        AuthenticationConfiguration authConfig,
        ChallengeNonceGenerator challengeNonceGenerator,
        ITemplateEngine templateEngine,
        WebEidMobileProperties webEidMobileProperties
    ) throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/css/**", "/files/**", "/img/**", "/js/**", "/scripts/**").permitAll()
                .requestMatchers("/").permitAll()
                .anyRequest().authenticated()
            )
            .authenticationProvider(webEidAuthenticationProvider)
            .addFilterBefore(new WebEidMobileAuthInitFilter("/auth/mobile/init", "/auth/mobile/login", challengeNonceGenerator, webEidMobileProperties), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(new WebEidChallengeNonceFilter("/auth/challenge", challengeNonceGenerator), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(new WebEidLoginPageGeneratingFilter("/auth/mobile/login", "/auth/login", templateEngine), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(new WebEidAjaxLoginProcessingFilter("/auth/login", authConfig.getAuthenticationManager()), UsernamePasswordAuthenticationFilter.class)
            .logout(l -> l.logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler()))
            .headers(h -> h.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
            .build();
    }
}
