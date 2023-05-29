package es.secdevoops.springboot.jwt.config;

import es.secdevoops.springboot.jwt.security.JwtAuthenticationFilter;
import es.secdevoops.springboot.jwt.security.CustomAuthenticationFailureHandler;
import es.secdevoops.springboot.jwt.security.CustomAuthenticationSuccessHandler;
import es.secdevoops.springboot.jwt.security.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig {


   /* //JwtAuthenticationFilter will filter and verify the JWT token
    private final JwtAuthenticationFilter jwtAuthFilter;

    //AuthenticationProvider will authenticate the user
    private final AuthenticationProvider authenticationProvider;

    //LogoutHandler will handle the user logout
    private final LogoutHandler logoutHandler;

    //OAuth2 user service
    private final CustomOAuth2UserService customOAuth2UserService;

    //
    private final CustomAuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    private final CustomAuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

        @Bean
        @Order(1)
        public SecurityFilterChain jwtSecurityFilterChain(HttpSecurity http) throws Exception {
            http
                    .csrf().disable()
                    .authorizeRequests() //Configures authorization
                        .requestMatchers("/secdevoops/auth/**", "/secdevoops/register/user/**", "/oauth/**", "/oauth2/**","/login/**", "/error")
                            .permitAll() //Permits all requests to these endpoints
                        .requestMatchers("/swagger-ui/**", "/swagger-ui/", "/v3/**")
                            .permitAll() //Permits all requests to these endpoints
                        .requestMatchers("/secdevoops/admin/**", "/secdevoops/register/admin/**")
                            .hasRole("ADMIN") //Only users with ROLE_ADMIN are allow to request this urls
                        .anyRequest()
                            .authenticated() //Authenticates any other request
                    .and()
                        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                        .authenticationProvider(authenticationProvider)
                        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                        .logout()
                        .logoutUrl("/secdevoops/logout")
                        .addLogoutHandler(logoutHandler)
                        .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext());
            return http.build();
        }

        @Bean
        @Order(2)
        public SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
            http
                    .csrf().disable()
                    .authorizeRequests()
                    .requestMatchers("/secdevoops/auth/**", "/secdevoops/register/user/**", "/oauth/**", "/login/**", "/error")
                        .permitAll() //Permits all requests to these endpoints
                    .requestMatchers("/swagger-ui/**", "/swagger-ui/", "/v3/**")
                        .permitAll() //Permits all requests to these endpoints
                    .anyRequest().authenticated()
                    .and()
                        .oauth2Login()
                        .loginPage("/login").permitAll()
                        .authorizationEndpoint().baseUri("/oauth2/authorize")
                        .authorizationRequestRepository(authorizationRequestRepository())
                    .and()
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                        .failureHandler(oAuth2AuthenticationFailureHandler);
            return http.build();
        }

        // ... other beans ...
*/


    //JwtAuthenticationFilter will filter and verify the JWT token
    private final JwtAuthenticationFilter jwtAuthFilter;

    //AuthenticationProvider will authenticate the user
    private final AuthenticationProvider authenticationProvider;

    //LogoutHandler will handle the user logout
    private final LogoutHandler logoutHandler;

    //OAuth2 user service
    private final CustomOAuth2UserService customOAuth2UserService;

    //
    private final CustomAuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    private final CustomAuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    //Configures the Spring Security filter chain
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf()  //Disables CSRF protection (jwt is not vulnerable to CSRF)
                .disable()
                .authorizeRequests() //Configures authorization
                    .requestMatchers("/secdevoops/auth/**", "/secdevoops/register/user/**", "/oauth/**", "/login/**", "/error")
                        .permitAll() //Permits all requests to these endpoints
                    .requestMatchers("/swagger-ui/**", "/swagger-ui/", "/v3/**")
                        .permitAll() //Permits all requests to these endpoints
                    .requestMatchers("/secdevoops/admin/**", "/secdevoops/register/admin/**")
                        .hasRole("ADMIN") //Only users with ROLE_ADMIN are allow to request this urls
                .anyRequest()
                    .authenticated() //Authenticates any other request
                .and()
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS) //Disables session creation
                .and()
                    .authenticationProvider(authenticationProvider) //Sets the AuthenticationProvider to authenticate users
                    .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class) //Adds the JWT filter before the UsernamePasswordAuthenticationFilter
                    .logout()
                    .logoutUrl("/secdevoops/logout") //Configures the logout endpoint
                    .addLogoutHandler(logoutHandler) //Adds the logout handler
                    .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext()) //Clears the SecurityContextHolder after logout
                .and()
                    .oauth2Login()
                        .loginPage("/login").permitAll()
                        .authorizationEndpoint()
                        .baseUri("/oauth2/authorize")
                        .authorizationRequestRepository(authorizationRequestRepository())
                    //.and().redirectionEndpoint().baseUri("/oauth2/callback")
                    //.and().userInfoEndpoint().userService(customOAuth2UserService)
                .and()
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                        .failureHandler(oAuth2AuthenticationFailureHandler);
                //.defaultSuccessUrl("/loginSuccess").permitAll()
                //.failureUrl("/loginFailure").permitAll();
        return http.build();
    }


    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
        return new HttpSessionOAuth2AuthorizationRequestRepository();
    }

}