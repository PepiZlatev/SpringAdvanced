package bg.softuni.security.config;

import bg.softuni.security.model.entity.enums.RoleEnum;
import bg.softuni.security.repository.UserRepository;
import bg.softuni.security.service.AppUserDetailsService;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfiguration {

    /**
     * Expose 3 things:
     * 1. PasswordEncoder;
     * 2. SecurityFilterChain;
     * 3. UserDetailsService;
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Pbkdf2PasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
                //defines which requests are allowed and which not
                .authorizeRequests()
                //everyone can download static resources (css, js, images)
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                //everyone can log in and register
                .antMatchers("/", "/users/login", "/users/register").permitAll()
                //pages, available only for moderators
                .antMatchers("/pages/moderators").hasRole(RoleEnum.MODERATOR.name())
                //pages, available only for admins
                .antMatchers("/pages/admins").hasRole(RoleEnum.ADMIN.name())
                //all other pages are available for logger in users
                .anyRequest().authenticated().and()
                //configuration of form login
                .formLogin().loginPage("/users/login")
                //the name username form field in .html
                .usernameParameter(UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY)
                //the name username form field in .html
                .passwordParameter(UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY)
                //login successful, go to the url
                .defaultSuccessUrl("/")
                //login not successful, go to the url
                .failureForwardUrl("/users/login-error")
                //logout
                .and().logout().logoutUrl("/users/logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID");

        return httpSecurity.build();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return new AppUserDetailsService(userRepository);
    }
}
