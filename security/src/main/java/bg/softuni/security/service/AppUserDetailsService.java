package bg.softuni.security.service;

import bg.softuni.security.model.entity.UserEntity;
import bg.softuni.security.model.entity.UserRoleEntity;
import bg.softuni.security.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.stream.Collectors;

/**
 * Cuz this Service will be returned as a @Bean, we don't annotate it with @Service
 */
public class AppUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public AppUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {


        return this.userRepository
                .findByEmail(username)
                .map(this::map)
                .orElseThrow(() ->
                        new UsernameNotFoundException(
                                String.format("User with emil %s not found!", username)));
    }

    private UserDetails map(UserEntity user) {
        return User.builder().username(user.getEmail())
                .password(user.getPassword())
                .authorities(user.getUserRoles()
                        .stream()
                        .map(this::map)
                        .collect(Collectors.toList()))
                .build();
    }

    private GrantedAuthority map(UserRoleEntity userRole) {
        return new SimpleGrantedAuthority("ROLE_" + userRole.getRole().name());
    }
}
