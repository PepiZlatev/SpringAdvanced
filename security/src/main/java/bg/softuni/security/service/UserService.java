package bg.softuni.security.service;

import bg.softuni.security.model.entity.UserEntity;
import bg.softuni.security.model.entity.UserRoleEntity;
import bg.softuni.security.model.entity.enums.RoleEnum;
import bg.softuni.security.repository.UserRepository;
import bg.softuni.security.repository.UserRoleRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final UserRoleRepository roleRepository;
    private final PasswordEncoder encoder;

    public UserService(UserRepository userRepository, UserRoleRepository roleRepository,
                       PasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
    }

    public void init() {
        if (this.userRepository.count() == 0 && this.roleRepository.count() == 0) {
            UserRoleEntity adminRole = new UserRoleEntity().setRole(RoleEnum.ADMIN);
            UserRoleEntity moderatorRole = new UserRoleEntity().setRole(RoleEnum.MODERATOR);

            adminRole = this.roleRepository.save(adminRole);
            moderatorRole = this.roleRepository.save(moderatorRole);

            initAdmin(List.of(adminRole, moderatorRole));
            initModerator(List.of(moderatorRole));
            initUser(List.of());

        }
    }

    private void initAdmin(List<UserRoleEntity> roles) {
        UserEntity admin = new UserEntity()
                .setUserRoles(roles)
                .setFirstName("Max")
                .setLastName("Mustermann")
                .setEmail("max@mail.com")
                .setPassword(encoder.encode("12345"));

        userRepository.save(admin);
    }

    private void initModerator(List<UserRoleEntity> roles) {
        UserEntity moderator = new UserEntity()
                .setUserRoles(roles)
                .setFirstName("Lisa")
                .setLastName("Mustermann")
                .setEmail("lisa@mail.com")
                .setPassword(encoder.encode("12345"));

        userRepository.save(moderator);
    }

    private void initUser(List<UserRoleEntity> roles) {
        UserEntity user = new UserEntity()
                .setUserRoles(roles)
                .setFirstName("Anna")
                .setLastName("Mustermann")
                .setEmail("anna@mail.com")
                .setPassword(encoder.encode("12345"));

        userRepository.save(user);
    }
}
