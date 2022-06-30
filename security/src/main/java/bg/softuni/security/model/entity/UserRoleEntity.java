package bg.softuni.security.model.entity;


import bg.softuni.security.model.entity.enums.RoleEnum;

import javax.persistence.*;

@Entity
@Table(name = "user_roles")
public class UserRoleEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RoleEnum roles;

    public Long getId() {
        return id;
    }

    public UserRoleEntity setId(Long id) {
        this.id = id;
        return this;
    }

    public RoleEnum getRole() {
        return roles;
    }

    public UserRoleEntity setRole(RoleEnum roles) {
        this.roles = roles;
        return this;
    }

    @Override
    public String toString() {
        return "UserRoleEntity{" +
                "id=" + id +
                ", roles=" + roles +
                '}';
    }
}
