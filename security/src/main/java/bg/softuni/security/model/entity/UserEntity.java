package bg.softuni.security.model.entity;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "users")
public class UserEntity extends BaseEntity{

    @Column(name = "email", nullable = false)
    private String email;

    @Column(name = "password")
    private String password;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    @Column(name = "is_active")
    private boolean isActive;

    @Column(name = "image_url")
    private String imageURL;

    @ManyToMany(fetch = FetchType.EAGER)
    private List<UserRoleEntity> userRoles = new ArrayList<>();


    public String getEmail() {
        return email;
    }

    public UserEntity setEmail(String username) {
        this.email = username;
        return this;
    }

    public String getPassword() {
        return password;
    }

    public UserEntity setPassword(String password) {
        this.password = password;
        return this;
    }

    public String getFirstName() {
        return firstName;
    }

    public UserEntity setFirstName(String firstName) {
        this.firstName = firstName;
        return this;
    }

    public String getLastName() {
        return lastName;
    }

    public UserEntity setLastName(String lastName) {
        this.lastName = lastName;
        return this;
    }

    public boolean isActive() {
        return isActive;
    }

    public UserEntity setActive(boolean active) {
        isActive = active;
        return this;
    }

    public List<UserRoleEntity> getUserRoles() {
        return userRoles;
    }

    public UserEntity setUserRoles(List<UserRoleEntity> userRoleEntities) {
        this.userRoles = userRoleEntities;
        return this;
    }

    public String getImageURL() {
        return imageURL;
    }

    public UserEntity setImageURL(String imageURL) {
        this.imageURL = imageURL;
        return this;
    }

    public UserEntity addRole(UserRoleEntity userRole) {
        this.userRoles.add(userRole);
        return this;
    }

    @Override
    public String toString() {
        return "UserEntity{" +
                "email='" + email + '\'' +
                ", password='" + password + '\'' +
                ", firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                ", isActive=" + isActive +
                ", imageURL='" + imageURL + '\'' +
                ", userRoles=" + userRoles +
                '}';
    }
}
