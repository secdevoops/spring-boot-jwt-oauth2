package es.secdevoops.springboot.jwt.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Entity
@Table(name="role")
@Data
public class Role {
    public static final String ADMIN_ROLE = "ROLE_ADMIN";
    public static final String USER_ROLE = "ROLE_USER";

    @Id
    private Integer id;

    @NotNull
    private String rolename;

    @NotNull
    private String description;

}