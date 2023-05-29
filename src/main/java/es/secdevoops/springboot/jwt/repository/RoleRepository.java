package es.secdevoops.springboot.jwt.repository;


import es.secdevoops.springboot.jwt.entities.Role;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer>{
    public Optional<Role> findByRolename(String rolename);
}