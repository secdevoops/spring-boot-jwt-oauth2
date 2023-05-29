package es.secdevoops.springboot.jwt.repository;

import es.secdevoops.springboot.jwt.entities.UserAccount;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserAccountRepository extends JpaRepository<UserAccount, Integer> {
    public Optional<UserAccount> findByUsername(String username);
}