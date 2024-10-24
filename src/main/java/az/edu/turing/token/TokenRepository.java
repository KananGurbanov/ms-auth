package az.edu.turing.token;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TokenRepository extends MongoRepository<RefreshToken, Integer> {
    Optional<RefreshToken> findByUserId(Long userId);
    void deleteByUserId(Long userId);
}