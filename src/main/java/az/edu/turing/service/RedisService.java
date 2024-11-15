package az.edu.turing.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class RedisService {

    private final RedisTemplate<String, String> redisTemplate;

    public void saveToken(final Long userId, final String token) {
        redisTemplate.opsForValue().set("refresh:" + userId, token, 1, TimeUnit.DAYS);
    }

    public void deleteToken(final Long userId) {
        redisTemplate.delete("refresh:" + userId);
    }

    public String getToken(final Long userId) {
        return redisTemplate.opsForValue().get("refresh:" + userId);
    }

    public void updateToken(final Long userId, final String token) {
        redisTemplate.opsForValue().set("refresh:" + userId, token, 1, TimeUnit.DAYS);
    }

    public boolean tokenExists(final Long userId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey("refresh:" + userId));
    }
}
