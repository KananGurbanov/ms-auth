package az.edu.turing.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.concurrent.TimeUnit;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

public class RedisServiceTest {

    @Mock
    private RedisTemplate<String, String> redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @InjectMocks
    private RedisService redisService;

    private final Long userId = 12345L;
    private final String token = "test-token";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    @Test
    void testSaveToken() {
        redisService.saveToken(userId, token);

        verify(valueOperations, times(1))
                .set("refresh:" + userId, token, 1, TimeUnit.DAYS);
    }

    @Test
    void testDeleteToken() {
        redisService.deleteToken(userId);

        verify(redisTemplate, times(1))
                .delete("refresh:" + userId);
    }

    @Test
    void testGetToken() {
        when(valueOperations.get("refresh:" + userId)).thenReturn(token);

        String result = redisService.getToken(userId);

        assertEquals(token, result);
        verify(valueOperations, times(1))
                .get("refresh:" + userId);
    }

    @Test
    void testUpdateToken() {
        redisService.updateToken(userId, token);

        verify(valueOperations, times(1))
                .set("refresh:" + userId, token, 1, TimeUnit.DAYS);
    }

    @Test
    void testTokenExists() {
        when(redisTemplate.hasKey("refresh:" + userId)).thenReturn(true);

        boolean exists = redisService.tokenExists(userId);

        assertTrue(exists);
        verify(redisTemplate, times(1))
                .hasKey("refresh:" + userId);
    }

    @Test
    void testTokenDoesNotExist() {
        when(redisTemplate.hasKey("refresh:" + userId)).thenReturn(false);

        boolean exists = redisService.tokenExists(userId);

        assertFalse(exists);
        verify(redisTemplate, times(1))
                .hasKey("refresh:" + userId);
    }
}

