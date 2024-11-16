package az.edu.turing.service;

import az.edu.turing.auth.AuthorizationHelperService;
import az.edu.turing.clients.MsTransferClient;
import az.edu.turing.dao.entity.UserEntity;
import az.edu.turing.dao.repository.UserRepository;
import az.edu.turing.exceptions.NotFoundException;
import az.edu.turing.mapper.UserMapper;
import az.edu.turing.model.dto.request.UpdateUserRequest;
import az.edu.turing.model.dto.response.RetrieveUserResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static az.edu.turing.model.enums.Error.ERR_06;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final MsTransferClient msTransferClient;
    private final UserMapper userMapper;
    private final AuthorizationHelperService authorizationHelperService;
    private final PasswordEncoder passwordEncoder;

    public RetrieveUserResponse getUser(String token) {
        authorizationHelperService.validateAccessToken(token);
        Long userId = authorizationHelperService.getUserId(token);
        log.info("User id : {}", userId);

        UserEntity userEntity = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException(ERR_06.getErrorDescription(), ERR_06.getErrorCode()));

        log.info("User entity : {}", userEntity);
        return userMapper.mapToDto(userEntity);
    }

    @Transactional
    public void deleteUser(String token) {
        authorizationHelperService.validateAccessToken(token);
        Long userId = authorizationHelperService.getUserId(token);
        log.info("User id : {}", userId);

        UserEntity userEntity = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException(ERR_06.getErrorDescription(), ERR_06.getErrorCode()));

        msTransferClient.deleteAllAccountsByUser("Bearer " + token);
        userRepository.delete(userEntity);
    }

    public RetrieveUserResponse updateUserPassword(String token, UpdateUserRequest updateUserRequest) {
        authorizationHelperService.validateAccessToken(token);
        Long userId = authorizationHelperService.getUserId(token);
        log.info("User id : {}", userId);

        UserEntity userEntity = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException(ERR_06.getErrorDescription(), ERR_06.getErrorCode()));

        userEntity.setPassword(passwordEncoder.encode(updateUserRequest.password()));
        return userMapper.mapToDto(userRepository.save(userEntity));
    }
}
