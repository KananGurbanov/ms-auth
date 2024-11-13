package az.edu.turing.service;

import az.edu.turing.dao.repository.UserRepository;
import az.edu.turing.exceptions.NotFoundException;
import az.edu.turing.mapper.UserMapper;
import az.edu.turing.model.dto.response.RetrieveUserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

import static az.edu.turing.model.enums.Error.ERR_06;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;

    public List<RetrieveUserResponse> getUsers() {
        return userRepository.findAll().stream().map(userMapper::mapToDtoUsers).toList();
    }

    public RetrieveUserResponse getUser(Long userId) {
        return userMapper.mapToDto(userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException(ERR_06.getErrorDescription(), ERR_06.getErrorCode())));
    }
}
