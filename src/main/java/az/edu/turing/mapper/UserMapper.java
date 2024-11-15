package az.edu.turing.mapper;

import az.edu.turing.dao.entity.UserEntity;
import az.edu.turing.model.dto.response.RetrieveUserResponse;
import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE, unmappedSourcePolicy = ReportingPolicy.IGNORE)
public interface UserMapper {

    RetrieveUserResponse mapToDto(UserEntity userEntity);
}
