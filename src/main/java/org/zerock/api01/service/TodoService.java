package org.zerock.api01.service;

import jakarta.transaction.Transactional;
import org.zerock.api01.dto.TodoDTO;

@Transactional
public interface TodoService {

    Long register(TodoDTO todoDTO);

    TodoDTO read(Long tno);

}
