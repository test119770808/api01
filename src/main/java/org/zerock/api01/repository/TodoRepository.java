package org.zerock.api01.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.zerock.api01.domain.Todo;

public interface TodoRepository extends JpaRepository<Todo, Long> {
}
