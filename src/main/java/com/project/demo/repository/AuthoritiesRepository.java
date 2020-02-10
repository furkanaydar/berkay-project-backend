package com.project.demo.repository;

import com.project.demo.model.Authorities;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;

public interface AuthoritiesRepository extends JpaRepository<Authorities, Long> {
}
