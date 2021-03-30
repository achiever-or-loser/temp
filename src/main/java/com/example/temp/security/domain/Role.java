package com.example.temp.security.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Role implements Serializable {

    private Long id;

    private String name;

    private String description;

    private Integer status;

    public static Role admin() {
        Role role = new Role();
        role.setId(1L);
        role.setName("admin");
        return role;
    }

    public static Role user() {
        Role role = new Role();
        role.setId(2L);
        role.setName("user");
        return role;
    }
}