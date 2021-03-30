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
public class MenuRight implements Serializable {
    private Long id;

    private Long parentId;

    private String name;

    private String url;

    private Integer status;

    private String icon;

    private String method;
}