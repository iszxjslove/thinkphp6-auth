<?php

return [
    'auth_on'               => 1,                           // 权限开关
    'auth_type'             => 1,                           // 认证方式，1为实时认证；2为登录认证。
    'auth_platform'         => '',                          // 平台
    'auth_group'            => 'think_auth_group',          // 用户组数据不带前缀表名
    'auth_group_access'     => 'think_auth_group_access',   // 用户-用户组关系不带前缀表名
    'auth_rule'             => 'think_auth_rule',           // 权限规则不带前缀表名
    'auth_user'             => 'user',                      // 用户信息表不带前缀表名,主键自增字段为id
    'access_table_group_id' => 'auth_group_id',             // 关系表组ID
    'access_table_user_id'  => 'user_id',                   // 关系表用户ID
];