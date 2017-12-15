package com.meiya.shiro.authorizer.permission;

import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.authz.permission.WildcardPermission;

import java.util.Arrays;
import java.util.Collection;

/**
 * 解析角色对应的权
 * 限集合（默认没有实现，可以自己提供）
 *
 */

public class MyRolePermissionResolver implements RolePermissionResolver {
    public Collection<Permission> resolvePermissionsInRole(String roleString) {
        if ("role1".equals(roleString)) {
            return Arrays.asList((Permission) new WildcardPermission("menu:*"));
        }

        return null;
    }
}
