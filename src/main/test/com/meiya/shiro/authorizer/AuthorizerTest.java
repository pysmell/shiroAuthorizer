package com.meiya.shiro.authorizer;


import junit.framework.Assert;
import org.junit.Test;

public class AuthorizerTest  extends BaseTest {

        @Test
        public void testIsPermitted() {
                login("classpath:shiro-authorizer.ini", "lqw", "123");
                //判断拥有权限：user:create
                Assert.assertTrue(subject().isPermitted("user1:update"));
                Assert.assertTrue(subject().isPermitted("user2:update"));
                //通过二进制位的方式表示权限
                Assert.assertTrue(subject().isPermitted("+user1+2"));//新增权限
                Assert.assertTrue(subject().isPermitted("+user1+8"));//查看权限
                Assert.assertTrue(subject().isPermitted("+user2+10"));//新增及查看

                Assert.assertFalse(subject().isPermitted("+user1+4"));//没有删除权限

                Assert.assertTrue(subject().isPermitted("menu:view"));//通过MyRolePermissionResolver解析得到的权限
             }

    @Test
    public void testIsPermitted2() {
        login("classpath:shiro-jdbc-authorizer.ini", "zhang", "123");
        //判断拥有权限：user:create
        Assert.assertTrue(subject().isPermitted("user1:update"));
        Assert.assertTrue(subject().isPermitted("user2:update"));
        //通过二进制位的方式表示权限
        Assert.assertTrue(subject().isPermitted("+user1+2"));//新增权限
        Assert.assertTrue(subject().isPermitted("+user1+8"));//查看权限
        Assert.assertTrue(subject().isPermitted("+user2+10"));//新增及查看

        Assert.assertFalse(subject().isPermitted("+user1+4"));//没有删除权限

        Assert.assertTrue(subject().isPermitted("menu:view"));//通过MyRolePermissionResolver解析得到的权限
    }
}
//验证流程
//首先取到用户名密码，封装成token，然后调用subject.login() 交给SecurityManager，SecurityManager委托给Authentication进行验证,首先先调用
//realm的doGetAuthenticationInfo，返回后调用AuthenticatingRealm类的getAuthenticationInfo()方法，
//判断其token和info是否都不为空，如果都不为空，判断是否设置缓存，如果设置，将其保存到缓存中，然后
//调用AuthenticatingRealm类的assertCredentialsMatch(token, info)方法，如果验证成功返回info
//然后调用ModularRealmAuthenticator类进行验证是否是多个realm，如果验证完成就会开始进行授权
//授权流程
//如果调用的是hasRoles* 则直接获取 AuthorizationInfo.getRoles()与传入的角色比较即可（AuthorizationInfo是realm doGetAuthorizationInfo方法返回的对象）
//如果调用如 isPermitted(“user:view”)，首先通过 PermissionResolver 将权限字符串
//转换成相应的 Permission 实例，默认使用 WildcardPermissionResolver，即转换为通配符的WildcardPermission
//通过AuthorizationInfo.getObjectPermissions()得到Permission实例集合；通过AuthorizationInfo.getStringPermissions()得到字符串集合并通过PermissionResolver解析为
//Permission实例；然后获取用户的角色，并通过RolePermissionResolver解析角色对应的权限集合(默认没用实现，可以自己提供)
//接着调用Permission.implies(Permission p)逐个与传入的权限比较，如果有匹配的则返回true，否则false


//多realm授权的理解
//ModularRealmAuthorizer 进行多 Realm 匹配流程：
//首先检查相应的 Realm 是否实现了实现了 Authorizer；
//如果实现了 Authorizer，那么接着调用其相应的 isPermitted*/hasRole*接口进行匹配；
//如果有一个 Realm 匹配那么将返回 true，否则返回 false。

//验证权限字符串的流程
//先将要验证的权限字符串解析成permission,然后获取Permisson的Resolve去处理permission，调用isPermitted() 传
//入用户名和要验证的权限，在调用getAuthorizationInfo(用户名) 传入用户名，获取AuthorizationInfo，首先
//先根据缓存是否可用，如果可用根据其用户名作为key找AuthorizationInfo，否则调用其doGetAuthorizationInfo(用户名)获取
//AuthorizationInfo,最后调用isPermitted(权限，Authorization)，再由Authorization获取权限集合，
//调用集合中的每个permission的implies()方法和验证的权限进行比对