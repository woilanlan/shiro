package com.longlong.test;

import com.alibaba.druid.pool.DruidDataSource;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Test;

/**
 * JdbcRealmTest
 */
public class JdbcRealmTest {

    DruidDataSource dataSource = new DruidDataSource();
    {
        dataSource.setUrl("jdbc:mysql://localhost:3306/shiro1?characterEncoding=UTF-8&useSSL=false&useUnicode=true");
        dataSource.setUsername("root");
        dataSource.setPassword("Longlong");
    }
    
    @Test
    public void testAuthentication() {
        JdbcRealm jdbcRealm = new JdbcRealm();
        jdbcRealm.setDataSource(dataSource);
        jdbcRealm.setPermissionsLookupEnabled(true);

        String sql = "select password from test_user where username = ?";
        jdbcRealm.setAuthenticationQuery(sql);

        String roleSql = "select role_name from test_user_role where username = ?";
        jdbcRealm.setUserRolesQuery(roleSql);

        //1.构建SecurityManager环境
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(jdbcRealm);

        //2.主体提交认证请求
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        //UsernamePasswordToken token = new UsernamePasswordToken("Mark","123456"); 
        UsernamePasswordToken token = new UsernamePasswordToken("longlong","654321");

        subject.login(token);
        System.out.println("isAuthenticated:"+subject.isAuthenticated());

        //subject.checkRoles("admin","user");
        subject.checkRole("admin");

        //要开启权限查询
        //subject.checkPermission("user:delete");
    }
}