package com.longlong.shiro.realm;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

/**
 * CustomRealm
 */
public class CustomRealm extends AuthorizingRealm {

    Map<String,String> userMap = new HashMap<>();
    {
        //userMap.put("Mark", "123456");
        userMap.put("Mark", "283538989cef48f3d7d8a1c1bdf2008f");
        super.setName("customRealm");
    }

    //授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = (String) principals.getPrimaryPrincipal();
        
        //从数据库或者缓存中获取角色数据
        Set<String> roles = getRolesByUsername(username);
        Set<String> permissions = getPermissionsByUsername(username);
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.setStringPermissions(permissions);
        simpleAuthorizationInfo.setRoles(roles);
        return simpleAuthorizationInfo;
    }

    private Set<String> getPermissionsByUsername(String username) {
        Set<String> sets = new HashSet<>();
        sets.add("user:delete");
        sets.add("user:add");
        return sets;
    }

    /**
     * 模拟数据库查询角色
     * 
     * @param username
     * @return
     */
    private Set<String> getRolesByUsername(String username) {
        Set<String> sets = new HashSet<>();
        sets.add("admin");
        sets.add("user");
        return sets;
    }

    // 认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        //1.从主体传过来的认证信息中，获取用户名
        String username = (String) token.getPrincipal();

        //2.通过用户名到数据库中获取凭证
        String password = getPasswordByUsername(username);
        if(password == null){
            return null;
        }
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(username,password,"customRealm");
        //加盐
        authenticationInfo.setCredentialsSalt(ByteSource.Util.bytes("Mark"));
        return authenticationInfo;
    }

    /**
     * 模拟数据库查询凭证
     * @param username
     * @return
     */
    private String getPasswordByUsername(String username) {
        return userMap.get(username);
    }

    // public static void main(String[] args) {
    //     Md5Hash md5Hash = new Md5Hash("123456","Mark");
    //     System.out.println(md5Hash.toString());
    // }

}