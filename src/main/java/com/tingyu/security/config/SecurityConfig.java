package com.tingyu.security.config;

import cn.hutool.json.JSONUtil;
import com.tingyu.security.filter.LoginFilter;
import com.tingyu.security.util.CommonResult;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.io.PrintWriter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private DataSource dataSource;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");
    }

    /**
     * @Description 角色继承
     * @Return
     **/
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_admin > ROLE_user");
        return roleHierarchy;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasRole("user")
                .anyRequest().authenticated()
                .and().formLogin().loginPage("/login.html").loginProcessingUrl("/doLogin")
                .usernameParameter("name").passwordParameter("passwd").defaultSuccessUrl("/index").permitAll()
                .and().csrf().disable();
        http.addFilterAt(loginFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    public LoginFilter loginFilter() throws Exception {
        LoginFilter loginFilter = new LoginFilter();
        loginFilter.setAuthenticationSuccessHandler(new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
                httpServletResponse.setCharacterEncoding("UTF-8");
                PrintWriter writer = httpServletResponse.getWriter();
                writer.write(JSONUtil.toJsonStr(CommonResult.ok("登录成功")));
            }
        });
        loginFilter.setAuthenticationFailureHandler(new AuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
                httpServletResponse.setCharacterEncoding("UTF-8");
                PrintWriter writer = httpServletResponse.getWriter();
                writer.write(JSONUtil.toJsonStr(CommonResult.error("登录失败")));
            }
        });
        loginFilter.setAuthenticationManager(authenticationManagerBean());
        loginFilter.setFilterProcessesUrl("/doLogin");
        loginFilter.setUsernameParameter("name");
        loginFilter.setPasswordParameter("passwd");
        return loginFilter;
    }

    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);
        if (!manager.userExists("tingyu")) {
            manager.createUser(User.withUsername("tingyu").password("tingyu1234").roles("admin").build());
        }
        if (!manager.userExists("user")) {
            manager.createUser(User.withUsername("user").password("user").roles("user").build());
        }
        return manager;
    }
}
