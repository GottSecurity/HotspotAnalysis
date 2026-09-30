package com.example;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

@Controller
public class ClassicSpringController extends WebSecurityConfigurerAdapter {
    NamedParameterJdbcTemplate jdbc;

    @ModelAttribute
    public void bind(User user) {
    }

    public ModelAndView show() {
        return new ModelAndView("redirect:/home");
    }

    public RedirectView away(String next) {
        return new RedirectView(next);
    }

    public void query(String name) {
        jdbc.query("SELECT id FROM users WHERE name = '" + name + "'", (rs, row) -> null);
    }

    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/admin/**").permitAll();
    }

    public void expr(String input) {
        new SpelExpressionParser().parseExpression(input);
    }
}
