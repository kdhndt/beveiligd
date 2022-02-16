package be.vdab.beveiligd.security;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import javax.sql.DataSource;

@EnableWebSecurity
//we overriden de methods van de geerfde adapter
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String MANAGER = "manager";
    private static final String HELPDESKMEDEWERKER = "helpdeskmedewerker";
    private static final String MAGAZIJNIER = "magazijnier";

    private final DataSource dataSource;

    public SecurityConfig(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //onthoud principals IN RAM, Spring maakt niet meer zelf een user gebruiker
/*        auth.inMemoryAuthentication()
        //{noop} wil zeggen dat pw niet versleuteld is
                .withUser("joe").password("{noop}theboss").authorities(MANAGER)
                .and()
                .withUser("averell").password("{noop}hungry")
                .authorities(HELPDESKMEDEWERKER, MAGAZIJNIER);*/

        //principals uit een database lezen, DataSource is gebaseerd op application.properties
        auth.jdbcAuthentication().dataSource(dataSource)
                //zoek user en authorities igv tables die een andere naamgeving en/of geen default structuur hebben:
                .usersByUsernameQuery(
                        """
                        select naam as username, paswoord as password, actief as enabled
                        from gebruikers where naam = ?
                        """
                )
                .authoritiesByUsernameQuery(
                        """
                        select gebruikers.naam as username, rollen.naam as authorities
                        from gebruikers inner join gebruikersrollen
                        on gebruikers.id = gebruikersrollen.gebruikerId
                        inner join rollen on rollen.id = gebruikersrollen.rolId
                        where gebruikers.naam = ?
                        """
                );
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                //geen beveiliging op URL's die hierbij passen (met hun subfolders)
                .mvcMatchers("/images/**")
                .mvcMatchers("/css/**")
                .mvcMatchers("/js/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        naam en pw in HTML form
//        http.formLogin();

        //definieer de URL van de controller als inlogpagina
        http.formLogin(login -> login.loginPage("/login"));
        //verleen rechten
        http.authorizeRequests(requests -> requests
                .mvcMatchers("/offertes/**").hasAuthority(MANAGER)
                .mvcMatchers("/werknemers/**").hasAnyAuthority(HELPDESKMEDEWERKER, MAGAZIJNIER)
/*                .mvcMatchers("/", "/login").permitAll()
                .mvcMatchers("/**").authenticated()*/
        );
        //logt je uit bij een POST request naar de URL /logout
//        http.logout();
        //verwijs naar andere pagina ipv de default login pagina na het uitloggen
        http.logout(logout -> logout.logoutSuccessUrl("/"));
    }
}
