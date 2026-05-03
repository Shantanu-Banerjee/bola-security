@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<BolaSecurityFilter> bolaFilter(BolaSecurityFilter filter) {
        FilterRegistrationBean<BolaSecurityFilter> registration = new FilterRegistrationBean<>();

        registration.setFilter(filter);
        registration.addUrlPatterns("/api/*");
        registration.setOrder(1);

        return registration;
    }
}