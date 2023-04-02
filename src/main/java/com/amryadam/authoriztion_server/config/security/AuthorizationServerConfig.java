package com.amryadam.authoriztion_server.config.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;


// http://localhost:9090/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=http://127.0.0.1:4200/admin/authorized&code_challenge=QYPAZ5NU8yvtlQ9erXrUYR-T5AGCjCF47vN-KsaI2A8&code_challenge_method=S256
// http://localhost:9090/oauth2/token?client_id=client&redirect_uri=https://blog.amryadam.com&grant_type=authorization_code&code=dWlJMGpGlUAPz0sRU1y8suXDyWejo0_B4-WrLP-ks5kSlcdvlGG-u1OxOORvvpm7IMJaC_lMqzTX2Oh6AKHGOb2J4-Hp6PVPvGjLeUQMnWzz6h3Xyy1D0S6czbiTeU8f&code_verifier=qPsH306-ZDDaOE8DFzVn05TkN3ZZoVmI_6x4LsVglQI


@Configuration
@AllArgsConstructor
public class AuthorizationServerConfig {
    private final CORSCustomizer corsCustomizer;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain securityASFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
        http.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        corsCustomizer.corsCustomizer(http);
        return http.formLogin().and().build();
    }


    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:4200/admin/authorized")
                .scope(OidcScopes.OPENID)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true).build())
                .tokenSettings(TokenSettings.builder()
                        .refreshTokenTimeToLive(Duration.ofHours(10))
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer("http://localhost:9090").build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRSAKey();
        JWKSet set = new JWKSet(rsaKey);
        return (j, sc) -> j.select(set);
    }

    public static RSAKey generateRSAKey() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            var keyPair = g.generateKeyPair();

            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

            return new RSAKey.Builder(rsaPublicKey).privateKey(rsaPrivateKey).keyID(UUID.randomUUID().toString()).build();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Problem generating the keys");
        }

    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }



















//    @Autowired
//    private CORSCustomizer corsCustomizer;
//
//    @Autowired
//    JpaUserDetailsService userDetailsService;
//
//    @Bean
//    public SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                .oidc(Customizer.withDefaults());
////                .authorizationEndpoint(a -> a.authenticationProviders(getAuthorizationEndpointProviders()))
//        http.exceptionHandling(
//                e -> e.authenticationEntryPoint(
//                        new LoginUrlAuthenticationEntryPoint("/login")
//                )
//        );
//        corsCustomizer.corsCustomizer(http);
//        return http.build();
//    }
//
//
////    private Consumer<List<AuthenticationProvider>> getAuthorizationEndpointProviders() {
////        return providers -> {
////            for (AuthenticationProvider p : providers) {
////                if (p instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider x) {
////                    x.setAuthenticationValidator(new CustomRedirectUriValidator());
////                }
////            }
////        };
////    }
//
//
//
//
////    @Bean
////    public RegisteredClientRepository registeredClientRepository(CustomClientService service) {
////        RegisteredClient r1 = RegisteredClient.withId(UUID.randomUUID().toString())
////                .clientId("client")
////                .clientSecret(passwordEncoder().encode("secret"))
////                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
////                .scope(OidcScopes.OPENID)
////                .scope(OidcScopes.PROFILE)
////                .scope(OidcScopes.ADDRESS)
////                .redirectUri("https://blog.amryadam.com")
////                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
////                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
////                .tokenSettings(
////                        TokenSettings.builder()
////                                .accessTokenFormat(OAuth2TokenFormat.REFERENCE) // change token type from non-opaque to opaque
////                                .accessTokenTimeToLive(Duration.ofSeconds(900))
////                                .build()
////                )
////                .build();
////
////        return new InMemoryRegisteredClientRepository(r1);
////    }
//
//
//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        // modify authorization endpoint
//        return AuthorizationServerSettings.builder()
//                .build();
//    }
//
//
////    @Bean
////    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
////
////        return context -> {
////            context.getClaims().claim("Role", "ADMIN");
////        };
////    }
//
//    @Bean
//    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer() {
//        return context -> {
//            OAuth2TokenClaimsSet.Builder claims = context.getClaims();
//            // Customize claims
//            claims.claim("amr", "yadam");
//
//        };
//    }

}
