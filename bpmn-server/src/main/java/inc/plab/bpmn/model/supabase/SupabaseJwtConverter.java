package inc.plab.bpmn.model.supabase;

import inc.plab.bpmn.service.supabase.SupabaseAuthService;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
public class SupabaseJwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private final SupabaseAuthService supabaseAuthService;
    private final SupabaseUserRepository userRepository;

    public SupabaseJwtConverter(SupabaseAuthService supabaseAuthService, SupabaseUserRepository userRepository) {
        this.supabaseAuthService = supabaseAuthService;
        this.userRepository = userRepository;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        SupabaseUser user = supabaseAuthService.loadUserByUsername(jwt.getSubject());

        return new JwtAuthenticationToken(jwt, user.getAuthorities(), user.getUsername()) {
            @Override
            public Object getPrincipal() {
                return user;
            }
        };
    }
}
