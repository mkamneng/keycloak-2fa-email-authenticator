package com.mesutpiskin.keycloak.auth.email;

import static com.mesutpiskin.keycloak.auth.email.ConditionalEmailAuthenticatorForm.OtpDecision.ABSTAIN;
import static com.mesutpiskin.keycloak.auth.email.ConditionalEmailAuthenticatorForm.OtpDecision.SHOW_OTP;
import static com.mesutpiskin.keycloak.auth.email.ConditionalEmailAuthenticatorForm.OtpDecision.SKIP_OTP;
import static org.keycloak.models.utils.KeycloakModelUtils.getRoleFromString;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import jakarta.ws.rs.core.HttpHeaders;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.MultivaluedHashMap;

public class ConditionalEmailAuthenticatorForm extends EmailAuthenticatorForm {

    public static final String SKIP = "skip";

    public static final String FORCE = "force";

    public static final String OTP_CONTROL_USER_ATTRIBUTE = "otpControlAttribute";

    public static final String SKIP_OTP_ROLE = "skipOtpRole";

    public static final String FORCE_OTP_ROLE = "forceOtpRole";

    public static final String SKIP_OTP_FOR_HTTP_HEADER = "noOtpRequiredForHeaderPattern";

    public static final String FORCE_OTP_FOR_HTTP_HEADER = "forceOtpForHeaderPattern";

    public static final String DEFAULT_OTP_OUTCOME = "defaultOtpOutcome";

    enum OtpDecision {
        SKIP_OTP, SHOW_OTP, ABSTAIN
    }
	
	@Override
    public void authenticate(AuthenticationFlowContext context) {

        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        if (user == null || realm == null) {
            return;
        }

        if(user.hasRole(context.getRealm().getRole("admin")) &&
                user.getUsername().equals("admin")) {
            System.out.println("### Super admin user detected, skipping email OTP");
            context.success();
            return;
        }

        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        Map<String, String> config =
                authenticatorConfig != null ? context.getAuthenticatorConfig().getConfig() : Map.of();

        if (tryConcludeBasedOn(voteForUserOtpControlAttribute(user, config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForUserRole(realm, user, config), context)) {
            return;
        }

        MultivaluedMap<String, String> requestHeaders = getRequestHeaders(context);
        if (tryConcludeBasedOn(voteForHttpHeaderMatchesPattern(requestHeaders, config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForDefaultFallback(config), context)) {
            return;
        }

        showOtpForm(context);
    }

    private OtpDecision voteForDefaultFallback(Map<String, String> config) {

        if (!config.containsKey(DEFAULT_OTP_OUTCOME)) {
            return ABSTAIN;
        }

        return switch (config.get(DEFAULT_OTP_OUTCOME)) {
            case SKIP -> SKIP_OTP;
            case FORCE -> SHOW_OTP;
            default -> ABSTAIN;
        };
    }

    private boolean tryConcludeBasedOn(OtpDecision state, AuthenticationFlowContext context) {

        return switch (state) {
            case SHOW_OTP -> {
                showOtpForm(context);
                yield true;
            }
            case SKIP_OTP -> {
                context.success();
                yield true;
            }
            default -> false;
        };
    }

    private void showOtpForm(AuthenticationFlowContext context) {
        super.authenticate(context);
    }

    private OtpDecision voteForUserOtpControlAttribute(UserModel user, Map<String, String> config) {

        if (!config.containsKey(OTP_CONTROL_USER_ATTRIBUTE)) {
            return ABSTAIN;
        }

        String attributeName = config.get(OTP_CONTROL_USER_ATTRIBUTE);
        if (attributeName == null) {
            return ABSTAIN;
        }

        Optional<String> value = user.getAttributeStream(attributeName).findFirst();
        return value.map(s -> switch (s.trim()) {
            case SKIP -> SKIP_OTP;
            case FORCE -> SHOW_OTP;
            default -> ABSTAIN;
        }).orElse(ABSTAIN);

    }

    private OtpDecision voteForHttpHeaderMatchesPattern(MultivaluedMap<String, String> requestHeaders, Map<String, String> config) {

        if (!config.containsKey(FORCE_OTP_FOR_HTTP_HEADER) && !config.containsKey(SKIP_OTP_FOR_HTTP_HEADER)) {
            return ABSTAIN;
        }

        //Inverted to allow white-lists, e.g. for specifying trusted remote hosts: X-Forwarded-Host: (1.2.3.4|1.2.3.5)
        if (containsMatchingRequestHeader(requestHeaders, config.get(SKIP_OTP_FOR_HTTP_HEADER))) {
            return SKIP_OTP;
        }

        if (containsMatchingRequestHeader(requestHeaders, config.get(FORCE_OTP_FOR_HTTP_HEADER))) {
            return SHOW_OTP;
        }

        return ABSTAIN;
    }

    private boolean containsMatchingRequestHeader(MultivaluedMap<String, String> requestHeaders, String headerPattern) {

        if (headerPattern == null) {
            return false;
        }

        //TODO cache RequestHeader Patterns
        //TODO how to deal with pattern syntax exceptions?
        // need CASE_INSENSITIVE flag so that we also have matches when the underlying container use a different case than what
        // is usually expected (e.g.: vertx)
        Pattern pattern = Pattern.compile(headerPattern, Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

        for (Map.Entry<String, List<String>> entry : requestHeaders.entrySet()) {

            String key = entry.getKey();

            for (String value : entry.getValue()) {

                String headerEntry = key.trim() + ": " + value.trim();

                if (pattern.matcher(headerEntry).matches()) {
                    return true;
                }
            }
        }

        return false;
    }

    private OtpDecision voteForUserRole(RealmModel realm, UserModel user, Map<String, String> config) {

        if (!config.containsKey(SKIP_OTP_ROLE) && !config.containsKey(FORCE_OTP_ROLE)) {
            return ABSTAIN;
        }

        if (userHasRole(realm, user, config.get(SKIP_OTP_ROLE))) {
            return SKIP_OTP;
        }

        if (userHasRole(realm, user, config.get(FORCE_OTP_ROLE))) {
            return SHOW_OTP;
        }

        return ABSTAIN;
    }

    private boolean userHasRole(RealmModel realm, UserModel user, String roleName) {

        if (roleName == null) {
            return false;
        }

        RoleModel role = getRoleFromString(realm, roleName);
        if (role != null) {
            return user.hasRole(role);
        }

        return false;
    }

    private MultivaluedMap<String, String> getRequestHeaders(AuthenticationFlowContext context) {

        MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();

        HttpRequest request = context.getHttpRequest();
        if( request == null ) {
            return multivaluedMap;
        }

        HttpHeaders headers = request.getHttpHeaders();
        if( headers == null ) {
            return multivaluedMap;
        }

        return headers.getRequestHeaders();
    }
}
