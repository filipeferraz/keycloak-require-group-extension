package com.filipeferraz.keycloak.auth.requiregroup;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Based on class CookieAuthenticator
 * https://github.com/keycloak/keycloak/blob/master/services/src/main/java/org/keycloak/authentication/authenticators/browser/CookieAuthenticator.java
 */
public class RequireGroupCookieAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(RequireGroupCookieAuthenticator.class);

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationManager.AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(context.getSession(),
                context.getRealm(), true);
        if (authResult == null) {
            context.attempted();
        } else {
            AuthenticationSessionModel clientSession = context.getAuthenticationSession();
            LoginProtocol protocol = context.getSession().getProvider(LoginProtocol.class, clientSession.getProtocol());

            // Cookie re-authentication is skipped if re-authentication is required
            if (protocol.requireReauthentication(authResult.getSession(), clientSession)) {
                context.attempted();
            } else {
                AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();

                RealmModel realm = context.getRealm();
                UserModel user = authResult.getUser();

                if (!RequireGroupCommon.isAllowed(configModel, realm, user)) {
                    context.failure(AuthenticationFlowError.CLIENT_DISABLED);
                    return;
                }

                context.getAuthenticationSession().setAuthNote(AuthenticationManager.SSO_AUTH, "true");

                context.setUser(authResult.getUser());
                context.attachUserSession(authResult.getSession());
                context.success();
            }
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

}
