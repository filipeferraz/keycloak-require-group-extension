package com.filipeferraz.keycloak.auth.requiregroup;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;


public class RequireGroupAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(RequireGroupAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();

        LOG.debugf("passed on authenticator required, client: %s", context.getSession().getContext().getClient().getName());

        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();

        if (!RequireGroupCommon.isAllowed(configModel, realm, user)) {
            context.forkWithErrorMessage(new FormMessage("label", "Permission denied for user on client " + context.getSession().getContext().getClient().getClientId() + "."));
            return;
        }

        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public void close() {
    }

}
