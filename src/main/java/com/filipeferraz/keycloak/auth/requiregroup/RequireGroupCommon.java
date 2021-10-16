package com.filipeferraz.keycloak.auth.requiregroup;

import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class RequireGroupCommon {

    private static final Logger LOG = Logger.getLogger(RequireGroupCommon.class);

    public static final String GROUP_ATTRIBUTE_NAME = "require-group-group";
    public static final String ACTION_ATTRIBUTE_NAME = "require-group-action";
    public static final String OPERATION_ATTRIBUTE_NAME = "require-group-operation";

    private static final String ALLOW_ACTION = "ALLOW";
    private static final String DENY_ACTION = "DENY";

    private static final String AND_OPERATION = "AND";
    private static final String OR_OPERATION = "OR";

    public static List<ProviderConfigProperty> generateConfig() {
        List<ProviderConfigProperty> configProperties = new ArrayList<>();

        ProviderConfigProperty property;

        property = new ProviderConfigProperty();
        property.setName(GROUP_ATTRIBUTE_NAME);
        property.setLabel("Group(s) name(s)");
        property.setHelpText("Name of groups for validation. Ex: group1,group2.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(ACTION_ATTRIBUTE_NAME);
        property.setLabel("Action");
        property.setHelpText("Action after the validation. ALLOW or DENY.");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setDefaultValue(ALLOW_ACTION);
        property.setOptions(Arrays.asList(ALLOW_ACTION, DENY_ACTION));
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(OPERATION_ATTRIBUTE_NAME);
        property.setLabel("Operation");
        property.setHelpText("Type of operation in validation. AND or OR.");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setDefaultValue(AND_OPERATION);
        property.setOptions(Arrays.asList(AND_OPERATION, OR_OPERATION));
        configProperties.add(property);

        return configProperties;
    }

    public static boolean isAllowed(AuthenticatorConfigModel configModel, RealmModel realm, UserModel user) {
        String groups = configModel.getConfig().get(GROUP_ATTRIBUTE_NAME);
        String acao = configModel.getConfig().getOrDefault(ACTION_ATTRIBUTE_NAME, ALLOW_ACTION);
        String operacao = configModel.getConfig().getOrDefault(OPERATION_ATTRIBUTE_NAME, AND_OPERATION);

        if (groups == null) {
            return false;
        }

        groups = groups.replaceAll("[ ]", "");

        List<String> notFoundGroups = new ArrayList<>();

        List<GroupModel> groupsList = Arrays.stream(groups.split(","))
                .map(grupo -> localizarGrupoKeycloak(realm, notFoundGroups, grupo))
                .filter(Objects::nonNull).collect(Collectors.toList());

        if (!notFoundGroups.isEmpty()) {
            LOG.errorf("Error validating group(s). Group(s) not found: %s.", String.join(", ", notFoundGroups));
            return false;
        }

        boolean sucess;

        if (OR_OPERATION.equals(operacao)) {
            // OR_OPERATION
            sucess = groupsList.stream().anyMatch(user::isMemberOf);
        } else {
            // AND_OPERATION
            sucess = groupsList.stream().allMatch(user::isMemberOf);
        }

        LOG.debugf("Acess %s to user after validation. realm=%s username=%s groups=%s", resultadoValidacao(acao, sucess), realm.getName(), user.getUsername(), groups);

        if (DENY_ACTION.equals(acao)) {
            // DENY_ACTION
            return !sucess;
        } else {
            // ALLOW_ACTION
            return sucess;
        }
    }

    private static GroupModel localizarGrupoKeycloak(RealmModel realm, List<String> gruposNaoEncontrados, String grupo) {
        GroupModel groupModel = KeycloakModelUtils.findGroupByPath(realm, grupo);
        if (groupModel == null) {
            gruposNaoEncontrados.add(grupo);
        }
        return groupModel;
    }

    private static String resultadoValidacao(String action, boolean validacao) {
        if (DENY_ACTION.equals(action)) {
            return validacao ? "DENIED" : "ALLOWED";
        } else {
            return validacao ? "ALLOWED" : "DENIED";
        }
    }

}
