package com.lattice.oidc.models.jpa.entities;

public interface RealmAttributes {

    String DISPLAY_NAME_HTML = "displayNameHtml";

    String ACTION_TOKEN_GENERATED_BY_ADMIN_LIFESPAN = "actionTokenGeneratedByAdminLifespan";

    String ACTION_TOKEN_GENERATED_BY_USER_LIFESPAN = "actionTokenGeneratedByUserLifespan";

    // KEYCLOAK-7688 Offline Session Max for Offline Token
    String OFFLINE_SESSION_MAX_LIFESPAN_ENABLED = "offlineSessionMaxLifespanEnabled";

    String OFFLINE_SESSION_MAX_LIFESPAN = "offlineSessionMaxLifespan";

    String CLIENT_SESSION_IDLE_TIMEOUT = "clientSessionIdleTimeout";
    String CLIENT_SESSION_MAX_LIFESPAN = "clientSessionMaxLifespan";
    String CLIENT_OFFLINE_SESSION_IDLE_TIMEOUT = "clientOfflineSessionIdleTimeout";
    String CLIENT_OFFLINE_SESSION_MAX_LIFESPAN = "clientOfflineSessionMaxLifespan";
    String WEBAUTHN_POLICY_RP_ENTITY_NAME = "webAuthnPolicyRpEntityName";
    String WEBAUTHN_POLICY_SIGNATURE_ALGORITHMS = "webAuthnPolicySignatureAlgorithms";

    String WEBAUTHN_POLICY_RP_ID = "webAuthnPolicyRpId";
    String WEBAUTHN_POLICY_ATTESTATION_CONVEYANCE_PREFERENCE = "webAuthnPolicyAttestationConveyancePreference";
    String WEBAUTHN_POLICY_AUTHENTICATOR_ATTACHMENT = "webAuthnPolicyAuthenticatorAttachment";
    String WEBAUTHN_POLICY_REQUIRE_RESIDENT_KEY = "webAuthnPolicyRequireResidentKey";
    String WEBAUTHN_POLICY_RESIDENT_KEY = "webAuthnPolicyResidentKey";
    String WEBAUTHN_POLICY_USER_VERIFICATION_REQUIREMENT = "webAuthnPolicyUserVerificationRequirement";
    String WEBAUTHN_POLICY_CREATE_TIMEOUT = "webAuthnPolicyCreateTimeout";
    String WEBAUTHN_POLICY_AVOID_SAME_AUTHENTICATOR_REGISTER = "webAuthnPolicyAvoidSameAuthenticatorRegister";
    String WEBAUTHN_POLICY_ACCEPTABLE_AAGUIDS = "webAuthnPolicyAcceptableAaguids";
    String WEBAUTHN_POLICY_EXTRA_ORIGINS = "webAuthnPolicyExtraOrigins";
    String WEBAUTHN_POLICY_PASSKEYS_ENABLED = "webAuthnPolicyPasskeysEnabled";
    String WEBAUTHN_POLICY_MEDIATION = "webAuthnPolicyMediation";

    String ADMIN_EVENTS_EXPIRATION = "adminEventsExpiration";

    String FIRST_BROKER_LOGIN_FLOW_ID = "firstBrokerLoginFlowId";

    String VERIFIABLE_CREDENTIALS_ENABLED = "verifiableCredentialsEnabled";

    String ORGANIZATIONS_ENABLED = "organizationsEnabled";
    String ADMIN_PERMISSIONS_ENABLED = "adminPermissionsEnabled";
    String ADMIN_PERMISSIONS_CLIENT_ID = "adminPermissionsClientId";
    String SCIM_API_ENABLED = "scimApiEnabled";
}
