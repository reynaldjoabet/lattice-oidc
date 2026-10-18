package com.lattice.oidc.models.jpa.entities;

import java.util.Map;

import jakarta.persistence.Access;
import jakarta.persistence.AccessType;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.MapKeyColumn;
import jakarta.persistence.Table;

@Entity
@Table(name="IDENTITY_PROVIDER")
public class IdentityProviderEntity {

    @Id
    @Column(name="INTERNAL_ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String internalId;

    @Column(name = "REALM_ID")
    protected String realmId;

    @Column(name="PROVIDER_ID")
    private String providerId;

    @Column(name="PROVIDER_ALIAS")
    private String alias;

    @Column(name="PROVIDER_DISPLAY_NAME")
    private String displayName;

    @Column(name="ENABLED")
    private boolean enabled;

    @Column(name = "TRUST_EMAIL")
    private Boolean trustEmail;

    @Column(name="STORE_TOKEN")
    private Boolean storeToken;

    @Column(name="LINK_ONLY")
    private Boolean linkOnly;

    @Column(name="HIDE_ON_LOGIN")
    private Boolean hideOnLogin;

    @Column(name="ADD_TOKEN_ROLE")
    protected Boolean addReadTokenRoleOnCreate;

    @Column(name="AUTHENTICATE_BY_DEFAULT")
    private Boolean authenticateByDefault;

    @Column(name="FIRST_BROKER_LOGIN_FLOW_ID")
    private String firstBrokerLoginFlowId;

    @Column(name="POST_BROKER_LOGIN_FLOW_ID")
    private String postBrokerLoginFlowId;

    @ElementCollection
    @MapKeyColumn(name="NAME")
    @Column(name="VALUE", columnDefinition = "TEXT")
    @CollectionTable(name="IDENTITY_PROVIDER_CONFIG", joinColumns={ @JoinColumn(name="IDENTITY_PROVIDER_ID") })
    private Map<String, String> config;

    public String getInternalId() {
        return this.internalId;
    }

    public void setInternalId(String internalId) {
        this.internalId = internalId;
    }

    public String getProviderId() {
        return this.providerId;
    }

    public void setProviderId(String providerId) {
        this.providerId = providerId;
    }

    public String getRealmId() {
        return this.realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public String getAlias() {
        return this.alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public boolean isEnabled() {
        return this.enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Boolean isStoreToken() {
        return this.storeToken;
    }

    public void setStoreToken(Boolean storeToken) {
        this.storeToken = storeToken;
    }

    public Boolean isAuthenticateByDefault() {
        return authenticateByDefault;
    }

    public void setAuthenticateByDefault(Boolean authenticateByDefault) {
        this.authenticateByDefault = authenticateByDefault;
    }

    public Boolean isLinkOnly() {
        return linkOnly;
    }

    public void setLinkOnly(Boolean linkOnly) {
        this.linkOnly = linkOnly;
    }

    public String getFirstBrokerLoginFlowId() {
        return firstBrokerLoginFlowId;
    }

    public void setFirstBrokerLoginFlowId(String firstBrokerLoginFlowId) {
        this.firstBrokerLoginFlowId = firstBrokerLoginFlowId;
    }

    public String getPostBrokerLoginFlowId() {
        return postBrokerLoginFlowId;
    }

    public void setPostBrokerLoginFlowId(String postBrokerLoginFlowId) {
        this.postBrokerLoginFlowId = postBrokerLoginFlowId;
    }

    public Boolean isHideOnLogin() {
        return this.hideOnLogin;
    }

    public void setHideOnLogin(Boolean hideOnLogin) {
        this.hideOnLogin = hideOnLogin;
    }

    public Map<String, String> getConfig() {
        return this.config;
    }

    public void setConfig(Map<String, String> config) {
        this.config = config;
    }

    public Boolean isAddReadTokenRoleOnCreate() {
        return addReadTokenRoleOnCreate;
    }

    public void setAddReadTokenRoleOnCreate(Boolean addReadTokenRoleOnCreate) {
        this.addReadTokenRoleOnCreate = addReadTokenRoleOnCreate;
    }

    public Boolean isTrustEmail() {
        return trustEmail;
    }

    public void setTrustEmail(Boolean trustEmail) {
        this.trustEmail = trustEmail;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof IdentityProviderEntity)) return false;

        IdentityProviderEntity that = (IdentityProviderEntity) o;

        if (!internalId.equals(that.internalId)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return internalId.hashCode();
    }

}
