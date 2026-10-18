package com.lattice.oidc.models.jpa.entities;

import java.util.Collection;
import java.util.LinkedList;

import jakarta.persistence.Access;
import jakarta.persistence.AccessType;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(name="USER_CONSENT", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"USER_ID", "CLIENT_ID"})
})
@NamedQueries({
        @NamedQuery(name="userConsentByUserAndClient", query="select consent from UserConsentEntity consent where consent.userId = :userId and consent.clientId = :clientId"),
        @NamedQuery(name="userConsentByUserAndExternalClient", query="select consent from UserConsentEntity consent where consent.userId = :userId and consent.clientStorageProvider = :clientStorageProvider and consent.externalClientId = :externalClientId"),
        @NamedQuery(name="userConsentsByUser", query="select consent from UserConsentEntity consent where consent.userId = :userId"),
        @NamedQuery(name="deleteUserConsentsByUser", query="delete from UserConsentEntity consent where consent.userId = :userId"),
        @NamedQuery(name="deleteUserConsentsByClient", query="delete from UserConsentEntity consent where consent.clientId = :clientId"),
        @NamedQuery(name="deleteUserConsentsByExternalClient", query="delete from UserConsentEntity consent where consent.clientStorageProvider = :clientStorageProvider and consent.externalClientId = :externalClientId"),
        @NamedQuery(name="deleteUserConsentsByClientStorageProvider", query="delete from UserConsentEntity consent where consent.clientStorageProvider = :clientStorageProvider"),
})
public class UserConsentEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @Column(name = "USER_ID")
    protected String userId;

    @Column(name="CLIENT_ID")
    protected String clientId;

    @Column(name="CLIENT_STORAGE_PROVIDER")
    protected String clientStorageProvider;

    @Column(name="EXTERNAL_CLIENT_ID")
    protected String externalClientId;

    @OneToMany(cascade ={CascadeType.REMOVE}, orphanRemoval = true, mappedBy = "userConsent")
    Collection<UserConsentClientScopeEntity> grantedClientScopes = new LinkedList<>();

    @Column(name = "CREATED_DATE")
    private Long createdDate;

    @Column(name = "LAST_UPDATED_DATE")
    private Long lastUpdatedDate;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public Collection<UserConsentClientScopeEntity> getGrantedClientScopes() {
        if (grantedClientScopes == null) {
            grantedClientScopes = new LinkedList<>();
        }
        return grantedClientScopes;
    }

    public void setGrantedClientScopes(Collection<UserConsentClientScopeEntity> grantedClientScopes) {
        this.grantedClientScopes = grantedClientScopes;
    }

    public Long getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(Long createdDate) {
        this.createdDate = createdDate;
    }

    public Long getLastUpdatedDate() {
        return lastUpdatedDate;
    }

    public void setLastUpdatedDate(Long lastUpdatedDate) {
        this.lastUpdatedDate = lastUpdatedDate;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientStorageProvider() {
        return clientStorageProvider;
    }

    public void setClientStorageProvider(String clientStorageProvider) {
        this.clientStorageProvider = clientStorageProvider;
    }

    public String getExternalClientId() {
        return externalClientId;
    }

    public void setExternalClientId(String externalClientId) {
        this.externalClientId = externalClientId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof UserConsentEntity)) return false;

        UserConsentEntity that = (UserConsentEntity) o;

        if (!id.equals(that.getId())) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
}
