package com.lattice.oidc.models.jpa.entities;

import java.io.Serializable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

@NamedQueries({
        @NamedQuery(name= "findFederatedIdentityByUser", query="select link from FederatedIdentityEntity link where link.localUserId = :localUserId"),
        @NamedQuery(name= "findFederatedIdentityByUserAndProvider", query="select link from FederatedIdentityEntity link where link.localUserId = :localUserId and link.identityProvider = :identityProvider"),
        @NamedQuery(name= "findUserByFederatedIdentityAndRealm", query="select link.localUserId from FederatedIdentityEntity link where link.realmId = :realmId and link.identityProvider = :identityProvider and link.userId = :userId"),
        @NamedQuery(name= "deleteFederatedIdentityByProvider", query="delete from FederatedIdentityEntity fdi where fdi.realmId = :realmId and fdi.identityProvider = :providerAlias "),
        @NamedQuery(name= "deleteFederatedIdentityByUser", query="delete from FederatedIdentityEntity social where social.localUserId = :localUserId")
})
@Table(name="FEDERATED_IDENTITY")
@Entity
@IdClass(FederatedIdentityEntity.Key.class)
public class FederatedIdentityEntity {

    @Id
    @Column(name = "USER_ID")
    private String localUserId;

    @Column(name = "REALM_ID")
    protected String realmId;

    @Id
    @Column(name = "IDENTITY_PROVIDER")
    protected String identityProvider;
    @Column(name = "FEDERATED_USER_ID")
    protected String userId;
    @Column(name = "FEDERATED_USERNAME")
    protected String userName;

    @Column(name = "TOKEN")
    protected String token;

    public String getLocalUserId() {
        return localUserId;
    }

    public void setLocalUserId(String localUserId) {
        this.localUserId = localUserId;
    }

    public String getIdentityProvider() {
        return identityProvider;
    }

    public void setIdentityProvider(String identityProvider) {
        this.identityProvider = identityProvider;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    public static class Key implements Serializable {

        protected String localUserId;

        protected String identityProvider;

        public Key() {
        }

        public Key(String localUserId, String identityProvider) {
            this.localUserId = localUserId;
            this.identityProvider = identityProvider;
        }

        public String getLocalUserId() {
            return localUserId;
        }

        public String getIdentityProvider() {
            return identityProvider;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Key key = (Key) o;

            if (identityProvider != null ? !identityProvider.equals(key.identityProvider) : key.identityProvider != null)
                return false;
            if (localUserId != null ? !localUserId.equals(key.localUserId != null ? key.localUserId : null) : key.localUserId != null) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = localUserId != null ? localUserId.hashCode() : 0;
            result = 31 * result + (identityProvider != null ? identityProvider.hashCode() : 0);
            return result;
        }

        @Override
        public String toString() {
            return "FederatedIdentityEntity.Key [user=" + (localUserId != null ? localUserId : null) + ", identityProvider=" + identityProvider + "]";
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof FederatedIdentityEntity)) return false;

        FederatedIdentityEntity key = (FederatedIdentityEntity) o;

        if (identityProvider != null ? !identityProvider.equals(key.identityProvider) : key.identityProvider != null)
            return false;
        if (localUserId != null ? !localUserId.equals(key.localUserId != null ? key.localUserId : null) : key.localUserId != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = localUserId != null ? localUserId.hashCode() : 0;
        result = 31 * result + (identityProvider != null ? identityProvider.hashCode() : 0);
        return result;
    }


}
