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

/**
 * Binding between realm and default clientScope
 *
 */
@NamedQueries({
        @NamedQuery(name="defaultClientScopeRealmMappingIdsByRealm", query="select m.clientScopeId from DefaultClientScopeRealmMappingEntity m where m.realm = :realm and m.defaultScope = :defaultScope"),
        @NamedQuery(name="deleteDefaultClientScopeRealmMapping", query="delete from DefaultClientScopeRealmMappingEntity where realm = :realm and clientScopeId = :clientScopeId"),
        @NamedQuery(name="deleteDefaultClientScopeRealmMappingByRealm", query="delete from DefaultClientScopeRealmMappingEntity where realm = :realm")
})
@Entity
@Table(name="DEFAULT_CLIENT_SCOPE")
@IdClass(DefaultClientScopeRealmMappingEntity.Key.class)
public class DefaultClientScopeRealmMappingEntity {

    @Id
    @Column(name = "SCOPE_ID")
    protected String clientScopeId;

    @Id
    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name="REALM_ID")
    protected RealmEntity realm;

    @Column(name="DEFAULT_SCOPE")
    protected boolean defaultScope;

    public String getClientScopeId() {
        return clientScopeId;
    }

    public void setClientScopeId(String clientScopeId) {
        this.clientScopeId = clientScopeId;
    }

    public RealmEntity getRealm() {
        return realm;
    }

    public void setRealm(RealmEntity realm) {
        this.realm = realm;
    }

    public boolean isDefaultScope() {
        return defaultScope;
    }

    public void setDefaultScope(boolean defaultScope) {
        this.defaultScope = defaultScope;
    }

    public static class Key implements Serializable {

        protected String clientScopeId;

        protected RealmEntity realm;

        public Key() {
        }

        public Key(String clientScopeId, RealmEntity realm) {
            this.clientScopeId = clientScopeId;
            this.realm = realm;
        }

        public String getClientScopeId() {
            return clientScopeId;
        }

        public RealmEntity getRealm() {
            return realm;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            DefaultClientScopeRealmMappingEntity.Key key = (DefaultClientScopeRealmMappingEntity.Key) o;

            if (clientScopeId != null ? !clientScopeId.equals(key.getClientScopeId() != null ? key.getClientScopeId() : null) : key.getClientScopeId() != null) return false;
            if (realm != null ? !realm.getId().equals(key.realm != null ? key.realm.getId() : null) : key.realm != null) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = clientScopeId != null ? clientScopeId.hashCode() : 0;
            result = 31 * result + (realm != null ? realm.getId().hashCode() : 0);
            return result;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!(o instanceof DefaultClientScopeRealmMappingEntity)) return false;

        DefaultClientScopeRealmMappingEntity key = (DefaultClientScopeRealmMappingEntity) o;

        if (clientScopeId != null ? !clientScopeId.equals(key.getClientScopeId() != null ? key.getClientScopeId() : null) : key.getClientScopeId() != null) return false;
        if (realm != null ? !realm.getId().equals(key.realm != null ? key.realm.getId() : null) : key.realm != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = clientScopeId != null ? clientScopeId.hashCode() : 0;
        result = 31 * result + (realm != null ? realm.getId().hashCode() : 0);
        return result;
    }
}
