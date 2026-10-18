package com.lattice.oidc.models.jpa.entities;

import jakarta.persistence.Access;
import jakarta.persistence.AccessType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

/**
 * JPA entity representing an internet domain that can be associated with an organizationId.
 *
 */
@Entity
@Table(name="ORG_DOMAIN")
@NamedQueries({
        @NamedQuery(name = "getDomainByRealmAndName", query = "select d from OrganizationDomainEntity d where d.realmId = :realmId and d.name = :name"),
        @NamedQuery(name = "deleteOrganizationDomainsByRealm", query = "delete from OrganizationDomainEntity d where d.realmId = :realmId"),
        @NamedQuery(name = "clearDomainIdpRouting", query = "update OrganizationDomainEntity d set d.identityProvider = null, d.autoRedirect = false where d.identityProvider.id = :idpId")
})
public class OrganizationDomainEntity {

    @Id
    @Column(name = "ID", length = 36)
    @Access(AccessType.PROPERTY)
    private String id;

    @Column(name = "NAME", nullable = false)
    private String name;

    @Column(name = "VERIFIED", nullable = false)
    private boolean verified;

    @Column(name = "REALM_ID", nullable = false)
    private String realmId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "IDP_ID", referencedColumnName = "INTERNAL_ID")
    private IdentityProviderEntity identityProvider;

    @Column(name = "ORG_ID")
    private String organizationId;

    @Column(name = "AUTO_REDIRECT", nullable = false)
    private boolean autoRedirect;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isVerified() {
        return verified;
    }

    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public IdentityProviderEntity getIdentityProvider() {
        return identityProvider;
    }

    public void setIdentityProvider(IdentityProviderEntity identityProvider) {
        this.identityProvider = identityProvider;
    }

    public String getOrganizationId() {
        return organizationId;
    }

    public void setOrganizationId(String organizationId) {
        this.organizationId = organizationId;
    }

    public boolean isAutoRedirect() {
        return autoRedirect;
    }

    public void setAutoRedirect(boolean autoRedirect) {
        this.autoRedirect = autoRedirect;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof OrganizationDomainEntity)) return false;
        OrganizationDomainEntity that = (OrganizationDomainEntity) o;
        return id != null && id.equals(that.getId());
    }

    @Override
    public int hashCode() {
        if (id == null) return super.hashCode();
        return id.hashCode();
    }
}
