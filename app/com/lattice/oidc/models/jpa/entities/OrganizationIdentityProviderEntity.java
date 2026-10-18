package com.lattice.oidc.models.jpa.entities;

import java.io.Serializable;
import java.util.Objects;

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

@Entity
@Table(name = "ORG_IDENTITY_PROVIDER")
@IdClass(OrganizationIdentityProviderEntity.Key.class)
@NamedQueries({
        @NamedQuery(name = "getOrganizationIdsByIdp",
                query = "select oip.organizationId from OrganizationIdentityProviderEntity oip where oip.identityProviderId = :idpId"),
        @NamedQuery(name = "getLinksByIdpAndMembershipType",
                query = "select oip from OrganizationIdentityProviderEntity oip where oip.identityProviderId = :idpId and oip.membershipType = :membershipType")
})
public class OrganizationIdentityProviderEntity {

    @Id
    @Column(name = "ORGANIZATION_ID")
    private String organizationId;

    @Id
    @Column(name = "IDENTITY_PROVIDER_ID")
    private String identityProviderId;

    @Column(name = "AUTO_MEMBERSHIP", nullable = false)
    private boolean autoMembership = true;

    @Column(name = "MEMBERSHIP_TYPE")
    private String membershipType = "UNMANAGED";

    public String getOrganizationId() {
        return organizationId;
    }

    public void setOrganizationId(String organizationId) {
        this.organizationId = organizationId;
    }

    public String getIdentityProviderId() {
        return identityProviderId;
    }

    public void setIdentityProviderId(String identityProviderId) {
        this.identityProviderId = identityProviderId;
    }

    public boolean isAutoMembership() {
        return autoMembership;
    }

    public void setAutoMembership(boolean autoMembership) {
        this.autoMembership = autoMembership;
    }

    public String getMembershipType() {
        return membershipType;
    }

    public void setMembershipType(String membershipType) {
        this.membershipType = membershipType;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OrganizationIdentityProviderEntity that)) return false;
        return Objects.equals(organizationId, that.organizationId)
                && Objects.equals(identityProviderId, that.identityProviderId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(organizationId, identityProviderId);
    }

    public static class Key implements Serializable {

        private String organizationId;
        private String identityProviderId;

        public Key() {
        }

        public Key(String organizationId, String identityProviderId) {
            this.organizationId = organizationId;
            this.identityProviderId = identityProviderId;
        }

        public String getOrganizationId() {
            return organizationId;
        }

        public String getIdentityProviderId() {
            return identityProviderId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Key key = (Key) o;
            return Objects.equals(organizationId, key.organizationId)
                    && Objects.equals(identityProviderId, key.identityProviderId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(organizationId, identityProviderId);
        }
    }
}
