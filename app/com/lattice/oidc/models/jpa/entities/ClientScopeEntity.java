package com.lattice.oidc.models.jpa.entities;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;

import jakarta.persistence.Access;
import jakarta.persistence.AccessType;
import jakarta.persistence.CascadeType;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import org.hibernate.annotations.Nationalized;

@Entity
@Table(name="CLIENT_SCOPE", uniqueConstraints = {@UniqueConstraint(columnNames = {"REALM_ID", "NAME"})})
@NamedQueries({
        @NamedQuery(name="getClientScopeIds", query="select scope.id from ClientScopeEntity scope where scope.realmId = :realm"),
        @NamedQuery(name = "getClientScopesByProtocol",
                    query = "select S from ClientScopeEntity S " +
                            "where S.realmId = :realm and S.protocol = :protocol")
})
public class ClientScopeEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    private String id;
    @Column(name = "NAME")
    private String name;
    @Nationalized
    @Column(name = "DESCRIPTION")
    private String description;
    @OneToMany(cascade ={CascadeType.REMOVE}, orphanRemoval = true, mappedBy = "clientScope")
    Collection<ProtocolMapperEntity> protocolMappers = new LinkedList<>();

    @Column(name = "REALM_ID")
    protected String realmId;

    @Column(name="PROTOCOL")
    private String protocol;

    @OneToMany(cascade ={CascadeType.REMOVE}, orphanRemoval = true, mappedBy = "clientScope")
    protected Collection<ClientScopeAttributeEntity> attributes = new LinkedList<>();

    @ElementCollection
    @Column(name="ROLE_ID")
    @CollectionTable(name="CLIENT_SCOPE_ROLE_MAPPING", joinColumns = { @JoinColumn(name="SCOPE_ID")})
    private Set<String> scopeMappingIds = new HashSet<>();

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

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

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Collection<ProtocolMapperEntity> getProtocolMappers() {
        if (protocolMappers == null) {
            protocolMappers = new LinkedList<>();
        }
        return protocolMappers;
    }

    public void setProtocolMappers(Collection<ProtocolMapperEntity> protocolMappers) {
        this.protocolMappers = protocolMappers;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public Collection<ClientScopeAttributeEntity> getAttributes() {
        if (attributes == null) {
            attributes = new LinkedList<>();
        }
        return attributes;
    }

    public void setAttributes(Collection<ClientScopeAttributeEntity> attributes) {
        this.attributes = attributes;
    }

    public Set<String> getScopeMappingIds() {
        return scopeMappingIds;
    }

    public void setScopeMappingIds(Set<String> scopeMappingIds) {
        this.scopeMappingIds = scopeMappingIds;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof ClientScopeEntity)) return false;

        ClientScopeEntity that = (ClientScopeEntity) o;

        if (!id.equals(that.getId())) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

}
