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

import org.hibernate.annotations.Nationalized;

@NamedQueries({
        @NamedQuery(name="getGroupIdsByParent", query="select u.id from GroupEntity u where u.realm = :realm and u.type = 0 and u.parentId = :parent order by u.name ASC"),
        @NamedQuery(name="getChildGroupIdsByParentIds", query="select g.id from GroupEntity g where g.realm = :realm and g.type = 0 and g.parentId in :parentIds"),
        @NamedQuery(name="deleteGroupsByRealm", query="delete from GroupEntity g where g.realm = :realm")
})
@Entity
@Table(name="KEYCLOAK_GROUP",
        uniqueConstraints = { @UniqueConstraint(columnNames = {"REALM_ID", "PARENT_GROUP", "NAME"})}
)
public class GroupEntity {

    /**
     * ID set in the PARENT column to mark the group as top level.
     */
    public static String TOP_PARENT_ID = " ";

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @Nationalized
    @Column(name = "NAME")
    protected String name;

    @Nationalized
    @Column(name = "DESCRIPTION")
    protected String description;

    @Column(name = "PARENT_GROUP")
    private String parentId;

    @Column(name = "REALM_ID")
    private String realm;

    @Column(name = "TYPE")
    private int type;

    @Column(name = "CREATED_TIMESTAMP")
    private Long createdTimestamp;

    @Column(name = "LAST_MODIFIED_TIMESTAMP")
    private Long lastModifiedTimestamp;

    /**
     * In case of an organization group,
     * this points to the Organization that owns this group
     */
    @Column(name = "ORG_ID")
    private String organizationId;

    @OneToMany(
            cascade = CascadeType.REMOVE,
            orphanRemoval = true, mappedBy="group")
    protected Collection<GroupAttributeEntity> attributes = new LinkedList<>();

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Collection<GroupAttributeEntity> getAttributes() {
        if (attributes == null) {
            attributes = new LinkedList<>();
        }
        return attributes;
    }

    public void setAttributes(Collection<GroupAttributeEntity> attributes) {
        this.attributes = attributes;
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

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getParentId() {
        return parentId;
    }

    public void setParentId(String parentId) {
        this.parentId = parentId;
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public String getOrganizationId() {
        return organizationId;
    }

    public void setOrganizationId(String organizationId) {
        this.organizationId = organizationId;
    }

    public Long getCreatedTimestamp() {
        return createdTimestamp;
    }

    public void setCreatedTimestamp(Long createdTimestamp) {
        this.createdTimestamp = createdTimestamp;
    }

    public Long getLastModifiedTimestamp() {
        return lastModifiedTimestamp;
    }

    public void setLastModifiedTimestamp(Long lastModifiedTimestamp) {
        this.lastModifiedTimestamp = lastModifiedTimestamp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof GroupEntity)) return false;

        GroupEntity that = (GroupEntity) o;

        if (!id.equals(that.id)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
}
