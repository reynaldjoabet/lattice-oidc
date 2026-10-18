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

import org.hibernate.annotations.Nationalized;

@NamedQueries({
        @NamedQuery(name="getGroupAttributesByNameAndValue", query="select attr from GroupAttributeEntity attr where attr.name = :name and attr.value = :value"),
        @NamedQuery(name="deleteGroupAttributesByRealm", query="delete from  GroupAttributeEntity a where a.group IN (select u from GroupEntity u where u.realm=:realm)")
})
@Table(name="GROUP_ATTRIBUTE")
@Entity
public class GroupAttributeEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name = "GROUP_ID")
    protected GroupEntity group;

    @Column(name = "NAME")
    protected String name;
    @Nationalized
    @Column(name = "VALUE")
    protected String value;

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

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public GroupEntity getGroup() {
        return group;
    }

    public void setGroup(GroupEntity group) {
        this.group = group;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof GroupAttributeEntity)) return false;

        GroupAttributeEntity that = (GroupAttributeEntity) o;

        if (!id.equals(that.getId())) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

}
