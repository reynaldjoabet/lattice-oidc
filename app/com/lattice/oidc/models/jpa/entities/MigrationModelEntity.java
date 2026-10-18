package com.lattice.oidc.models.jpa.entities;

import jakarta.persistence.Access;
import jakarta.persistence.AccessType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

@Table(name="MIGRATION_MODEL")
@Entity
@NamedQueries({
        @NamedQuery(name = "getLatest", query = "select m from MigrationModelEntity m ORDER BY m.updatedTime DESC")
})
public class MigrationModelEntity {
    public static final String SINGLETON_ID = "SINGLETON";
    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    private String id;

    @Column(name="VERSION", length = 36)
    protected String version;

    @Column(name="UPDATE_TIME")
    protected long updatedTime;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public long getUpdateTime() {
        return updatedTime;
    }

    public void setUpdatedTime(long updatedTime) {
        this.updatedTime = updatedTime;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof MigrationModelEntity)) return false;

        MigrationModelEntity that = (MigrationModelEntity) o;

        if (!id.equals(that.id)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

}
