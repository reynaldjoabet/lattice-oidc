package com.lattice.oidc.models.jpa.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

/**
 * Stores a list of revoked tokens in the database, so it is available after restarts.
 *
 */
@NamedQueries({
        @NamedQuery(
                name = "findExpiredRevokedTokenIds",
                query = "select t.id from RevokedTokenEntity t where t.expire <= :currentTime"
        ),
        @NamedQuery(
                name = "deleteExpiredRevokedTokenByIds",
                query = "delete from RevokedTokenEntity where id in :ids and expire <= :currentTime"
        ),
        @NamedQuery(
                name = "findRevokeTokenExpireTime",
                query = "select t.expire from RevokedTokenEntity t where t.id = :id"
        ),
        @NamedQuery(
                name = "insertRevokeTokenIfAbsent",
                query = "insert into RevokedTokenEntity (id, expire) values (:id, :expire)" +
                        " on conflict (id) do update set expire = :expire" +
                        " where expire <= :currentTime"
        ),
})
@Table(name="REVOKED_TOKEN")
@Entity
public class RevokedTokenEntity {
    @Id
    @Column(name="ID", length = 36)
    protected String id;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    /**
     * Expire time in seconds.
     */
    @Column(name="EXPIRE")
    protected long expire;

    public long getExpire() {
        return expire;
    }

    public void setExpire(long expire) {
        this.expire = expire;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof RevokedTokenEntity that)) return false;

        return id.equals(that.getId());
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

}
