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
        @NamedQuery(name="userHasRole", query="select m from UserRoleMappingEntity m where m.userId = :userId and m.roleId = :roleId"),
        @NamedQuery(name="userRoleMappings", query="select m from UserRoleMappingEntity m where m.userId = :userId"),
        @NamedQuery(name="userRoleMappingIds", query="select m.roleId from UserRoleMappingEntity m where m.userId = :userId"),
        @NamedQuery(name="deleteUserRoleMappingsByRole", query="delete from UserRoleMappingEntity m where m.roleId = :roleId"),
        @NamedQuery(name="deleteUserRoleMappingsByUser", query="delete from UserRoleMappingEntity m where m.userId = :userId"),

})
@Table(name="USER_ROLE_MAPPING")
@Entity
@IdClass(UserRoleMappingEntity.Key.class)
public class UserRoleMappingEntity  {

    @Id
    @Column(name = "USER_ID")
    protected String userId;

    @Id
    @Column(name = "ROLE_ID")
    protected String roleId;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getRoleId() {
        return roleId;
    }

    public void setRoleId(String roleId) {
        this.roleId = roleId;
    }


    public static class Key implements Serializable {

        protected String userId;

        protected String roleId;

        public Key() {
        }

        public Key(String userId, String roleId) {
            this.userId = userId;
            this.roleId = roleId;
        }

        public String getUserId() {
            return userId;
        }

        public String getRoleId() {
            return roleId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Key key = (Key) o;

            if (!roleId.equals(key.roleId)) return false;
            if (!userId.equals(key.userId)) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = userId.hashCode();
            result = 31 * result + roleId.hashCode();
            return result;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof UserRoleMappingEntity)) return false;

        UserRoleMappingEntity key = (UserRoleMappingEntity) o;

        if (!roleId.equals(key.roleId)) return false;
        if (!userId.equals(key.userId)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = userId.hashCode();
        result = 31 * result + roleId.hashCode();
        return result;
    }

}
