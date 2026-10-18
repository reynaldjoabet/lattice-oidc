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
})
@Entity
@Table(name="USER_REQUIRED_ACTION")
@IdClass(UserRequiredActionEntity.Key.class)
public class UserRequiredActionEntity {

    @Id
    @Column(name = "USER_ID")
    protected String userId;

    @Id
    @Column(name="REQUIRED_ACTION")
    protected String action;

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public static class Key implements Serializable {

        protected String userId;

        protected String action;

        public Key() {
        }

        public Key(String userId, String action) {
            this.userId = userId;
            this.action = action;
        }

        public String getUserId() {
            return userId;
        }

        public String getAction() {
            return action;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Key key = (Key) o;

            if (action != key.action) return false;
            if (userId != null ? !userId.equals(key.userId != null ? key.userId : null) : key.userId != null) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = userId != null ? userId.hashCode() : 0;
            result = 31 * result + (action != null ? action.hashCode() : 0);
            return result;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof UserRequiredActionEntity)) return false;

        UserRequiredActionEntity key = (UserRequiredActionEntity) o;

        if (action != key.action) return false;
        if (userId != null ? !userId.equals(key.userId != null ? key.userId : null) : key.userId != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = userId != null ? userId.hashCode() : 0;
        result = 31 * result + (action != null ? action.hashCode() : 0);
        return result;
    }


}
