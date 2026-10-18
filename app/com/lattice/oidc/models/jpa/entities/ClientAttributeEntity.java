package com.lattice.oidc.models.jpa.entities;

import java.io.Serializable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import org.hibernate.annotations.Nationalized;


@Table(name="CLIENT_ATTRIBUTES")
@Entity
@IdClass(ClientAttributeEntity.Key.class)
public class ClientAttributeEntity {

    @Id
    @Column(name = "CLIENT_ID")
    protected String clientId;

    @Id
    @Column(name="NAME")
    protected String name;

    @Nationalized
    @Column(name = "VALUE")
    protected String value;

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
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


    public static class Key implements Serializable {

        protected String clientId;

        protected String name;

        public Key() {
        }

        public Key(String clientId, String name) {
            this.clientId = clientId;
            this.name = name;
        }

        public String getClientId() {
            return clientId;
        }

        public String getName() {
            return name;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            ClientAttributeEntity.Key key = (ClientAttributeEntity.Key) o;

            if (clientId != null ? !clientId.equals(key.clientId != null ? key.clientId : null) : key.clientId != null) return false;
            if (name != null ? !name.equals(key.name != null ? key.name : null) : key.name != null) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = clientId != null ? clientId.hashCode() : 0;
            result = 31 * result + (name != null ? name.hashCode() : 0);
            return result;
        }
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!(o instanceof ClientAttributeEntity)) return false;

        ClientAttributeEntity key = (ClientAttributeEntity) o;

        if (clientId != null ? !clientId.equals(key.clientId != null ? key.clientId : null) : key.clientId != null) return false;
        if (name != null ? !name.equals(key.name != null ? key.name : null) : key.name != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = clientId != null ? clientId.hashCode() : 0;
        result = 31 * result + (name != null ? name.hashCode() : 0);
        return result;
    }
}
