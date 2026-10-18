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
import jakarta.persistence.Version;

@NamedQueries({
        @NamedQuery(name="credentialByUser", query="select cred from CredentialEntity cred where cred.userId = :userId order by cred.priority"),

})
@Table(name="CREDENTIAL")
@Entity
public class CredentialEntity {
    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @Column(name="TYPE")
    protected String type;

    @Column(name="USER_LABEL")
    protected String userLabel;

    @Column(name="CREATED_DATE")
    protected Long createdDate;
    
    @Column(name = "USER_ID")
    protected String userId;

    @Column(name="SECRET_DATA")
    protected String secretData;

    @Column(name="CREDENTIAL_DATA")
    protected String credentialData;

    @Column(name="PRIORITY")
    protected int priority;

    @Deprecated // Needed just for backwards compatibility when migrating old credentials
    @Column(name="SALT")
    protected byte[] salt;

    @Version
    @Column(name="VERSION")
    private int version;

    public String getId() {
        return id;
    }
    public void setId(String id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }
    public void setType(String type) {
        this.type = type;
    }

    public String getUserLabel() {
        return userLabel;
    }
    public void setUserLabel(String userLabel) {
        this.userLabel = userLabel;
    }

    public String getUserId() {
        return userId;
    }
    public void setUserId(String userId) {
        this.userId = userId;
    }

    @Deprecated
    public byte[] getSalt() {
        return salt;
    }

    @Deprecated
    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public Long getCreatedDate() {
        return createdDate;
    }
    public void setCreatedDate(Long createdDate) {
        this.createdDate = createdDate;
    }

    public String getSecretData() {
        return secretData;
    }
    public void setSecretData(String secretData) {
        this.secretData = secretData;
    }

    public String getCredentialData() {
        return credentialData;
    }
    public void setCredentialData(String credentialData) {
        this.credentialData = credentialData;
    }

    public int getPriority() {
        return priority;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof CredentialEntity)) return false;

        CredentialEntity that = (CredentialEntity) o;

        if (!id.equals(that.getId())) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

}
