package net.ripe.db.whois.common.rpsl.impl.afrinic;

import net.ripe.db.whois.common.rpsl.IObjectType;

/**
 * Created by michel on 7/10/14.
 */
public abstract class AbstractObjectType implements IObjectType {
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        IObjectType that = (IObjectType) o;

        if (!this.getName().equals(that.getName())) return false;
        if (!this.getShortName().equals(that.getShortName())) return false;
        if(this.getId() != that.getId()) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = getId();
        result = 31 * result + getShortName().hashCode();
        result = 31 * result + getName().hashCode();
        return result;
    }
}
