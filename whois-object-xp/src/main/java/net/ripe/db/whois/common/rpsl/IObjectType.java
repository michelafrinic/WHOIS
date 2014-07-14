package net.ripe.db.whois.common.rpsl;

/**
 * Created by michel on 7/9/14.
 */
public interface IObjectType {
    public String getName();
    public String getShortName();
    public boolean isSet();
    public String getDocumentation();
    public int getId();
}
