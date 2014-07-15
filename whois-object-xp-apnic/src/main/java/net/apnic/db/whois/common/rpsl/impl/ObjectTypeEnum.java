package net.apnic.db.whois.common.rpsl.impl;

import net.ripe.db.whois.common.rpsl.IObjectType;

/**
 * Created by michel on 7/11/14.
 */
public enum ObjectTypeEnum implements IObjectType {
    INETNUM("inetnum", "in", "This is an inetnum object", 1, false),
    PERSON("person", "pn", "This is a person object", 3, false),
    ROLE("role", "ro", "This is a role object", 6, false),
    ORGANISATION("organisation", "on", "This is an organisation object", 2, false);

    String name;
    String shortName;
    String documentation;
    int id;
    boolean set;

    ObjectTypeEnum(String name, String shortName, String documentation, int id, boolean set) {
        this.name = name;
        this.shortName = shortName;
        this.documentation = documentation;
        this.id = id;
        this.set = set;
    }

    public static ObjectTypeEnum valueOf(int id) {
        for (ObjectTypeEnum ote : ObjectTypeEnum.values()) {
            if (ote.getId() == id) {
                return ote;
            }
        }
        return null;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getShortName() {
        return shortName;
    }

    @Override
    public String getDocumentation() {
        return documentation;
    }

    @Override
    public int getId() {
        return id;
    }

    @Override
    public boolean isSet() {
        return set;
    }
}
