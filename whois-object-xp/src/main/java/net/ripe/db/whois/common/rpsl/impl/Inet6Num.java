package net.ripe.db.whois.common.rpsl.impl;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class Inet6Num extends AbstractObjectType {
    private static final String name = "inet6num";
    private static final String shortName = "i6";

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getShortName() {
        return shortName;
    }

    @Override
    public boolean isSet() {
        return false;
    }

    @Override
    public String getDocumentation() {
        return "" +
                "      An inet6num object contains information on allocations\n" +
                "      and assignments of IPv6 address space.\n";
    }

    @Override
    public int getId() {
        return 5;
    }
}
