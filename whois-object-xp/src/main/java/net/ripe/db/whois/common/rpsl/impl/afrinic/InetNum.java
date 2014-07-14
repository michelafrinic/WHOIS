package net.ripe.db.whois.common.rpsl.impl.afrinic;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class InetNum extends AbstractObjectType {
    private static final String name = "inetnum";
    private static final String shortName = "in";

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
                "      An inetnum object contains information on allocations and\n" +
                "      assignments of IPv4 address space.\n";
    }

    @Override
    public int getId() {
        return 6;
    }
}
