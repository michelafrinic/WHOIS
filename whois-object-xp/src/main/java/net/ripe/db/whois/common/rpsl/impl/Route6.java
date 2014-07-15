package net.ripe.db.whois.common.rpsl.impl;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class Route6 extends AbstractObjectType {
    private static final String name = "route6";
    private static final String shortName = "r6";

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
                "      Each interAS route (also referred to as an interdomain route)\n" +
                "      in IPv6 domain originated by an AS is specified using a route6 \n" +
                "      object. The \"route6:\" attribute is the address prefix of the \n" +
                "      route and the \"origin:\" attribute is the AS number of the AS \n" +
                "      that originates the route into the interAS routing system.\n";
    }

    @Override
    public int getId() {
        return 19;
    }
}
