package net.ripe.db.whois.common.rpsl.impl.afrinic;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class Route extends AbstractObjectType {
    private static final String name = "route";
    private static final String shortName = "rt";

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
                "      Each interAS route (also referred to as an interdomain route) \n" +
                "      originated by an AS is specified using a route object. The \"route:\" \n" +
                "      attribute is the address prefix of the route and the \"origin:\" \n" +
                "      attribute is the AS number of the AS that originates the route \n" +
                "      into the interAS routing system. \n";
    }

    @Override
    public int getId() {
        return 12;
    }
}
