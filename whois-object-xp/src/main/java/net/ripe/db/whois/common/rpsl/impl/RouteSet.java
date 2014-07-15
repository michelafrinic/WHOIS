package net.ripe.db.whois.common.rpsl.impl;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class RouteSet extends AbstractObjectType {
    private static final String name = "routeset";
    private static final String shortName = "rs";

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
        return true;
    }

    @Override
    public String getDocumentation() {
        return "" +
                "      A route-set object defines a set of routes that can be\n" +
                "      represented by route objects or by address prefixes. In the\n" +
                "      first case, the set is populated by means of the \"mbrs-by-ref:\"\n" +
                "      attribute, in the latter, the members of the set are explicitly\n" +
                "      listed in the \"members:\" attribute. The \"members:\" attribute is\n" +
                "      a list of address prefixes or other route-set names.  Note that\n" +
                "      the route-set class is a set of route prefixes, not of database\n" +
                "      route objects.\n";
    }

    @Override
    public int getId() {
        return 13;
    }
}
