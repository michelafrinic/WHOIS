package net.ripe.db.whois.common.rpsl.impl.afrinic;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class FilterSet extends AbstractObjectType {
    private static final String name = "filter-set";
    private static final String shortName = "fs";

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
                "      A filter-set object defines a set of routes that are matched by\n" +
                "      its filter.  The \"filter-set:\" attribute defines the name of\n" +
                "      the filter.  It is an RPSL name that starts with \"fltr-\".  The\n" +
                "      \"filter:\" attribute defines the set's policy filter.   A policy\n" +
                "      filter is a logical expression which when applied to a set of\n" +
                "      routes returns a subset of these routes.\n";
    }

    @Override
    public int getId() {
        return 14;
    }
}
