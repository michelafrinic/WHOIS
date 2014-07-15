package net.ripe.db.whois.common.rpsl.impl;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class RtrSet extends AbstractObjectType {
    private static final String name = "rtr-set";
    private static final String shortName = "is";

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
                "      A rtr-set object defines a set of routers. A set may be described \n" +
                "      by the \"members:\" attribute, which is a list of inet-rtr names, \n" +
                "      IPv4 addresses or other rtr-set names. A set may also be populated \n" +
                "      by means of the \"mbrs-by-ref:\" attribute, in which case it is \n" +
                "      represented by inet-rtr objects.\n";
    }

    @Override
    public int getId() {
        return 16;
    }
}
