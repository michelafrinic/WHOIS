package net.ripe.db.whois.common.rpsl.impl;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class InetRtr extends AbstractObjectType {
    private static final String name = "inet-rtr";
    private static final String shortName = "ir";

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
                "      Routers are specified using the inet-rtr class.  The \"inet-rtr:\"\n" +
                "      attribute is a valid DNS name of the router described. Each\n" +
                "      \"alias:\" attribute, if present, is a canonical DNS name for the\n" +
                "      router.  The \"local-as:\" attribute specifies the AS number of\n" +
                "      the AS that owns/operates this router.\n";
    }

    @Override
    public int getId() {
        return 4;
    }
}
