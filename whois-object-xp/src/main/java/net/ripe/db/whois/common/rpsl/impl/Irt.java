package net.ripe.db.whois.common.rpsl.impl;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class Irt extends AbstractObjectType {
    private static final String name = "irt";
    private static final String shortName = "it";

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
                "      An irt object is used to define a Computer Security Incident\n" +
                "      Response Team (CSIRT).\n";
    }

    @Override
    public int getId() {
        return 17;
    }
}
