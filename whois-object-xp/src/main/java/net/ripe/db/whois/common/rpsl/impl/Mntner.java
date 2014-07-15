package net.ripe.db.whois.common.rpsl.impl;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class Mntner extends AbstractObjectType {
    private static final String name = "mntner";
    private static final String shortName = "mt";

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
                "      Objects in the AFRINIC Database may be protected using mntner\n" +
                "      (pronounced \"maintainer\") objects.  A mntner object specifies\n" +
                "      authentication information required to authorise creation,\n" +
                "      deletion or modification of the objects protected by the mntner.\n";
    }

    @Override
    public int getId() {
        return 9;
    }
}
