package net.ripe.db.whois.common.rpsl.impl;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class Organisation extends AbstractObjectType {
    private static final String name = "organisation";
    private static final String shortName = "oa";

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
                "      The organisation class provides information identifying \n" +
                "      an organisation such as a company, charity or university,\n" +
                "      that is a holder of a network resource whose data is stored \n" +
                "      in the whois database.\n" +
                "      Organisation objects are not created automatically, but are forwarded\n" +
                "      to AfriNIC Database Administration (afrinic-dbm@rafrinic.net).\n";
    }

    @Override
    public int getId() {
        return 18;
    }
}
