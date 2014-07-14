package net.ripe.db.whois.common.rpsl.impl.afrinic;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class Domain extends AbstractObjectType {
    private static final String name = "domain";
    private static final String shortName = "dn";

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
                "      A domain object represents a Top Level Domain (TLD) or\n" +
                "      other domain registrations. It is also used for Reverse\n" +
                "      Delegations.\n";
    }

    @Override
    public int getId() {
        return 3;
    }
}
