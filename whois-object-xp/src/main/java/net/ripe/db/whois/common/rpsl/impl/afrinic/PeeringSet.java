package net.ripe.db.whois.common.rpsl.impl.afrinic;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class PeeringSet extends AbstractObjectType {
    private static final String name = "peering-set";
    private static final String shortName = "ps";

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
                "      A peering-set object defines a set of peerings that are listed \n" +
                "      in its \"peering:\" attributes.  The \"peering-set:\" attribute \n" +
                "      defines the name of the set. \n";
    }

    @Override
    public int getId() {
        return 15;
    }
}
