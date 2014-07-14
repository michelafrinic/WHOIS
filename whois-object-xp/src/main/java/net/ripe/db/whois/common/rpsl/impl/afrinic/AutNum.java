package net.ripe.db.whois.common.rpsl.impl.afrinic;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class AutNum extends AbstractObjectType {
    private static final String name = "aut-num";
    private static final String shortName = "an";

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
                "      An object of the aut-num class is a database representation of \n" +
                "      an Autonomous System (AS), which is a group of IP networks operated \n" +
                "      by one or more network operators that has a single and clearly \n" +
                "      defined external routing policy.\n";
    }

    @Override
    public int getId() {
        return 2;
    }
}
