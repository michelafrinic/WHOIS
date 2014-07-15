package net.ripe.db.whois.common.rpsl.impl;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class ASBlock extends AbstractObjectType {
    private static final String name = "as-block";
    private static final String shortName = "ak";

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
        "      An as-block object is needed to delegate a range of AS numbers \n" +
        "      to a given repository.  This object may be used for authorisation \n" +
        "      of the creation of aut-num objects within the range specified \n" +
        "      by the \"as-block:\" attribute.\n";
    }

    @Override
    public int getId() {
        return 0;
    }


}
