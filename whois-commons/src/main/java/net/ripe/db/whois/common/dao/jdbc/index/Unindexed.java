package net.ripe.db.whois.common.dao.jdbc.index;

import net.ripe.db.whois.common.rpsl.AttributeType;

public class Unindexed extends IndexStrategyAdapter {
    public Unindexed(final AttributeType attributeType) {
        super(attributeType);
    }
}
